#pragma once

#include <asio.hpp>
#include <functional>
#include <memory>
#include <atomic>
#include "BufferPool.h"
#include "Logger.h"
#include "Utilities.h"


class UDPNetworkUtility {
public:
    template<typename SendFraming, typename ReceiveFraming>
    class Connection : public std::enable_shared_from_this<Connection<SendFraming, ReceiveFraming>> {
    private:
        asio::ip::udp::socket socket_;
        std::string connectionUuid_;
        asio::strand<asio::io_context::executor_type> strand_;
        std::shared_ptr<BufferPool> buffer_pool_;
        LockFreeQueue<ByteVector*, 1024> send_queue_;
        std::atomic<bool> is_closed_{false};
        std::function<void(std::shared_ptr<Connection>)> connection_closed_callback_;
        std::function<void(const ByteVector&)> receive_callback_;
        SendFraming send_framing_;
        ReceiveFraming receive_framing_;

    public:
        explicit Connection(asio::io_context& io_context, json senderFramingInitialData, json receiveFramingInitialData)
            : socket_(io_context, asio::ip::udp::endpoint(asio::ip::udp::v4(), 0)),
              connectionUuid_(Utilities::generateUuid()),
              strand_(asio::make_strand(io_context)),
              buffer_pool_(std::make_shared<BufferPool>(8192)),
              resolver(io_context),send_framing_(senderFramingInitialData), receive_framing_(receiveFramingInitialData)
        {
        }
        auto get_shared_this() {
            return this->std::enable_shared_from_this<Connection>::template shared_from_this();
        }
        void start(const std::function<void(const ByteVector&)>& receive_callback) {
            receive_callback_ = receive_callback;
            do_receive();
        }

        bool is_closed() const { return is_closed_.load(std::memory_order_acquire); }

        void set_closed_callback(const std::function<void(std::shared_ptr<Connection>)>& callback) {
            connection_closed_callback_ = callback;
        }

        asio::ip::udp::socket& socket() { return socket_; }

        std::string getConnectionUuid() { return connectionUuid_; }

        void send(const ByteVector& message) {
            if (is_closed()) {
                return;
            }

            ByteVector* buffer = buffer_pool_->acquire();
            *buffer = send_framing_.frameMessage(message);

            asio::post(strand_, [this, buffer]() {
                send_queue_.push(buffer);
                if (send_queue_.size() == 1) {
                    do_send();
                }
            });
        }

        void close() {
            if (is_closed_.exchange(true, std::memory_order_acq_rel)) {
                return;
            }

            asio::post(strand_, [this, self = get_shared_this()]() {
                do_close();
            });
        }

        SendFraming& getSendFraming() { return send_framing_; }
        ReceiveFraming& getReceiveFraming() { return receive_framing_; }

        asio::ip::udp::resolver resolver;
        asio::ip::udp::endpoint endpoint;

    private:
        void do_receive() {
            if (!socket_.is_open()) {
                LOG_ERROR("Socket is not open");
                return;
            }
            auto receive_buffer = buffer_pool_->acquire();
            receive_buffer->resize(buffer_pool_->getBufferSize());
            std::string client_key = endpoint.address().to_string() + ":" + std::to_string(endpoint.port());
            LOG_DEBUG("Remote endpoint: %s", client_key.c_str());

            socket_.async_receive_from(
                asio::buffer(*receive_buffer), endpoint,
                asio::bind_executor(strand_, [this, self = get_shared_this(), receive_buffer](
                    const asio::error_code& ec, std::size_t bytes_received) {
                    if (!ec) {
                        receive_buffer->resize(bytes_received);
                        process_received_data(*receive_buffer);
                        do_receive();
                    } else {
                        LOG_ERROR("Error in receive: %s", ec.message().c_str());
                        close();
                    }
                    buffer_pool_->release(receive_buffer);
                }));
        }

        void process_received_data(const ByteVector& data) {
            if (receive_framing_.isCompleteMessage(data)) {
                ByteVector message = receive_framing_.extractMessage(data);
                receive_callback_(message);
            } else {
                LOG_WARNING("Received incomplete or invalid message");
            }
        }

        void do_send() {
            if (is_closed()) {
                return;
            }

            auto buffer = send_queue_.pop();
            if (!buffer) {
                return;
            }

            socket_.async_send_to(
                asio::buffer(**buffer), endpoint,
                asio::bind_executor(strand_, [this, self = get_shared_this(), buffer](
                    const asio::error_code& ec, std::size_t bytes_sent) {
                    buffer_pool_->release(*buffer);

                    if (!ec) {
                        LOG_DEBUG("Sent %zu bytes", bytes_sent);
                        if (!send_queue_.empty()) {
                            do_send();
                        }
                    } else {
                        LOG_ERROR("Error in send: %s", ec.message().c_str());
                        close();
                    }
                }));
        }

        void do_close() {
            // Clear the write queue
            while (auto opt_buffer = send_queue_.pop()) {
                buffer_pool_->release(*opt_buffer);
            }

            if (!socket_.is_open())
            {
                if (connection_closed_callback_)
                {
                    connection_closed_callback_(get_shared_this());
                }
                return; // Socket is already closed
            }

            std::error_code ec;

            // Cancel any pending asynchronous operations
            socket_.cancel(ec);
            if (ec)
            {
                LOG_ERROR("Error cancelling pending operations: %s", ec.message().c_str());
            }

            // Shutdown the socket
            socket_.shutdown(asio::ip::tcp::socket::shutdown_both, ec);
            if (ec && ec != asio::error::not_connected)
            {
                LOG_ERROR("Error shutting down socket: %s", ec.message().c_str());
            }

            // Close the socket
            socket_.close(ec);
            if (ec)
            {
                LOG_ERROR("Error closing socket: %s", ec.message().c_str());
            }

            if (connection_closed_callback_)
            {
                connection_closed_callback_(get_shared_this());
            }
        }
    };
    template<typename SendFraming, typename ReceiveFraming>
    using MessageCallback = std::function<void(const std::shared_ptr<Connection<SendFraming, ReceiveFraming>>&, const ByteVector&)>;

    template<typename SendFraming, typename ReceiveFraming>
    static std::shared_ptr<Connection<SendFraming, ReceiveFraming>> create_connection(asio::io_context& io_context, json& senderFramingInitialData, json& receiveFramingInitialData) {
        return std::make_shared<Connection<SendFraming, ReceiveFraming>>(io_context, senderFramingInitialData, receiveFramingInitialData);

    }

    template<typename SendFraming, typename ReceiveFraming>
    static std::shared_ptr<Connection<SendFraming, ReceiveFraming>> connect(
        asio::io_context& io_context,
        const std::string& host,
        const std::string& port,
        const std::function<void(std::error_code, std::shared_ptr<Connection<SendFraming, ReceiveFraming>>)>& callback,
        const MessageCallback<SendFraming, ReceiveFraming>& messageCallback,
        const std::function<void(std::shared_ptr<Connection<SendFraming, ReceiveFraming>>)>& closed_callback, json& senderFramingInitialData, json& receiveFramingInitialData) {

        auto connection = create_connection<SendFraming, ReceiveFraming>(io_context, senderFramingInitialData, receiveFramingInitialData);
        connection->set_closed_callback(closed_callback);

        auto endpoints = connection->resolver.resolve(asio::ip::udp::v4(), host, port);
        connection->endpoint = *endpoints.begin();

        connection->start(
            [connection, messageCallback](const ByteVector& data) {
                messageCallback(connection, data);
            });

        callback(std::error_code(), connection);

        return connection;
    }
};