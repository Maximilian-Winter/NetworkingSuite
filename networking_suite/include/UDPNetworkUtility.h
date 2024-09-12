

#pragma once

#include <asio.hpp>
#include <functional>
#include <memory>
#include <atomic>
#include "SessionContext.h"
#include "BufferPool.h"
#include "Logger.h"
#include "Utilities.h"
#include "nlohmann/json.hpp"

using json = nlohmann::json;
class UDPNetworkUtility {
public:
    template< typename SenderFramingType, typename ReceiverFramingType>
    class Session : public std::enable_shared_from_this<Session<SenderFramingType, ReceiverFramingType>> {
    private:
        asio::ip::udp::socket socket_;
        std::string connectionUuid_;
        asio::strand<asio::io_context::executor_type> strand_;
        std::shared_ptr<BufferPool> buffer_pool_;
        LockFreeQueue<ByteVector*, 1024> send_queue_;
        std::atomic<bool> is_closed_{false};
        SessionContext<Session, SenderFramingType, ReceiverFramingType> connection_context_;

        ByteVector receive_buffer_;

    public:
        explicit Session(asio::io_context& io_context)
            : socket_(io_context, asio::ip::udp::endpoint(asio::ip::udp::v4(), 0)),
              connectionUuid_(Utilities::generateUuid()),
              strand_(asio::make_strand(io_context)),
              buffer_pool_(std::make_shared<BufferPool>(65536)),
              resolver(io_context)
        {
            receive_buffer_.reserve(buffer_pool_->getBufferSize());
        }

        auto get_shared_this() {
            return this->shared_from_this();
        }

        void start(const SessionContext<Session, SenderFramingType, ReceiverFramingType>& connection_context) {
            connection_context_ = connection_context;
            connection_context_.set_session(get_shared_this());
            connection_context_.on_connect();
            do_receive();
        }

        bool is_closed() const { return is_closed_.load(std::memory_order_acquire); }


        asio::ip::udp::socket& socket() { return socket_; }

        std::string getConnectionUuid() { return connectionUuid_; }

        void send(const ByteVector& message) {
            if (is_closed()) {
                return;
            }

            ByteVector* buffer = buffer_pool_->acquire();
            *buffer = connection_context_.preprocess_write(message);

            asio::post(strand_, [this, buffer]() {
                send_queue_.push(buffer);
                if (send_queue_.size() == 1) {
                    do_send();
                }
            });
        }

        void close() {

            asio::post(strand_, [this, self = get_shared_this()]() {
                do_close();
            });
        }

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

        void process_received_data(const ByteVector& new_data) {
            receive_buffer_.insert(receive_buffer_.end(), new_data.begin(), new_data.end());

            while (true) {
                if (connection_context_.checkIfIsCompleteMessage(receive_buffer_)) {
                    ByteVector message = connection_context_.postprocess_read(receive_buffer_);
                    size_t message_size = receive_buffer_.size();
                    receive_buffer_.erase(receive_buffer_.begin(), receive_buffer_.begin() + static_cast<int>(message_size));

                    connection_context_.on_message(message);
                } else {
                    break;
                }
            }

            if (receive_buffer_.size() > buffer_pool_->getBufferSize()) {
                LOG_WARNING("Receive buffer overflow, discarding old data");
                receive_buffer_.erase(receive_buffer_.begin(), receive_buffer_.end() - static_cast<int>(buffer_pool_->getBufferSize()));
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

            if (is_closed_.exchange(true, std::memory_order_acq_rel)) {
                return;
            }
            // Clear the write queue
            while (auto opt_buffer = send_queue_.pop()) {
                buffer_pool_->release(*opt_buffer);
            }

            if (!socket_.is_open())
            {
                connection_context_.on_close();
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

            connection_context_.on_close();
        }
    };
    template< typename SenderFramingType, typename ReceiverFramingType>
    using MessageCallback = std::function<void(const std::shared_ptr<Session<SenderFramingType, ReceiverFramingType>>&, const ByteVector&)>;

    template< typename SenderFramingType, typename ReceiverFramingType>
    static std::shared_ptr<Session<SenderFramingType, ReceiverFramingType>> create_connection(asio::io_context& io_context) {
        return std::make_shared<Session<SenderFramingType, ReceiverFramingType>>(io_context);
    }

    template< typename SenderFramingType, typename ReceiverFramingType>
    static std::shared_ptr<Session<SenderFramingType, ReceiverFramingType>> connect(
        asio::io_context& io_context,
        const std::string& host,
        const std::string& port,
        SessionContext<Session<SenderFramingType, ReceiverFramingType>, SenderFramingType, ReceiverFramingType> connection_context
) {

        auto connection = create_connection<SenderFramingType, ReceiverFramingType>(io_context);


        auto endpoints = connection->resolver.resolve(asio::ip::udp::v4(), host, port);
        connection->endpoint = *endpoints.begin();

        connection->start(connection_context);

        return connection;
    }
};