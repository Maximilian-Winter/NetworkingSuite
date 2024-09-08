//
// Created by maxim on 08.09.2024.
//
#pragma once

#include <asio/ssl.hpp>
#include <asio.hpp>
#include <functional>
#include <memory>
#include <atomic>
#include "BufferPool.h"
#include "Logger.h"
#include "MessageFraming.h"
#include "Utilities.h"

class SSLNetworkUtility {
public:
    template<typename SendFraming, typename ReceiveFraming>
    class Session : public std::enable_shared_from_this<Session<SendFraming, ReceiveFraming>> {
    protected:
        asio::ip::tcp::socket socket_;
        std::unique_ptr<asio::ssl::stream<asio::ip::tcp::socket>> ssl_socket_;
        std::string sessionUuid_;
        asio::strand<asio::io_context::executor_type> strand_;
        std::shared_ptr<BufferPool> buffer_pool_;
        LockFreeQueue<ByteVector*, 1024> write_queue_;
        std::atomic<bool> is_closed_{false};
        std::function<void(std::shared_ptr<Session>)> connection_closed_callback_;
        std::function<void(const ByteVector&)> message_handler_;
        SendFraming send_framing_;
        ReceiveFraming receive_framing_;
        ByteVector read_buffer_;

    public:
        virtual ~Session() = default;

        auto get_shared_this() {
            return this->std::enable_shared_from_this<Session>::shared_from_this();
        }

        explicit Session(asio::io_context& io_context, asio::ip::tcp::socket socket, asio::ssl::context& ssl_context, const json senderFramingInitialData, const json receiveFramingInitialData)
        : socket_(std::move(socket)),
              ssl_socket_(new asio::ssl::stream<asio::ip::tcp::socket>(std::move(socket_), ssl_context)),
              strand_(asio::make_strand(io_context)),
              buffer_pool_(std::make_shared<BufferPool>(8192)),
              sessionUuid_(Utilities::generateUuid()), send_framing_(senderFramingInitialData), receive_framing_(receiveFramingInitialData)
        {
            read_buffer_.reserve(buffer_pool_->getBufferSize() + receive_framing_.getMaxFramingOverhead());
        }

        void start(const std::function<void(const ByteVector&)>& messageHandler,
                   const std::function<void(std::shared_ptr<Session>)>& closedCallback) {
            message_handler_ = messageHandler;
            connection_closed_callback_ = closedCallback;
            do_handshake();
        }

        bool is_closed() const { return is_closed_.load(std::memory_order_acquire); }

        asio::ssl::stream<asio::ip::tcp::socket>& socket() { return *ssl_socket_; }

        std::string getSessionUuid() { return sessionUuid_; }

        void write(const ByteVector& message) {
            if (is_closed()) {
                return;
            }

            ByteVector* buffer = buffer_pool_->acquire();
            *buffer = send_framing_.frameMessage(message);

            asio::post(strand_, [this, buffer]() {
                write_queue_.push(buffer);
                if (write_queue_.size() == 1) {
                    do_write();
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

    protected:
        void do_handshake() {

            ssl_socket_->async_handshake(asio::ssl::stream_base::server,
                asio::bind_executor(strand_, [this, self = get_shared_this()](const asio::error_code& ec) {
                    if (!ec) {
                        do_read();
                    } else {
                        LOG_ERROR("SSL handshake failed: %s", ec.message().c_str());
                        close();
                    }
                }));
        }

        void do_read() {
            auto read_buffer = buffer_pool_->acquire();
            asio::async_read(*ssl_socket_,
                asio::buffer(*read_buffer),
                asio::bind_executor(strand_, [this, self = get_shared_this(), read_buffer](
                    const asio::error_code& ec, std::size_t bytes_transferred) {
                    if (!ec) {
                        read_buffer->resize(bytes_transferred);
                        process_read_data(*read_buffer);
                        do_read();
                    } else if (ec != asio::error::operation_aborted) {
                        LOG_DEBUG("Error in SSL read: %s", ec.message().c_str());
                        close();
                    }
                    buffer_pool_->release(read_buffer);
                }));
        }

        void process_read_data(const ByteVector& new_data) {
            read_buffer_.insert(read_buffer_.end(), new_data.begin(), new_data.end());

            while (true) {
                if (receive_framing_.isCompleteMessage(read_buffer_)) {
                    ByteVector message = receive_framing_.extractMessage(read_buffer_);
                    ByteVector message_size = receive_framing_.frameMessage(message);
                    read_buffer_.erase(read_buffer_.begin(), read_buffer_.begin() + static_cast<int>(message_size.size()));

                    message_handler_(message);
                } else {
                    break;
                }
            }

            if (read_buffer_.size() > buffer_pool_->getBufferSize()) {
                LOG_WARNING("Read buffer overflow, discarding old data");
                read_buffer_.erase(read_buffer_.begin(), read_buffer_.end() - static_cast<int>(buffer_pool_->getBufferSize()));
            }
        }

        void do_write() {
            if (is_closed()) {
                return;
            }

            auto buffer = write_queue_.pop();
            if (!buffer) {
                return;
            }

            asio::async_write(ssl_socket_, asio::buffer(**buffer),
                asio::bind_executor(strand_, [this, self = get_shared_this(), buffer](
                    const asio::error_code& ec, std::size_t bytes_written) {
                    buffer_pool_->release(*buffer);

                    if (!ec) {
                        LOG_DEBUG("Wrote %zu bytes over SSL", bytes_written);
                        if (!write_queue_.empty()) {
                            do_write();
                        }
                    } else if (ec != asio::error::operation_aborted) {
                        LOG_DEBUG("Error in SSL write: %s", ec.message().c_str());
                        close();
                    }
                }));
        }

        void do_close() {
            // Clear the write queue
            while (auto opt_buffer = write_queue_.pop()) {
                buffer_pool_->release(*opt_buffer);
            }

            if (!ssl_socket_->lowest_layer().is_open()) {
                if (connection_closed_callback_) {
                    connection_closed_callback_(get_shared_this());
                }
                return; // Socket is already closed
            }

            std::error_code ec;

            // Cancel any pending asynchronous operations
            ssl_socket_->lowest_layer().cancel(ec);
            if (ec) {
                LOG_ERROR("Error cancelling pending operations: %s", ec.message().c_str());
            }

            // Perform SSL shutdown
            ssl_socket_->async_shutdown(
                [this, self = get_shared_this()](const asio::error_code& shutdown_ec) {
                    if (shutdown_ec) {
                        LOG_ERROR("Error during SSL shutdown: %s", shutdown_ec.message().c_str());
                    }

                    // Close the underlying socket
                    asio::error_code close_ec;
                    ssl_socket_->lowest_layer().close(close_ec);
                    if (close_ec) {
                        LOG_ERROR("Error closing socket: %s", close_ec.message().c_str());
                    }

                    if (connection_closed_callback_) {
                        connection_closed_callback_(get_shared_this());
                    }
                });
        }
    };

    template<typename SendFraming, typename ReceiveFraming>
    static std::shared_ptr<Session<SendFraming, ReceiveFraming>> createSession(
        asio::io_context& io_context, asio::ip::tcp::socket socket, asio::ssl::context& ssl_context,
        const json senderFramingInitialData, const json receiveFramingInitialData) {
        return std::make_shared<Session<SendFraming, ReceiveFraming>>(
            io_context, socket, ssl_context, senderFramingInitialData, receiveFramingInitialData);
    }

    template<typename SendFraming, typename ReceiveFraming>
    static std::shared_ptr<Session<SendFraming, ReceiveFraming>> connect(
        asio::io_context& io_context, asio::ssl::context& ssl_context,
        const std::string& host, const std::string& port,
        const std::function<void(std::error_code, std::shared_ptr<Session<SendFraming, ReceiveFraming>>)>& callback,
        const std::function<void(std::shared_ptr<Session<SendFraming, ReceiveFraming>> session, ByteVector message)>& messageCallback,
        const std::function<void(std::shared_ptr<Session<SendFraming, ReceiveFraming>>)>& closedCallback,
        const json& senderFramingInitialData, const json& receiveFramingInitialData) {
        asio::ip::tcp::socket socket(io_context);
        auto session = std::make_shared<Session<SendFraming, ReceiveFraming>>(
            io_context, socket, ssl_context, senderFramingInitialData, receiveFramingInitialData);

        asio::ip::tcp::resolver resolver(io_context);
        auto endpoints = resolver.resolve(host, port);

        asio::async_connect(session->socket(), endpoints,
            [session, callback, closedCallback, messageCallback](const std::error_code& ec, const asio::ip::tcp::endpoint&) {
                if (!ec) {
                    session->ssl_socket_.async_handshake(asio::ssl::stream_base::client,
                        [session, callback, closedCallback, messageCallback](const std::error_code& handshake_ec) {
                            if (!handshake_ec) {
                                session->start(
                                    [session, messageCallback](const ByteVector& data) {
                                        messageCallback(session, data);
                                    },
                                    closedCallback
                                );
                                callback(handshake_ec, session);
                            } else {
                                callback(handshake_ec, nullptr);
                            }
                        });
                } else {
                    callback(ec, nullptr);
                }
            });

        return session;
    }
};