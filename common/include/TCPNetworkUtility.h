#pragma once

#include <asio.hpp>
#include <functional>
#include <memory>
#include <atomic>
#include "BufferPool.h"
#include "Logger.h"
#include "MessageFraming.h"

class TCPNetworkUtility {
public:

    class Session : public std::enable_shared_from_this<Session> {
    private:
        asio::ip::tcp::socket socket_;

        asio::strand<asio::io_context::executor_type> strand_;
        std::shared_ptr<BufferPool> buffer_pool_;
        LockFreeQueue<ByteVector*, 1024> write_queue_;
        std::atomic<bool> is_closed_{false};
        std::function<void(std::shared_ptr<Session>)> connection_closed_callback_;
        std::function<void(const ByteVector&)> message_handler_;
        std::shared_ptr<MessageFraming> message_framing_;
        ByteVector read_buffer_;

    public:
        explicit Session(asio::io_context& io_context, std::shared_ptr<MessageFraming> framing)
            : socket_(io_context),
              strand_(asio::make_strand(io_context)),
              buffer_pool_(std::make_shared<BufferPool>(8192)),
              message_framing_(std::move(framing)) {
            read_buffer_.reserve(buffer_pool_->getBufferSize() + message_framing_->getMaxFramingOverhead());
        }

        void start(const std::function<void(const ByteVector&)>& messageHandler,
                   const std::function<void(std::shared_ptr<Session>)>& closedCallback) {
            message_handler_ = messageHandler;
            connection_closed_callback_ = closedCallback;
            do_read();
        }

        bool is_closed() const { return is_closed_.load(std::memory_order_acquire); }

        asio::ip::tcp::socket& socket() { return socket_; }

        void write(const ByteVector& message) {
            if (is_closed()) {
                return;
            }

            ByteVector* buffer = buffer_pool_->acquire();
            *buffer = message_framing_->frameMessage(message);

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

            asio::post(strand_, [this, self = shared_from_this()]() {
                do_close();
            });
        }

    private:
        void do_read() {
            auto read_buffer = buffer_pool_->acquire();
            socket_.async_read_some(
                asio::buffer(read_buffer->data(), read_buffer->size()),
                asio::bind_executor(strand_, [this, self = shared_from_this(), read_buffer](
                    const asio::error_code& ec, std::size_t bytes_transferred) {
                    if (!ec) {
                        read_buffer->resize(bytes_transferred);
                        process_read_data(*read_buffer);
                        do_read();
                    } else if (ec != asio::error::operation_aborted) {
                        LOG_ERROR("Error in read: %s", ec.message().c_str());
                        close();
                    }
                    buffer_pool_->release(read_buffer);
                }));
        }

        void process_read_data(const ByteVector& new_data) {
            read_buffer_.insert(read_buffer_.end(), new_data.begin(), new_data.end());

            while (true) {
                if (message_framing_->isCompleteMessage(read_buffer_)) {
                    ByteVector message = message_framing_->extractMessage(read_buffer_);
                    size_t message_size = message_framing_->frameMessage(message).size();
                    read_buffer_.erase(read_buffer_.begin(), read_buffer_.begin() + static_cast<int>(message_size));

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

            asio::async_write(socket_, asio::buffer(**buffer),
                asio::bind_executor(strand_, [this, self = shared_from_this(), buffer](
                    const asio::error_code& ec, std::size_t bytes_written) {
                    buffer_pool_->release(*buffer);

                    if (!ec) {
                        LOG_DEBUG("Wrote %zu bytes", bytes_written);
                        if (!write_queue_.empty()) {
                            do_write();
                        }
                    } else if (ec != asio::error::operation_aborted) {
                        LOG_ERROR("Error in write: %s", ec.message().c_str());
                        close();
                    }
                }));
        }

        void do_close() {
            while (auto buffer = write_queue_.pop()) {
                buffer_pool_->release(*buffer);
            }

            std::error_code ec;
            socket_.shutdown(asio::ip::tcp::socket::shutdown_both, ec);
            if (ec) {
                LOG_ERROR("Error shutting down socket: %s", ec.message().c_str());
            }

            socket_.close(ec);
            if (ec) {
                LOG_ERROR("Error closing socket: %s", ec.message().c_str());
            }

            if (connection_closed_callback_) {
                connection_closed_callback_(shared_from_this());
            }
        }

    };
    using MessageCallback = std::function<void(const std::shared_ptr<Session>&, const ByteVector&)>;
    static std::shared_ptr<Session> createSession(asio::io_context& io_context, asio::ip::tcp::socket& socket, const std::shared_ptr<MessageFraming>& framing) {
        auto session = std::make_shared<Session>(io_context, framing);
        session->socket() = std::move(socket);
        return session;
    }

    static std::shared_ptr<Session> connect(
        asio::io_context& io_context,
        const std::string& host,
        const std::string& port,
        const std::shared_ptr<MessageFraming>& framing,
        const std::function<void(std::error_code, std::shared_ptr<Session>)>& callback,
        const MessageCallback& messageCallback,
        const std::function<void(std::shared_ptr<Session>)>& closedCallback) {

        auto session = std::make_shared<Session>(io_context, framing);

        asio::ip::tcp::resolver resolver(io_context);
        auto endpoints = resolver.resolve(host, port);

        asio::async_connect(session->socket(), endpoints,
            [session, callback, closedCallback, messageCallback](const std::error_code& ec, const asio::ip::tcp::endpoint&) {
                if (!ec) {
                    session->start(
                        [session, messageCallback, ec](const ByteVector& data) {
                            messageCallback(session, data);
                        },
                        closedCallback
                    );
                }
                callback(ec, session);
            });

        return session;
    }
};