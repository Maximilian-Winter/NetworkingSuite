//
// Created by maxim on 10.09.2024.
//

#pragma once

#include <asio.hpp>
#include <asio/ssl.hpp>
#include <memory>
#include <atomic>
#include <type_traits>
#include "BufferPool.h"
#include "Logger.h"
#include "SessionContext.h"
#include "Utilities.h"

template<typename SenderFramingType, typename ReceiverFramingType>
class NetworkSession : public std::enable_shared_from_this<NetworkSession<SenderFramingType, ReceiverFramingType>> {
private:
    asio::io_context& io_context_;
    asio::ip::tcp::socket socket_;
    std::unique_ptr<asio::ssl::stream<asio::ip::tcp::socket&>> ssl_stream_;
    std::string sessionUuid_;
    asio::strand<asio::io_context::executor_type> strand_;
    std::shared_ptr<BufferPool> buffer_pool_;
    LockFreeQueue<ByteVector*, 1024> write_queue_;
    std::atomic<bool> is_closed_{false};
    ByteVector read_buffer_;
    SessionContext<NetworkSession, SenderFramingType, ReceiverFramingType> connection_context_;
    bool is_ssl_;

public:
    explicit NetworkSession(asio::io_context& io_context, asio::ip::tcp::socket socket, asio::ssl::context* ssl_context = nullptr)
    : io_context_(io_context),
      socket_(std::move(socket)),
      sessionUuid_(Utilities::generateUuid()),
      strand_(asio::make_strand(io_context)),
      buffer_pool_(std::make_shared<BufferPool>(32728)),
      is_ssl_(ssl_context != nullptr)
    {
        if (is_ssl_) {
            ssl_stream_ = std::make_unique<asio::ssl::stream<asio::ip::tcp::socket&>>(socket_, *ssl_context);
        }
        read_buffer_.reserve(buffer_pool_->getBufferSize());
    }

    explicit NetworkSession(asio::io_context& io_context, asio::ssl::context* ssl_context = nullptr)
        : io_context_(io_context),
          socket_(io_context),
          sessionUuid_(Utilities::generateUuid()),
          strand_(asio::make_strand(io_context)),
          buffer_pool_(std::make_shared<BufferPool>(32728)),
          is_ssl_(ssl_context != nullptr)
    {
        if (is_ssl_) {
            ssl_stream_ = std::make_unique<asio::ssl::stream<asio::ip::tcp::socket&>>(socket_, *ssl_context);
        }
        read_buffer_.reserve(buffer_pool_->getBufferSize());
    }
    void start(const SessionContext<NetworkSession, SenderFramingType, ReceiverFramingType>& context) {
        connection_context_ = context;
        connection_context_.set_port(this->shared_from_this());

        if (is_ssl_) {
            do_ssl_handshake();
        } else {
            connection_context_.on_connect();
            do_read();
        }
    }

    bool is_closed() const { return is_closed_.load(std::memory_order_acquire); }
    asio::ip::tcp::socket& socket() { return socket_; }
    std::string getSessionUuid() const { return sessionUuid_; }

    void write(const ByteVector& message) {
        if (is_closed()) {
            return;
        }

        ByteVector* buffer = buffer_pool_->acquire();
        *buffer = connection_context_.preprocess_write(message);

        asio::post(strand_, [this, buffer]() {
            write_queue_.push(buffer);
            if (write_queue_.size() == 1) {
                do_write();
            }
        });
    }

    void close() {
        asio::post(strand_, [this, self = this->shared_from_this()]() {
            do_close();
        });
    }

private:
    void do_ssl_handshake() {
        ssl_stream_->async_handshake(asio::ssl::stream_base::server,
            asio::bind_executor(strand_, [this, self = this->shared_from_this()](const asio::error_code& ec) {
                if (!ec) {
                    connection_context_.on_connect();
                    do_read();
                } else {
                    LOG_ERROR("SSL handshake failed: %s", ec.message().c_str());
                    close();
                }
            }));
    }

    void do_read() {
        auto read_buffer = buffer_pool_->acquire();
        auto buffer = asio::buffer(*read_buffer);

        auto read_handler = [this, self = this->shared_from_this(), read_buffer](
            const asio::error_code& ec, std::size_t bytes_transferred) {
            if (!ec) {
                read_buffer->resize(bytes_transferred);
                process_read_data(*read_buffer);
                do_read();
            } else if (ec != asio::error::operation_aborted) {
                LOG_DEBUG("Error in read: %s", ec.message().c_str());
                close();
            }
            buffer_pool_->release(read_buffer);
        };

        if (is_ssl_) {
            ssl_stream_->async_read_some(buffer, asio::bind_executor(strand_, read_handler));
        } else {
            socket_.async_read_some(buffer, asio::bind_executor(strand_, read_handler));
        }
    }

    void process_read_data(const ByteVector& new_data) {
        read_buffer_.insert(read_buffer_.end(), new_data.begin(), new_data.end());

        while (true) {
            if (connection_context_.checkIfIsCompleteMessage(read_buffer_)) {
                ByteVector message = connection_context_.postprocess_read(read_buffer_);
                size_t message_size = read_buffer_.size();
                read_buffer_.erase(read_buffer_.begin(), read_buffer_.begin() + static_cast<int>(message_size));

                connection_context_.on_message(message);
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

        auto write_handler = [this, self = this->shared_from_this(), buffer](
            const asio::error_code& ec, std::size_t bytes_written) {
            buffer_pool_->release(*buffer);

            if (!ec) {
                LOG_DEBUG("Wrote %zu bytes", bytes_written);
                if (!write_queue_.empty()) {
                    do_write();
                }
            } else if (ec != asio::error::operation_aborted) {
                LOG_DEBUG("Error in write: %s", ec.message().c_str());
                close();
            }
        };

        if (is_ssl_) {
            asio::async_write(*ssl_stream_, asio::buffer(**buffer), asio::bind_executor(strand_, write_handler));
        } else {
            asio::async_write(socket_, asio::buffer(**buffer), asio::bind_executor(strand_, write_handler));
        }
    }

    void do_close() {

        if (is_closed_.exchange(true, std::memory_order_acq_rel)) {
            return;
        }

        // Clear the write queue
        while (auto opt_buffer = write_queue_.pop()) {
            buffer_pool_->release(*opt_buffer);
        }

        if (!socket_.is_open()) {
            connection_context_.on_close();
            return;
        }

        std::error_code ec;

        // Cancel any pending asynchronous operations
        socket_.cancel(ec);
        if (ec) {
            LOG_ERROR("Error cancelling pending operations: %s", ec.message().c_str());
        }

        if (is_ssl_) {
            ssl_stream_->async_shutdown(
                [this, self = this->shared_from_this()](const asio::error_code& shutdown_ec) {
                    if (shutdown_ec) {
                        LOG_ERROR("Error during SSL shutdown: %s", shutdown_ec.message().c_str());
                    }
                    finish_close();
                });
        } else {
            finish_close();
        }
    }

    void finish_close() {
        std::error_code ec;
        socket_.shutdown(asio::ip::tcp::socket::shutdown_both, ec);
        if (ec && ec != asio::error::not_connected) {
            LOG_ERROR("Error shutting down socket: %s", ec.message().c_str());
        }

        socket_.close(ec);
        if (ec) {
            LOG_ERROR("Error closing socket: %s", ec.message().c_str());
        }

        connection_context_.on_close();
    }
public:

    static std::shared_ptr<NetworkSession> createSession(
        asio::io_context& io_context,
        asio::ip::tcp::socket& socket,
        asio::ssl::context* ssl_context = nullptr)
    {
        auto session = std::make_shared<NetworkSession>(io_context, ssl_context);
        session->socket() = std::move(socket);
        return session;
    }


    static std::shared_ptr<NetworkSession> connect(
        asio::io_context& io_context,
        const std::string& host,
        const std::string& port,
        const SessionContext<NetworkSession, SenderFramingType, ReceiverFramingType>& connection_context,
        asio::ssl::context* ssl_context = nullptr)
    {
        auto session = std::make_shared<NetworkSession>(io_context, ssl_context);

        asio::ip::tcp::resolver resolver(io_context);
        auto endpoints = resolver.resolve(host, port);

        asio::async_connect(session->socket(), endpoints,
            [session, connection_context](const std::error_code& ec, const asio::ip::tcp::endpoint&) {
                if (!ec) {
                    session->start(connection_context);
                }
            });

        return session;
    }

};
