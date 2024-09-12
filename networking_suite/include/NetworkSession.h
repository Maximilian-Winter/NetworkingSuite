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
public:
    enum class SessionRole
    {
        SERVER,
        CLIENT
    };
private:
    asio::io_context& io_context_;
    asio::ip::tcp::socket socket_;
    SessionRole session_role_;
    std::unique_ptr<asio::ssl::stream<asio::ip::tcp::socket&>> ssl_stream_;
    std::string sessionUuid_;
    asio::strand<asio::io_context::executor_type> strand_;
    std::shared_ptr<BufferPool> buffer_pool_;
    LockFreeQueue<ByteVector*, 1024> write_queue_;
    std::atomic<bool> is_closed_{false};
    ByteVector read_buffer_;
    SessionContext<NetworkSession, SenderFramingType, ReceiverFramingType> connection_context_;
    bool is_ssl_;
    bool allow_self_signed_;
public:
    explicit NetworkSession(asio::io_context& io_context, asio::ip::tcp::socket socket, asio::ssl::context* ssl_context = nullptr)
        : io_context_(io_context),
          socket_(std::move(socket)), session_role_(SessionRole::SERVER),
          sessionUuid_(Utilities::generateUuid()),
          strand_(asio::make_strand(io_context)),
          buffer_pool_(std::make_shared<BufferPool>(32728)),
          is_ssl_(ssl_context != nullptr), allow_self_signed_(false)
    {
        if (is_ssl_)
        {
            ssl_stream_ = std::make_unique<asio::ssl::stream<asio::ip::tcp::socket &> >(socket_, *ssl_context);
        }
        read_buffer_.reserve(buffer_pool_->getBufferSize());
    }

    explicit NetworkSession(asio::io_context& io_context, asio::ssl::context* ssl_context = nullptr)
        : io_context_(io_context),
          socket_(io_context), session_role_(SessionRole::SERVER),
          sessionUuid_(Utilities::generateUuid()),
          strand_(asio::make_strand(io_context)),
          buffer_pool_(std::make_shared<BufferPool>(32728)),
          is_ssl_(ssl_context != nullptr), allow_self_signed_(false)
    {
        if (is_ssl_)
        {
            ssl_stream_ = std::make_unique<asio::ssl::stream<asio::ip::tcp::socket &> >(socket_, *ssl_context);
        }
        read_buffer_.reserve(buffer_pool_->getBufferSize());
    }

    void start(const SessionContext<NetworkSession, SenderFramingType, ReceiverFramingType>& context,
               SessionRole session_role = SessionRole::SERVER,
               const std::string& hostname = "",
               bool allow_self_signed = false) {
        connection_context_ = context;
        connection_context_.set_session(this->shared_from_this());
        session_role_ = session_role;
        allow_self_signed_ = allow_self_signed;
        if (is_ssl_) {
            if (!hostname.empty()) {
                if (!SSL_set_tlsext_host_name(ssl_stream_->native_handle(), hostname.c_str())) {
                    throw std::runtime_error("Failed to set SNI hostname");
                }
            }
            do_ssl_handshake(hostname);
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
    void do_ssl_handshake(const std::string& hostname) {
        ssl_stream_->async_handshake(
            session_role_ == SessionRole::SERVER ? asio::ssl::stream_base::server : asio::ssl::stream_base::client,
            asio::bind_executor(strand_, [this, self = this->shared_from_this(), hostname](const asio::error_code& ec) {
                if (!ec) {
                    if (!hostname.empty()) {
                        if (!SSL_get_peer_certificate(ssl_stream_->native_handle())) {
                            LOG_ERROR("No certificate was presented by the server");
                            connection_context_.on_error(asio::error::no_recovery, "No server certificate");
                            close();
                            return;
                        }
                        long verify_result = SSL_get_verify_result(ssl_stream_->native_handle());
                        if (verify_result != X509_V_OK) {
                            if (!(allow_self_signed_ && verify_result == X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT)) {
                                LOG_ERROR("Certificate verification failed: %s", X509_verify_cert_error_string(verify_result));
                                connection_context_.on_error(asio::error::no_recovery, "Certificate verification failed");
                                close();
                                return;
                            } else {
                                LOG_WARNING("Allowing self-signed certificate");
                            }
                        }
                        // Perform hostname verification here if needed
                    }
                    connection_context_.on_connect();
                    do_read();
                } else {
                    LOG_ERROR("SSL handshake failed: %s", ec.message().c_str());
                    char error_buffer[256];
                    ERR_error_string_n(ERR_get_error(), error_buffer, sizeof(error_buffer));
                    LOG_ERROR("OpenSSL Error: %s", error_buffer);
                    connection_context_.on_error(ec, "SSL handshake failed");
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
                connection_context_.on_error(ec, "Read operation failed");
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
                connection_context_.on_error(ec, "Write operation failed");
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
            connection_context_.on_error(ec, "Error cancelling pending operations");
        }

        if (is_ssl_) {
            ssl_stream_->async_shutdown(
                [this, self = this->shared_from_this()](const asio::error_code& shutdown_ec) {
                    if (shutdown_ec) {
                        LOG_ERROR("Error during SSL shutdown: %s", shutdown_ec.message().c_str());
                        connection_context_.on_error(shutdown_ec, "SSL shutdown failed");
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
            connection_context_.on_error(ec, "Error shutting down socket");
        }

        socket_.close(ec);
        if (ec) {
            LOG_ERROR("Error closing socket: %s", ec.message().c_str());
            connection_context_.on_error(ec, "Error closing socket");
        }

        connection_context_.on_close();
    }
public:

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
            [session, connection_context, host](const std::error_code& ec, const asio::ip::tcp::endpoint&) {
                if (!ec) {
                    session->socket().set_option(asio::ip::tcp::no_delay(true));
                    session->start(connection_context, SessionRole::CLIENT, host, true);
                } else {
                    LOG_ERROR("Connection failed: %s", ec.message().c_str());
                    session->connection_context_.on_error(ec, "Connection failed");
                }
            });

        return session;
    }

};
