#pragma once

#include <asio.hpp>
#include <asio/ssl.hpp>
#include <memory>
#include <atomic>
#include <type_traits>
#include <variant>

#include "BufferPool.h"
#include "Logger.h"
#include "SessionContext.h"
#include "Utilities.h"


class NetworkSession : public std::enable_shared_from_this<NetworkSession>
{
public:
    enum class SessionRole
    {
        SERVER,
        CLIENT
    };

    enum class ProtocolType
    {
        TCP,
        UDP
    };

private:
    asio::io_context &io_context_;
    std::variant<asio::ip::tcp::socket, asio::ip::udp::socket> socket_;
    SessionRole session_role_;
    std::unique_ptr<asio::ssl::stream<asio::ip::tcp::socket &> > ssl_stream_;
    std::string sessionUuid_;
    asio::strand<asio::io_context::executor_type> strand_;
    std::shared_ptr<BufferPool> buffer_pool_;
    LockFreeQueue<ByteVector *, 1024> write_queue_;
    std::atomic<bool> is_closed_{false};
    ByteVector read_buffer_;
    std::shared_ptr<SessionContext> connection_context_;
    bool is_ssl_;
    bool allow_self_signed_;
    asio::steady_timer shutdown_timer_;
    ProtocolType protocol_type_;
    asio::ip::udp::endpoint udp_endpoint_;
    asio::ip::udp::resolver udp_resolver_;

public:
        // Constructor for new connections
    explicit NetworkSession(asio::io_context& io_context, ProtocolType protocol_type, asio::ssl::context* ssl_context = nullptr)
        : io_context_(io_context),
          socket_(protocol_type == ProtocolType::TCP
              ? std::variant<asio::ip::tcp::socket, asio::ip::udp::socket>(std::in_place_index<0>, io_context)
              : std::variant<asio::ip::tcp::socket, asio::ip::udp::socket>(std::in_place_index<1>, io_context, asio::ip::udp::endpoint(asio::ip::udp::v4(), 0))),
          session_role_(SessionRole::SERVER),
          sessionUuid_(Utilities::generateUuid()),
          strand_(asio::make_strand(io_context)),
          buffer_pool_(std::make_shared<BufferPool>(65536)),
          is_ssl_(ssl_context != nullptr && protocol_type == ProtocolType::TCP),
          allow_self_signed_(false),
          shutdown_timer_(io_context),
          protocol_type_(protocol_type),
          udp_resolver_(io_context)
    {
        if (is_ssl_ && protocol_type == ProtocolType::TCP) {
            ssl_stream_ = std::make_unique<asio::ssl::stream<asio::ip::tcp::socket&>>(std::get<asio::ip::tcp::socket>(socket_), *ssl_context);
        }
        read_buffer_.reserve(buffer_pool_->getBufferSize());
    }

    // Constructor for existing TCP socket
    explicit NetworkSession(asio::io_context& io_context, asio::ip::tcp::socket socket, asio::ssl::context* ssl_context = nullptr)
        : io_context_(io_context),
          socket_(std::move(socket)),
          session_role_(SessionRole::SERVER),
          sessionUuid_(Utilities::generateUuid()),
          strand_(asio::make_strand(io_context)),
          buffer_pool_(std::make_shared<BufferPool>(65536)),
          is_ssl_(ssl_context != nullptr),
          allow_self_signed_(false),
          shutdown_timer_(io_context),
          protocol_type_(ProtocolType::TCP),
          udp_resolver_(io_context)
    {
        if (is_ssl_) {
            ssl_stream_ = std::make_unique<asio::ssl::stream<asio::ip::tcp::socket&>>(std::get<asio::ip::tcp::socket>(socket_), *ssl_context);
        }
        read_buffer_.reserve(buffer_pool_->getBufferSize());
    }

    // Constructor for existing UDP socket
    explicit NetworkSession(asio::io_context& io_context, asio::ip::udp::endpoint endpoint)
        : io_context_(io_context), socket_(std::variant<asio::ip::tcp::socket, asio::ip::udp::socket>(std::in_place_index<1>, io_context, endpoint)),
          udp_endpoint_(endpoint),
          session_role_(SessionRole::SERVER),
          sessionUuid_(Utilities::generateUuid()),
          strand_(asio::make_strand(io_context)),
          buffer_pool_(std::make_shared<BufferPool>(65536)),
          is_ssl_(false),
          allow_self_signed_(false),
          shutdown_timer_(io_context),
          protocol_type_(ProtocolType::UDP),
          udp_resolver_(io_context)
    {
        read_buffer_.reserve(buffer_pool_->getBufferSize());
    }


    void start(std::shared_ptr<SessionContext> context,
               SessionRole session_role = SessionRole::SERVER,
               const std::string &hostname = "",
               bool allow_self_signed = false)
    {
        connection_context_ = context;
        connection_context_->set_session(this->shared_from_this());
        session_role_ = session_role;
        allow_self_signed_ = allow_self_signed;

        if (protocol_type_ == ProtocolType::TCP)
        {
            if (is_ssl_)
            {
                if (!hostname.empty())
                {
                    if (!SSL_set_tlsext_host_name(ssl_stream_->native_handle(), hostname.c_str()))
                    {
                        throw std::runtime_error("Failed to set SNI hostname");
                    }
                }
                do_ssl_handshake(hostname);
            } else
            {
                connection_context_->on_connect();
                do_read();
            }
        } else
        {
            connection_context_->on_connect();
            do_receive();
        }
    }

    bool is_closed() const { return is_closed_.load(std::memory_order_acquire); }

    auto &tcp_socket()
    {
        return std::get<asio::ip::tcp::socket>(socket_);
    }
    auto &udp_socket()
    {
        return std::get<asio::ip::udp::socket>(socket_);
    }
    std::string getSessionUuid() const { return sessionUuid_; }

    void write(const ByteVector &message)
    {
        if (is_closed())
        {
            return;
        }

        ByteVector *buffer = buffer_pool_->acquire();
        *buffer = connection_context_->write_preprocess(message);

        asio::post(strand_, [this, buffer]()
        {
            write_queue_.push(buffer);
            if (write_queue_.size() == 1)
            {
                if (protocol_type_ == ProtocolType::TCP)
                {
                    do_write();
                } else
                {
                    do_send();
                }
            }
        });
    }

    void close()
    {
        asio::post(strand_, [this, self = this->shared_from_this()]()
        {
            do_close();
        });
    }

private:
    void do_ssl_handshake(const std::string &hostname)
    {
        ssl_stream_->async_handshake(
            session_role_ == SessionRole::SERVER ? asio::ssl::stream_base::server : asio::ssl::stream_base::client,
            asio::bind_executor(strand_, [this, self = this->shared_from_this(), hostname](const asio::error_code &ec)
            {
                if (!ec)
                {
                    if (!hostname.empty())
                    {
                        if (!SSL_get_peer_certificate(ssl_stream_->native_handle()))
                        {
                            LOG_ERROR("No certificate was presented by the server");
                            connection_context_->on_error(asio::error::no_recovery, "No server certificate");
                            close();
                            return;
                        }
                        long verify_result = SSL_get_verify_result(ssl_stream_->native_handle());
                        if (verify_result != X509_V_OK)
                        {
                            if (!(allow_self_signed_ && verify_result == X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT))
                            {
                                LOG_ERROR("Certificate verification failed: %s",
                                          X509_verify_cert_error_string(verify_result));
                                connection_context_->on_error(asio::error::no_recovery,
                                                             "Certificate verification failed");
                                close();
                                return;
                            } else
                            {
                                LOG_WARNING("Allowing self-signed certificate");
                            }
                        }
                    }
                    connection_context_->on_connect();
                    do_read();
                } else
                {
                    LOG_ERROR("SSL handshake failed: %s", ec.message().c_str());
                    char error_buffer[256];
                    ERR_error_string_n(ERR_get_error(), error_buffer, sizeof(error_buffer));
                    LOG_ERROR("OpenSSL Error: %s", error_buffer);
                    connection_context_->on_error(ec, "SSL handshake failed");
                    close();
                }
            }));
    }

    void do_read()
    {
        auto read_buffer = buffer_pool_->acquire();
        auto buffer = asio::buffer(*read_buffer);

        auto read_handler = [this, self = this->shared_from_this(), read_buffer](
            const asio::error_code &ec, std::size_t bytes_transferred)
        {
            if (!ec)
            {
                read_buffer->resize(bytes_transferred);
                process_read_data(*read_buffer);
                do_read();
            } else if (ec != asio::error::operation_aborted)
            {
                LOG_DEBUG("Error in read: %s", ec.message().c_str());
                connection_context_->on_error(ec, "Read operation failed");
                close();
            }
            buffer_pool_->release(read_buffer);
        };

        if (is_ssl_)
        {
            ssl_stream_->async_read_some(buffer, asio::bind_executor(strand_, read_handler));
        } else
        {
            std::get<asio::ip::tcp::socket>(socket_).
                    async_read_some(buffer, asio::bind_executor(strand_, read_handler));
        }
    }

    void do_receive()
    {
        auto receive_buffer = buffer_pool_->acquire();
        receive_buffer->resize(buffer_pool_->getBufferSize());

        std::get<asio::ip::udp::socket>(socket_).async_receive_from(
            asio::buffer(*receive_buffer), udp_endpoint_,
            asio::bind_executor(strand_, [this, self = this->shared_from_this(), receive_buffer](
                            const asio::error_code &ec, std::size_t bytes_received)
                                {
                                    if (!ec)
                                    {
                                        receive_buffer->resize(bytes_received);
                                        process_read_data(*receive_buffer);
                                        do_receive();
                                    } else
                                    {
                                        LOG_ERROR("Error in receive: %s", ec.message().c_str());
                                        close();
                                    }
                                    buffer_pool_->release(receive_buffer);
                                }));
    }

    void process_read_data(const ByteVector &new_data)
    {
        read_buffer_.insert(read_buffer_.end(), new_data.begin(), new_data.end());
        MessageState message_state = connection_context_->check_message_state(read_buffer_);
        while (message_state == MessageState::FINISHED)
        {
            auto message = connection_context_->extract_message(read_buffer_);
            connection_context_->on_message(message);
            message_state = connection_context_->check_message_state(read_buffer_);
        }

    }

    void do_write()
    {
        if (is_closed())
        {
            return;
        }

        auto buffer = write_queue_.pop();
        if (!buffer)
        {
            return;
        }

        auto write_handler = [this, self = this->shared_from_this(), buffer](
            const asio::error_code &ec, std::size_t bytes_written)
        {
            buffer_pool_->release(*buffer);

            if (!ec)
            {
                LOG_DEBUG("Wrote %zu bytes", bytes_written);
                if (!write_queue_.empty())
                {
                    do_write();
                }
            } else if (ec != asio::error::operation_aborted)
            {
                LOG_DEBUG("Error in write: %s", ec.message().c_str());
                connection_context_->on_error(ec, "Write operation failed");
                close();
            }
        };

        if (is_ssl_)
        {
            asio::async_write(*ssl_stream_, asio::buffer(**buffer), asio::bind_executor(strand_, write_handler));
        } else
        {
            asio::async_write(std::get<asio::ip::tcp::socket>(socket_), asio::buffer(**buffer),
                              asio::bind_executor(strand_, write_handler));
        }
    }

    void do_send()
    {
        if (is_closed())
        {
            return;
        }

        auto buffer = write_queue_.pop();
        if (!buffer)
        {
            return;
        }

        std::get<asio::ip::udp::socket>(socket_).async_send_to(
            asio::buffer(**buffer), udp_endpoint_,
            asio::bind_executor(strand_, [this, self = this->shared_from_this(), buffer](
                            const asio::error_code &ec, std::size_t bytes_sent)
                                {
                                    buffer_pool_->release(*buffer);

                                    if (!ec)
                                    {
                                        LOG_DEBUG("Sent %zu bytes", bytes_sent);
                                        if (!write_queue_.empty())
                                        {
                                            do_send();
                                        }
                                    } else
                                    {
                                        LOG_ERROR("Error in send: %s", ec.message().c_str());
                                        close();
                                    }
                                }));
    }

    void do_close()
    {
        if (is_closed_.exchange(true, std::memory_order_acq_rel))
        {
            return;
        }

        // Clear the write queue
        while (auto opt_buffer = write_queue_.pop())
        {
            buffer_pool_->release(*opt_buffer);
        }

        if (protocol_type_ == ProtocolType::TCP)
        {
            if (!std::get<asio::ip::tcp::socket>(socket_).is_open())
            {
                connection_context_->on_close();
                return;
            }

            asio::post(strand_, [this, self = this->shared_from_this()]()
            {
                std::error_code ec;
                std::get<asio::ip::tcp::socket>(socket_).cancel(ec);
                if (ec)
                {
                    LOG_ERROR("Error cancelling pending operations: %s", ec.message().c_str());
                    connection_context_->on_error(ec, "Error cancelling pending operations");
                }

                if (is_ssl_)
                {
                    initiate_ssl_shutdown();
                } else
                {
                    finish_close();
                }
            });
        } else
        {
            if (!std::get<asio::ip::udp::socket>(socket_).is_open())
            {
                connection_context_->on_close();
                return;
            }

            asio::post(strand_, [this, self = this->shared_from_this()]()
            {
                std::error_code ec;
                std::get<asio::ip::udp::socket>(socket_).close(ec);
                if (ec)
                {
                    LOG_ERROR("Error closing UDP socket: %s", ec.message().c_str());
                    connection_context_->on_error(ec, "Error closing UDP socket");
                }
                connection_context_->on_close();
            });
        }
    }

    void initiate_ssl_shutdown()
    {
        ssl_stream_->async_shutdown(
            asio::bind_executor(strand_, [this, self = this->shared_from_this()](const asio::error_code &shutdown_ec)
            {
                handle_ssl_shutdown(shutdown_ec);
            })
        );
    }

    void handle_ssl_shutdown(const asio::error_code &shutdown_ec)
    {
        if (shutdown_ec)
        {
            if (shutdown_ec == asio::error::eof ||
                shutdown_ec == asio::ssl::error::stream_truncated ||
                ERR_GET_REASON(shutdown_ec.value()) == SSL_R_PROTOCOL_IS_SHUTDOWN)
            {
                LOG_INFO("SSL shutdown completed with expected condition: %s", shutdown_ec.message().c_str());
            } else
            {
                LOG_WARNING("Non-critical error during SSL shutdown: %s", shutdown_ec.message().c_str());
            }
        } else
        {
            LOG_INFO("SSL shutdown completed successfully");
        }

        finish_close();
    }

    void finish_close()
    {
        if (!std::get<asio::ip::tcp::socket>(socket_).is_open())
        {
            connection_context_->on_close();
            return;
        }
        std::error_code ec;
        std::get<asio::ip::tcp::socket>(socket_).shutdown(asio::ip::tcp::socket::shutdown_both, ec);
        if (ec && ec != asio::error::not_connected)
        {
            LOG_ERROR("Error shutting down socket: %s", ec.message().c_str());
            connection_context_->on_error(ec, "Error shutting down socket");
        }

        std::get<asio::ip::tcp::socket>(socket_).close(ec);
        if (ec)
        {
            LOG_ERROR("Error closing socket: %s", ec.message().c_str());
            connection_context_->on_error(ec, "Error closing socket");
        }

        connection_context_->on_close();
    }

public:
    static std::shared_ptr<NetworkSession> connect_tcp(
        asio::io_context &io_context,
        const std::string &host,
        const std::string &port,
        const std::shared_ptr<SessionContext> &connection_context,
        asio::ssl::context *ssl_context = nullptr)
    {
        auto session = std::make_shared<NetworkSession>(io_context, ProtocolType::TCP, ssl_context);

        asio::ip::tcp::resolver resolver(io_context);
        auto endpoints = resolver.resolve(host, port);

        asio::async_connect(session->tcp_socket(), endpoints,
                            [session, connection_context, host](const std::error_code &ec,
                                                                const asio::ip::tcp::endpoint &)
                            {
                                if (!ec)
                                {
                                    session->tcp_socket().set_option(asio::ip::tcp::no_delay(true));
                                    session->start(connection_context, SessionRole::CLIENT, host, true);
                                } else
                                {
                                    LOG_ERROR("TCP connection failed: %s", ec.message().c_str());
                                    session->connection_context_->on_error(ec, "TCP connection failed");
                                }
                            });

        return session;
    }

    static std::shared_ptr<NetworkSession> connect_udp(
        asio::io_context &io_context,
        const std::string &host,
        const std::string &port,
        const std::shared_ptr<SessionContext> &connection_context)
    {
        auto session = std::make_shared<NetworkSession>(io_context, ProtocolType::UDP);

        session->udp_resolver_.async_resolve(
            host, port,
            [session, connection_context](const asio::error_code &ec, asio::ip::udp::resolver::results_type results)
            {
                if (!ec)
                {
                    session->udp_endpoint_ = *results.begin();
                    session->start(connection_context, SessionRole::CLIENT);
                } else
                {
                    LOG_ERROR("UDP resolution failed: %s", ec.message().c_str());
                    session->connection_context_->on_error(ec, "UDP resolution failed");
                }
            });

        return session;
    }
};
