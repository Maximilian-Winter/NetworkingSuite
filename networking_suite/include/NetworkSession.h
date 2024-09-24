#pragma once

#include <asio.hpp>
#include <asio/ssl.hpp>
#include <memory>
#include <atomic>

#include <variant>
#ifdef _WIN64
typedef __int64 ssize_t;
#else
#include <unistd.h>
#endif
#define DEBUGBUILD
#include <nghttp2/nghttp2.h>

#include "BufferPool.h"

#include "SessionContextTemplate.h"


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
    std::unique_ptr<SessionContext> connection_context_;
    bool is_ssl_;
    bool allow_self_signed_;
    asio::steady_timer shutdown_timer_;
    ProtocolType protocol_type_;
    asio::ip::udp::endpoint udp_endpoint_;
    asio::ip::udp::resolver udp_resolver_;
    asio::ssl::context *ssl_context_;
    ByteVector bulk_send_buffer_;
    std::atomic<bool> is_bulk_sending_{false};
public:
    // Constructor for new connections
    explicit NetworkSession(asio::io_context &io_context, ProtocolType protocol_type,
                            asio::ssl::context *ssl_context = nullptr);

    // Constructor for existing TCP socket
    explicit NetworkSession(asio::io_context &io_context, asio::ip::tcp::socket socket,
                            asio::ssl::context *ssl_context = nullptr);

    // Constructor for existing UDP socket
    explicit NetworkSession(asio::io_context &io_context, asio::ip::udp::endpoint endpoint);


    void start(const std::shared_ptr<SessionContextTemplate> &context_template,
               SessionRole session_role = SessionRole::SERVER,
               const std::string &hostname = "",
               bool allow_self_signed = false);

    bool is_closed() const;

    asio::ip::tcp::socket &tcp_socket();

    asio::ip::udp::socket &udp_socket();

    bool is_ssl_stream() const
    {
        return ssl_stream_ != nullptr;
    }

    asio::ssl::stream<asio::ip::tcp::socket &> &ssl_stream() const
    {
        return *ssl_stream_;
    }

    std::string getSessionUuid() const;

    void write(const ByteVector &message, bool send_all_data_at_once_in_order_added = false, bool write_immediately = false);

    void close();

private:
    void do_ssl_handshake(const std::string &hostname, const std::shared_ptr<SessionContextTemplate>& context_template);

    void do_read();

    void do_receive();

    void process_read_data(const ByteVector &new_data);

    void do_write(bool send_all_data_at_once_in_order_added = false);

    void do_send();

    void do_close();

    void initiate_ssl_shutdown();

    void handle_ssl_shutdown(const asio::error_code &shutdown_ec);

    void finish_close();

public:
    static std::shared_ptr<NetworkSession> connect_tcp(
        asio::io_context &io_context,
        const std::string &host,
        const std::string &port,
        const std::shared_ptr<SessionContextTemplate> &connection_context_template,
        asio::ssl::context *ssl_context = nullptr);

    static std::shared_ptr<NetworkSession> connect_udp(
        asio::io_context &io_context,
        const std::string &host,
        const std::string &port,
        const std::shared_ptr<SessionContextTemplate> &connection_context);
};
