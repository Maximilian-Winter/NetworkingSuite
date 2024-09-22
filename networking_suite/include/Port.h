//
// Created by maxim on 07.09.2024.
//

#pragma once

#include <asio.hpp>
#include <asio/ssl.hpp>
#include <memory>
#include <NetworkSession.h>
#include <shared_mutex>

#include <utility>

#include "SessionContext.h"


class Port
{
public:
    enum class Protocol { TCP, UDP };

    Port(asio::io_context &io_context, unsigned short port_number, Protocol protocol)
        : io_context_(io_context), port_number_(port_number), protocol_(protocol)
    {
    }

    virtual ~Port() = default;

    virtual void start() = 0;

    virtual void stop() = 0;

    [[nodiscard]] unsigned short getPortNumber() const { return port_number_; }
    [[nodiscard]] Protocol getProtocol() const { return protocol_; }

protected:
    asio::io_context &io_context_;
    unsigned short port_number_;
    Protocol protocol_;

};



template< typename SenderFramingType, typename ReceiverFramingType>
class TcpPort : public Port
{
public:
    TcpPort(asio::io_context &io_context, unsigned short port_number, SessionContext<NetworkSession<SenderFramingType, ReceiverFramingType>,SenderFramingType, ReceiverFramingType>& connection_context, asio::ssl::context* ssl_context = nullptr)
        : Port(io_context, port_number, Protocol::TCP), connection_context_(connection_context),
          acceptor_(io_context, asio::ip::tcp::endpoint(asio::ip::tcp::v4(), port_number)), ssl_context_(ssl_context)
    {
    }

    void start() override
    {
        do_accept();
    }

    void stop() override
    {
        acceptor_.close();
    }


private:
    void do_accept()
    {
        acceptor_.async_accept(
            [this](std::error_code ec, asio::ip::tcp::socket socket)
            {
                if (!ec)
                {
                    auto session = std::make_shared<NetworkSession<SenderFramingType, ReceiverFramingType>>(io_context_, std::move(socket), ssl_context_);
                    session->start(connection_context_);

                    {
                        std::lock_guard lock(user_mutex);
                        connected_users_[session->getSessionUuid()] = session;
                    }
                    connection_context_.on_connect();
                }
                do_accept();
            });
    }
    asio::ssl::context* ssl_context_;
    asio::ip::tcp::acceptor acceptor_;
    SessionContext<NetworkSession<SenderFramingType, ReceiverFramingType>, SenderFramingType, ReceiverFramingType>& connection_context_;
    std::mutex user_mutex;
    std::unordered_map<std::string, std::shared_ptr<NetworkSession<SenderFramingType, ReceiverFramingType>>> connected_users_;
};
template< typename SenderFramingType, typename ReceiverFramingType>
class UdpPort : public Port
{
public:
    UdpPort(asio::io_context &io_context, unsigned short port_number, SessionContext<NetworkSession<SenderFramingType, ReceiverFramingType>,SenderFramingType, ReceiverFramingType >& connection_context)
        : Port(io_context, port_number, Protocol::UDP),
          socket_(io_context, asio::ip::udp::endpoint(asio::ip::udp::v4(), port_number)),
            connection_context_(connection_context)
    {
    }

    void start() override
    {
        do_receive();
    }

    void stop() override
    {
        socket_.close();
    }


private:
    void do_receive()
    {
        auto receive_buffer = std::make_shared<ByteVector>(buffer_size);
        socket_.async_receive_from(
            asio::buffer(*receive_buffer),
            sender_endpoint_,
            [this, receive_buffer](std::error_code ec, std::size_t bytes_recvd)
            {
                if (!ec)
                {
                    receive_buffer->resize(bytes_recvd);
                    if (connection_context_.checkIfIsCompleteMessage(*receive_buffer))
                    {
                        auto message = connection_context_.postprocess_read(*receive_buffer);
                        auto connection = std::make_shared<NetworkSession<SenderFramingType, ReceiverFramingType>>(io_context_, std::move(socket));
                            connection->udp_endpoint_ = sender_endpoint_;
                            connection->start(connection_context_);
                            {
                                std::lock_guard lock(user_mutex);
                                connected_users_[connection->getConnectionUuid()] = connection;
                            }
                            connection_context_.on_connect();

                            connection_context_.on_message(message);
                    }
                }
                do_receive();
            });
    }

    std::mutex user_mutex;
    asio::ip::udp::socket socket_;
    asio::ip::udp::endpoint sender_endpoint_;
    SessionContext<NetworkSession<SenderFramingType, ReceiverFramingType>,SenderFramingType, ReceiverFramingType>& connection_context_;
    std::unordered_map<std::string, std::shared_ptr<NetworkSession<SenderFramingType, ReceiverFramingType>> > connected_users_;
    static constexpr std::size_t buffer_size = 65536;
};
