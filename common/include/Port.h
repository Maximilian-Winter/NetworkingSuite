//
// Created by maxim on 07.09.2024.
//

#pragma once

#include <asio.hpp>
#include <asio/ssl.hpp>
#include <functional>
#include <memory>
#include <shared_mutex>
#include <utility>
#include "HttpMessageHandler.h"

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

template<typename SendFraming, typename ReceiveFraming>
class TcpPort : public Port
{
public:
    TcpPort(asio::io_context &io_context, unsigned short port_number, const json senderFramingInitialData, const json receiveFramingInitialData)
        : Port(io_context, port_number, Protocol::TCP), senderFramingInitialData(senderFramingInitialData), receiveFramingInitialData(receiveFramingInitialData),
          acceptor_(io_context, asio::ip::tcp::endpoint(asio::ip::tcp::v4(), port_number))
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

    void setConnectedCallback(const std::function<void(std::shared_ptr<TCPNetworkUtility::Session<SendFraming, ReceiveFraming>>)> &callback)
    {
        connected_callback_ = callback;
    }

    void setMessageHandler(const std::shared_ptr<TCPMessageHandler<SendFraming, ReceiveFraming>> &handler)
    {
        message_handler_ = handler;
    }

    void setCloseCallback(const std::function<void(std::shared_ptr<TCPNetworkUtility::Session<SendFraming, ReceiveFraming>>)> &callback)
    {
        close_callback_ = callback;
    }

private:
    void do_accept()
    {
        acceptor_.async_accept(
            [this](std::error_code ec, asio::ip::tcp::socket socket)
            {
                if (!ec)
                {
                    auto session = TCPNetworkUtility::createSession<SendFraming, ReceiveFraming>(io_context_, socket, senderFramingInitialData, receiveFramingInitialData);
                    session->start(
                        [this, session](const ByteVector &data)
                        {
                            if (message_handler_)
                            {
                                message_handler_->handleMessage(session, data);
                            }
                        },
                        [this](std::shared_ptr<TCPNetworkUtility::Session<SendFraming, ReceiveFraming>> s)
                        {
                            if (close_callback_)
                            {
                                close_callback_(s);
                            }
                            {
                                std::lock_guard lock(user_mutex);
                                connected_users_.erase(s->getSessionUuid());
                            }
                        }
                    );

                    {
                        std::lock_guard lock(user_mutex);
                        connected_users_[session->getSessionUuid()] = session;
                    }
                    if (connected_callback_)
                    {
                        connected_callback_(session);
                    }
                }
                do_accept();
            });
    }
    json senderFramingInitialData;
    json receiveFramingInitialData;
    asio::ip::tcp::acceptor acceptor_;
    std::shared_ptr<TCPMessageHandler<SendFraming, ReceiveFraming>> message_handler_;
    std::mutex user_mutex;
    std::unordered_map<std::string, std::shared_ptr<TCPNetworkUtility::Session<SendFraming, ReceiveFraming>> > connected_users_;
    std::function<void(std::shared_ptr<TCPNetworkUtility::Session<SendFraming, ReceiveFraming>>)> connected_callback_;
    std::function<void(std::shared_ptr<TCPNetworkUtility::Session<SendFraming, ReceiveFraming>>)> close_callback_;
};

template<typename SendFraming, typename ReceiveFraming>
class UdpPort : public Port
{
public:
    UdpPort(asio::io_context &io_context, unsigned short port_number, json senderFramingInitialData, json receiveFramingInitialData)
        : Port(io_context, port_number, Protocol::UDP), senderFramingInitialData(std::move(senderFramingInitialData)), receiveFramingInitialData(std::move(receiveFramingInitialData)),
          socket_(io_context, asio::ip::udp::endpoint(asio::ip::udp::v4(), port_number))
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

    void setMessageHandler(const std::shared_ptr<UDPMessageHandler<SendFraming, ReceiveFraming>> &handler)
    {
        message_handler_ = handler;
    }

    void setConnectedCallback(const std::function<void(std::shared_ptr<UDPNetworkUtility::Connection<SendFraming, ReceiveFraming>>)> &callback)
    {
        connected_callback_ = callback;
    }

    void setCloseCallback(const std::function<void(std::shared_ptr<UDPNetworkUtility::Connection<SendFraming, ReceiveFraming>>)> &callback)
    {
        close_callback_ = callback;
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
                    ReceiveFraming framing_(receiveFramingInitialData);
                    if (framing_.isCompleteMessage(*receive_buffer))
                    {
                        auto message = framing_.extractMessage(*receive_buffer);
                        if (message_handler_)
                        {
                            auto connection = std::make_shared<UDPNetworkUtility::Connection<SendFraming, ReceiveFraming>>(io_context_, senderFramingInitialData, receiveFramingInitialData);
                            connection->socket() = std::move(socket_);
                            connection->endpoint = sender_endpoint_;
                            connection->start(
                                [this, connection](const ByteVector &data)
                                {
                                    if (message_handler_)
                                    {
                                        message_handler_->handleMessage(connection, data);
                                    }
                                });
                            connection->set_closed_callback(
                                [this](const std::shared_ptr<UDPNetworkUtility::Connection<SendFraming, ReceiveFraming>> &c)
                                {
                                    if (close_callback_)
                                    {
                                        close_callback_(c);
                                    }
                                    {
                                        connected_users_.erase(c->getConnectionUuid());
                                    }
                                });
                            {
                                std::lock_guard lock(user_mutex);
                                connected_users_[connection->getConnectionUuid()] = connection;
                            }
                            if (connected_callback_)
                            {
                                connected_callback_(connection);
                            }
                            message_handler_->handleMessage(connection, message);
                        }
                    }
                }
                do_receive();
            });
    }
    json senderFramingInitialData;
    json receiveFramingInitialData;
    std::mutex user_mutex;
    asio::ip::udp::socket socket_;
    asio::ip::udp::endpoint sender_endpoint_;
    std::shared_ptr<UDPMessageHandler<SendFraming, ReceiveFraming>> message_handler_;
    std::function<void(std::shared_ptr<UDPNetworkUtility::Connection<SendFraming, ReceiveFraming>>)> close_callback_;
    std::function<void(std::shared_ptr<UDPNetworkUtility::Connection<SendFraming, ReceiveFraming>>)> connected_callback_;
    std::unordered_map<std::string, std::shared_ptr<UDPNetworkUtility::Connection<SendFraming, ReceiveFraming>> > connected_users_;
    static constexpr std::size_t buffer_size = 8192;
};



template<typename SendFraming, typename ReceiveFraming>
class SslPort : public Port
{
public:
    SslPort(asio::io_context& io_context, unsigned short port_number,
            const std::string& ssl_cert_file, const std::string& ssl_key_file, const std::string& ssl_dh_file,
            json  senderFramingInitialData, json  receiveFramingInitialData)
        : Port(io_context, port_number, Protocol::TCP),
          senderFramingInitialData(std::move(senderFramingInitialData)),
          receiveFramingInitialData(std::move(receiveFramingInitialData)),
          acceptor_(io_context, asio::ip::tcp::endpoint(asio::ip::tcp::v4(), port_number)),
          ssl_context_(asio::ssl::context::sslv23)
    {
        ssl_context_.set_options(
            asio::ssl::context::default_workarounds
            | asio::ssl::context::no_sslv2
            | asio::ssl::context::single_dh_use);
        ssl_context_.use_certificate_chain_file(ssl_cert_file);
        ssl_context_.use_private_key_file(ssl_key_file, asio::ssl::context::pem);
        ssl_context_.use_tmp_dh_file(ssl_dh_file);
    }

    void start() override
    {
        do_accept();
    }

    void stop() override
    {
        acceptor_.close();
    }

    void setConnectedCallback(const std::function<void(std::shared_ptr<SSLNetworkUtility::Session<SendFraming, ReceiveFraming>>)>& callback)
    {
        connected_callback_ = callback;
    }

    void setMessageHandler(const std::shared_ptr<SSLHttpMessageHandler<SendFraming, ReceiveFraming>>& handler)
    {
        message_handler_ = handler;
    }

    void setCloseCallback(const std::function<void(std::shared_ptr<SSLNetworkUtility::Session<SendFraming, ReceiveFraming>>)>& callback)
    {
        close_callback_ = callback;
    }

private:
    void do_accept()
    {
        acceptor_.async_accept(
            [this](std::error_code ec, asio::ip::tcp::socket socket)
            {
                if (!ec)
                {
                    auto session = std::make_shared<SSLNetworkUtility::Session<SendFraming, ReceiveFraming>>(io_context_, std::move(socket), ssl_context_, senderFramingInitialData, receiveFramingInitialData);
                    session->start(
                        [this, session](const ByteVector& data)
                        {
                            if (message_handler_)
                            {
                                message_handler_->handleMessage(session, data);
                            }
                        },
                        [this](std::shared_ptr<SSLNetworkUtility::Session<SendFraming, ReceiveFraming>> s)
                        {
                            if (close_callback_)
                            {
                                close_callback_(s);
                            }
                            {
                                std::lock_guard lock(user_mutex);
                                connected_users_.erase(s->getSessionUuid());
                            }
                        }
                    );

                    {
                        std::lock_guard lock(user_mutex);
                        connected_users_[session->getSessionUuid()] = session;
                    }
                    if (connected_callback_)
                    {
                        connected_callback_(session);
                    }
                }
                do_accept();
            });
    }

    json senderFramingInitialData;
    json receiveFramingInitialData;
    asio::ip::tcp::acceptor acceptor_;
    asio::ssl::context ssl_context_;
    std::shared_ptr<SSLHttpMessageHandler<SendFraming, ReceiveFraming>> message_handler_;
    std::mutex user_mutex;
    std::unordered_map<std::string, std::shared_ptr<SSLNetworkUtility::Session<SendFraming, ReceiveFraming>>> connected_users_;
    std::function<void(std::shared_ptr<SSLNetworkUtility::Session<SendFraming, ReceiveFraming>>)> connected_callback_;
    std::function<void(std::shared_ptr<SSLNetworkUtility::Session<SendFraming, ReceiveFraming>>)> close_callback_;
};