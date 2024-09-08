//
// Created by maxim on 07.09.2024.
//

#pragma once

#include <asio.hpp>
#include <functional>
#include <memory>
#include <shared_mutex>
#include <utility>


class Port
{
public:
    enum class Protocol { TCP, UDP };

    Port(asio::io_context &io_context, unsigned short port_number, Protocol protocol,
         std::shared_ptr<MessageFraming> framing)
        : io_context_(io_context), port_number_(port_number), protocol_(protocol),
          framing_(std::move(framing))
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
    std::shared_ptr<MessageFraming> framing_;
};

class TCPPort : public Port
{
public:
    TCPPort(asio::io_context &io_context, unsigned short port_number,
            std::shared_ptr<MessageFraming> framing)
        : Port(io_context, port_number, Protocol::TCP, std::move(framing)),
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

    void setConnectedCallback(const std::function<void(std::shared_ptr<TCPNetworkUtility::Session>)> &callback)
    {
        connected_callback_ = callback;
    }

    void setMessageHandler(const std::shared_ptr<MessageHandler<std::shared_ptr<TCPNetworkUtility::Session>>> &handler)
    {
        message_handler_ = handler;
    }

    void setCloseCallback(const std::function<void(std::shared_ptr<TCPNetworkUtility::Session>)> &callback)
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
                    auto session = TCPNetworkUtility::createSession(io_context_, socket, framing_);
                    session->start(
                        [this, session](const ByteVector &data)
                        {
                            if (message_handler_)
                            {
                                message_handler_->handleMessage(session, data);
                            }
                        },
                        [this](std::shared_ptr<TCPNetworkUtility::Session> s)
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

    asio::ip::tcp::acceptor acceptor_;
    std::shared_ptr<MessageHandler<std::shared_ptr<TCPNetworkUtility::Session>>> message_handler_;
    std::mutex user_mutex;
    std::unordered_map<std::string, std::shared_ptr<TCPNetworkUtility::Session> > connected_users_;
    std::function<void(std::shared_ptr<TCPNetworkUtility::Session>)> connected_callback_;
    std::function<void(std::shared_ptr<TCPNetworkUtility::Session>)> close_callback_;
};

class UDPPort : public Port
{
public:
    UDPPort(asio::io_context &io_context, unsigned short port_number,
            std::shared_ptr<MessageFraming> framing)
        : Port(io_context, port_number, Protocol::UDP, std::move(framing)),
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

    void setMessageHandler(const std::shared_ptr<UDPMessageHandler> &handler)
    {
        message_handler_ = handler;
    }

    void setConnectedCallback(const std::function<void(std::shared_ptr<UDPNetworkUtility::Connection>)> &callback)
    {
        connected_callback_ = callback;
    }

    void setCloseCallback(const std::function<void(std::shared_ptr<UDPNetworkUtility::Connection>)> &callback)
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
                    if (framing_->isCompleteMessage(*receive_buffer))
                    {
                        auto message = framing_->extractMessage(*receive_buffer);
                        if (message_handler_)
                        {
                            auto connection = std::make_shared<UDPNetworkUtility::Connection>(io_context_, framing_);
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
                                [this](const std::shared_ptr<UDPNetworkUtility::Connection> &c)
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

    std::mutex user_mutex;
    asio::ip::udp::socket socket_;
    asio::ip::udp::endpoint sender_endpoint_;
    std::shared_ptr<UDPMessageHandler> message_handler_;
    std::function<void(std::shared_ptr<UDPNetworkUtility::Connection>)> close_callback_;
    std::function<void(std::shared_ptr<UDPNetworkUtility::Connection>)> connected_callback_;
    std::unordered_map<std::string, std::shared_ptr<UDPNetworkUtility::Connection> > connected_users_;
    static constexpr std::size_t buffer_size = 8192;
};
