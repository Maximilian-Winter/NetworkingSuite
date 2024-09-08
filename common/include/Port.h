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
class TCPPort : public Port
{
public:
    TCPPort(asio::io_context &io_context, unsigned short port_number)
        : Port(io_context, port_number, Protocol::TCP),
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
                    auto session = TCPNetworkUtility::createSession<SendFraming, ReceiveFraming>(io_context_, socket);
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
                                close_callback_(std::move(s));
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
    std::shared_ptr<TCPMessageHandler<SendFraming, ReceiveFraming>> message_handler_;
    std::mutex user_mutex;
    std::unordered_map<std::string, std::shared_ptr<TCPNetworkUtility::Session<SendFraming, ReceiveFraming>> > connected_users_;
    std::function<void(std::shared_ptr<TCPNetworkUtility::Session<SendFraming, ReceiveFraming>>)> connected_callback_;
    std::function<void(std::shared_ptr<TCPNetworkUtility::Session<SendFraming, ReceiveFraming>>)> close_callback_;
};

template<typename SendFraming, typename ReceiveFraming>
class UDPPort : public Port
{
public:
    UDPPort(asio::io_context &io_context, unsigned short port_number)
        : Port(io_context, port_number, Protocol::UDP),
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
                    ReceiveFraming framing_;
                    if (framing_->isCompleteMessage(*receive_buffer))
                    {
                        auto message = framing_->extractMessage(*receive_buffer);
                        if (message_handler_)
                        {
                            auto connection = std::make_shared<UDPNetworkUtility::Connection<SendFraming, ReceiveFraming>>(io_context_, framing_);
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

    std::mutex user_mutex;
    asio::ip::udp::socket socket_;
    asio::ip::udp::endpoint sender_endpoint_;
    std::shared_ptr<UDPMessageHandler<SendFraming, ReceiveFraming>> message_handler_;
    std::function<void(std::shared_ptr<UDPNetworkUtility::Connection<SendFraming, ReceiveFraming>>)> close_callback_;
    std::function<void(std::shared_ptr<UDPNetworkUtility::Connection<SendFraming, ReceiveFraming>>)> connected_callback_;
    std::unordered_map<std::string, std::shared_ptr<UDPNetworkUtility::Connection<SendFraming, ReceiveFraming>> > connected_users_;
    static constexpr std::size_t buffer_size = 8192;
};
