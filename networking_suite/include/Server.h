//
// Created by maxim on 07.09.2024.
//

#pragma once

#include <utility>
#include <vector>
#include <memory>
#include "AsioThreadPool.h"
#include "Config.h"
#include "Port.h"


class Server {
public:
    Server(std::shared_ptr<AsioThreadPool> thread_pool, Config  config)
        : thread_pool_(std::move(thread_pool)), config_(std::move(config))
    {
        //auto port = config_.get<short>("port", 8080);
        std::string defaultLevel = "INFO";
        auto log_level = config_.get<std::string>("log_level", "INFO");
        auto log_file = config_.get<std::string>("log_file", "client.log");
        auto log_file_size_in_mb = config_.get<float>("max_log_file_size_in_mb", 1.0f);
        AsyncLogger& logger = AsyncLogger::getInstance();
        logger.setLogLevel(AsyncLogger::parseLogLevel(log_level));
        logger.addDestination(std::make_shared<AsyncLogger::ConsoleDestination>());
        logger.addDestination(std::make_shared<AsyncLogger::FileDestination>(log_file, log_file_size_in_mb * (1024 * 1024)));
    }
    template< typename SenderFramingType, typename ReceiverFramingType>
    void addTcpPort(unsigned short port_number, SessionContext<NetworkSession<SenderFramingType, ReceiverFramingType>, SenderFramingType, ReceiverFramingType> &connection_context) {
        auto tcp_port = std::make_shared<TcpPort<SenderFramingType, ReceiverFramingType>>(thread_pool_->get_io_context(), port_number, connection_context);
        ports_.push_back(tcp_port);
    }

    template< typename SenderFramingType, typename ReceiverFramingType>
    void addSslTcpPort(unsigned short port_number, const std::string& ssl_cert_file, const std::string& ssl_key_file, const std::string& ssl_dh_file, SessionContext<NetworkSession<SenderFramingType, ReceiverFramingType>, SenderFramingType, ReceiverFramingType>& connection_context) {
        ssl_contexts_.emplace_back(std::make_shared<asio::ssl::context>(asio::ssl::context::sslv23));
        ssl_contexts_.back()->set_options(
                          asio::ssl::context::default_workarounds
                          | asio::ssl::context::no_sslv2
                          | asio::ssl::context::single_dh_use);
        ssl_contexts_.back()->use_certificate_chain_file(ssl_cert_file);
        ssl_contexts_.back()->use_private_key_file(ssl_key_file, asio::ssl::context::pem);
        ssl_contexts_.back()->use_tmp_dh_file(ssl_dh_file);
        auto tcp_port = std::make_shared<TcpPort<SenderFramingType, ReceiverFramingType>>(thread_pool_->get_io_context(), port_number, connection_context, ssl_contexts_.back().get());
        ports_.push_back(tcp_port);
    }

    template< typename SenderFramingType, typename ReceiverFramingType>
    void addUdpPort(unsigned short port_number, SessionContext<NetworkSession<SenderFramingType, ReceiverFramingType>, SenderFramingType, ReceiverFramingType>& connection_context) {
        auto udp_port = std::make_shared<UdpPort<SenderFramingType, ReceiverFramingType>>(thread_pool_->get_io_context(), port_number,connection_context);
        ports_.push_back(udp_port);
    }

    void start() {
        for (auto& port : ports_) {
            port->start();
        }
        thread_pool_->start_threads();
    }

    void stop() {
        for (auto& port : ports_) {
            port->stop();
        }
        thread_pool_->stop();
    }

private:

    std::vector<std::shared_ptr<asio::ssl::context>> ssl_contexts_;
    std::shared_ptr<AsioThreadPool> thread_pool_;
    std::vector<std::shared_ptr<Port>> ports_;
    Config config_;
};
