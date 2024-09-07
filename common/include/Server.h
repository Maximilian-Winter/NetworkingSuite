//
// Created by maxim on 07.09.2024.
//

#pragma once

#include <vector>
#include <memory>
#include "AsioThreadPool.h"
#include "MessageFraming.h"
#include "MessageHandler.h"
#include "Config.h"
#include "Port.h"

class Server {
public:
    Server(std::shared_ptr<AsioThreadPool> thread_pool, std::shared_ptr<MessageFraming> framing, const Config& config)
        : thread_pool_(std::move(thread_pool)), framing_(std::move(framing)), config_(config)
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

    void addTCPPort(unsigned short port_number, const std::function<void(std::shared_ptr<TCPNetworkUtility::Session>)> &connectedCallback, const std::shared_ptr<TCPMessageHandler> &handler, const std::function<void(std::shared_ptr<TCPNetworkUtility::Session>)>& close_callback) {
        auto tcp_port = std::make_shared<TCPPort>(thread_pool_->get_io_context(), port_number, framing_);
        tcp_port->setConnectedCallback(connectedCallback);
        tcp_port->setMessageHandler(handler);
        tcp_port->setCloseCallback(close_callback);
        ports_.push_back(tcp_port);
    }

    void addUDPPort(unsigned short port_number, const std::function<void(std::shared_ptr<UDPNetworkUtility::Connection>)> &connectedCallback, const std::shared_ptr<UDPMessageHandler>& handler, const std::function<void(std::shared_ptr<UDPNetworkUtility::Connection>)>& close_callback) {
        auto udp_port = std::make_shared<UDPPort>(thread_pool_->get_io_context(), port_number, framing_);
        udp_port->setConnectedCallback(connectedCallback);
        udp_port->setMessageHandler(handler);
        udp_port->setCloseCallback(close_callback);
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


    std::shared_ptr<AsioThreadPool> thread_pool_;
    std::shared_ptr<MessageFraming> framing_;
    std::vector<std::shared_ptr<Port>> ports_;
    Config config_;
};
