//
// Created by maxim on 07.09.2024.
//

#pragma once

#include <memory>
#include <functional>
#include <MessageHandler.h>

#include "AsioThreadPool.h"
#include "TCPNetworkUtility.h"
#include "UDPNetworkUtility.h"
#include "Config.h"

class Client {
public:
    Client(std::shared_ptr<AsioThreadPool> thread_pool, std::shared_ptr<MessageFraming> framing, const Config& config)
        : thread_pool_(std::move(thread_pool)), framing_(std::move(framing)), config_(config)
    {

        //auto port = config_.get<short>("port", 8080);
        std::string defaultLevel = "DEBUG";
        auto log_level = config_.get<std::string>("log_level", "INFO");
        auto log_file = config_.get<std::string>("log_file", "client.log");
        auto log_file_size_in_mb = config_.get<float>("max_log_file_size_in_mb", 1.0f);
        AsyncLogger& logger = AsyncLogger::getInstance();
        logger.setLogLevel(AsyncLogger::parseLogLevel(log_level));
        logger.addDestination(std::make_shared<AsyncLogger::ConsoleDestination>());
        logger.addDestination(std::make_shared<AsyncLogger::FileDestination>(log_file, log_file_size_in_mb * (1024 * 1024)));
    }

    void connectTCP(const std::string& host, const std::string& port,
                const std::function<void(std::error_code, std::shared_ptr<TCPNetworkUtility::Session>)>& connect_callback,
                    const std::shared_ptr<TCPMessageHandler>& message_handler,
                    const std::function<void(std::shared_ptr<TCPNetworkUtility::Session>)>& close_callback) {

        auto messageHandling = [message_handler](std::shared_ptr<TCPNetworkUtility::Session> session, ByteVector message)
        {
            message_handler->handleMessage(session, message);
        };
        TCPNetworkUtility::connect(
            thread_pool_->get_io_context(), host, port, framing_,
            connect_callback,
            messageHandling,
            close_callback
        );
    }

    void connectUDP(const std::string& host, const std::string& port,
                    const std::function<void(std::error_code, std::shared_ptr<UDPNetworkUtility::Connection>)>& connect_callback,
                    const std::shared_ptr<UDPMessageHandler>& message_handler,
                    const std::function<void(std::shared_ptr<UDPNetworkUtility::Connection>)>& close_callback) {
        auto messageHandling = [message_handler](std::shared_ptr<UDPNetworkUtility::Connection> connection, ByteVector message)
        {
            message_handler->handleMessage(connection, message);
        };
        UDPNetworkUtility::connect(
            thread_pool_->get_io_context(), host, port, framing_,
            connect_callback,
            messageHandling,
            close_callback
        );
    }

    void start() {
        thread_pool_->start_threads();
    }

    void stop() {
        thread_pool_->stop();
    }

private:
    std::shared_ptr<AsioThreadPool> thread_pool_;
    std::shared_ptr<MessageFraming> framing_;
    Config config_;
};
