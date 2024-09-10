//
// Created by maxim on 07.09.2024.
//

#pragma once

#include <memory>
#include <functional>


#include "AsioThreadPool.h"
#include "TCPNetworkUtility.h"
#include "UDPNetworkUtility.h"
#include "Config.h"

class Client {
public:
    Client(std::shared_ptr<AsioThreadPool> thread_pool, const Config& config)
        : thread_pool_(std::move(thread_pool)), config_(config)
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

    template<typename SendFraming, typename ReceiveFraming>
    void connectTCP(const std::string& host, const std::string& port,
                const std::function<void(std::error_code, std::shared_ptr<TCPNetworkUtility::Session<SendFraming, ReceiveFraming>>)>& connect_callback,
                    const std::shared_ptr<TCPMessageHandler<SendFraming, ReceiveFraming>> &handler,
                    const std::function<void(std::shared_ptr<TCPNetworkUtility::Session<SendFraming, ReceiveFraming>>)>& close_callback, const json senderFramingInitialData, const json receiveFramingInitialData) {

        auto messageHandling = [handler](std::shared_ptr<TCPNetworkUtility::Session<SendFraming, ReceiveFraming>> session, ByteVector message)
        {
            handler->handleMessage(session, message);
        };
        TCPNetworkUtility::connect<SendFraming, ReceiveFraming>(
            thread_pool_->get_io_context(), host, port,
            connect_callback,
            messageHandling,
            close_callback,senderFramingInitialData, receiveFramingInitialData
        );
    }

    template<typename SendFraming, typename ReceiveFraming>
    void connectUDP(const std::string& host, const std::string& port,
                    const std::function<void(std::error_code, std::shared_ptr<UDPNetworkUtility::Session<SendFraming, ReceiveFraming>>)>& connect_callback,
                    const std::shared_ptr<UDPMessageHandler<SendFraming, ReceiveFraming>>& message_handler,
                    const std::function<void(std::shared_ptr<UDPNetworkUtility::Session<SendFraming, ReceiveFraming>>)>& close_callback, json& senderFramingInitialData, json& receiveFramingInitialData) {
        auto messageHandling = [message_handler](std::shared_ptr<UDPNetworkUtility::Session<SendFraming, ReceiveFraming>> connection, ByteVector message)
        {
            message_handler->handleMessage(connection, message);
        };
        UDPNetworkUtility::connect<SendFraming, ReceiveFraming>(
            thread_pool_->get_io_context(), host, port,
            connect_callback,
            messageHandling,
            close_callback,senderFramingInitialData, receiveFramingInitialData
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
    Config config_;
};
