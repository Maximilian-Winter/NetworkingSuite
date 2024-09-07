//
// Created by maxim on 07.09.2024.
//
// EchoServer.cpp
#include "Server.h"
#include "Config.h"
#include "AsioThreadPool.h"
#include "MessageFraming.h"
#include <iostream>
#include <csignal>

std::atomic<bool> running(true);

void signal_handler(int signal) {
    std::cout << "Caught signal " << signal << ". Shutting down..." << std::endl;
    running = false;
}

int main() {
    signal(SIGINT, signal_handler);

    Config config;
    if (!config.load("server_config.json")) {
        std::cerr << "Failed to load configuration." << std::endl;
        return 1;
    }

    auto thread_pool = std::make_shared<AsioThreadPool>(1);
    auto framing = std::make_shared<MagicNumberFraming>(0x12345678, 0x87654321);

    Server server(thread_pool, framing, config);

    server.addTCPPort(8080,
        [](const std::shared_ptr<TCPNetworkUtility::Session>& session, const ByteVector& data) {
            std::cout << "Received TCP message: " << std::string(data.begin(), data.end()) << std::endl;
            session->write(data);  // Echo back the received data
        },
        [](const std::shared_ptr<TCPNetworkUtility::Session>& session) {
            std::cout << "TCP session closed." << std::endl;
        }
    );

    server.addUDPPort(8081,
        [](const std::shared_ptr<UDPNetworkUtility::Connection>& connection, const ByteVector& data) {
            std::cout << "Received UDP message: " << std::string(data.begin(), data.end()) << std::endl;
            connection->send(data);  // Echo back the received data
        },
        [](const std::shared_ptr<UDPNetworkUtility::Connection>& connection) {
            std::cout << "UDP connection closed." << std::endl;
        }
    );

    server.start();

    std::cout << "Echo server started. Press Ctrl+C to stop." << std::endl;

    while (running) {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }

    std::cout << "Stopping server..." << std::endl;
    server.stop();

    return 0;
}