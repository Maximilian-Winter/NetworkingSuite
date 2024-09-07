//
// Created by maxim on 07.09.2024.
//
// EchoClient.cpp
#include "Client.h"
#include "Config.h"
#include "AsioThreadPool.h"
#include "MessageFraming.h"
#include <iostream>
#include <thread>

int main() {
    Config config;
    if (!config.load("client_config.json")) {
        std::cerr << "Failed to load configuration." << std::endl;
        return 1;
    }

    auto thread_pool = std::make_shared<AsioThreadPool>(1);
    auto framing = std::make_shared<MagicNumberFraming>(0x12345678, 0x87654321);

    Client client(thread_pool, framing, config);

    std::shared_ptr<TCPNetworkUtility::Session> tcp_session;
    std::shared_ptr<UDPNetworkUtility::Connection> udp_connection;

    // Connect to TCP server
    client.connectTCP("127.0.0.1", "8080",
        [](const std::shared_ptr<TCPNetworkUtility::Session>& session, const ByteVector& data) {
            std::cout << "Received TCP response: " << std::string(data.begin(), data.end()) << std::endl;
        },
        [](const std::shared_ptr<TCPNetworkUtility::Session>& session) {
            std::cout << "TCP connection closed." << std::endl;
        },
        [&tcp_session](std::error_code ec, std::shared_ptr<TCPNetworkUtility::Session> session) {
            if (!ec) {
                std::cout << "Connected to TCP server." << std::endl;
                tcp_session = session;
            } else {
                std::cerr << "Failed to connect to TCP server: " << ec.message() << std::endl;
            }
        }
    );

    // Connect to UDP server
    client.connectUDP("127.0.0.1", "8081",
        [](const std::shared_ptr<UDPNetworkUtility::Connection>& connection, const ByteVector& data) {
            std::cout << "Received UDP response: " << std::string(data.begin(), data.end()) << std::endl;
        },
        [](const std::shared_ptr<UDPNetworkUtility::Connection>& connection) {
            std::cout << "UDP connection closed." << std::endl;
        },
        [&udp_connection](std::error_code ec, std::shared_ptr<UDPNetworkUtility::Connection> connection) {
            if (!ec) {
                std::cout << "Connected to UDP server." << std::endl;
                udp_connection = std::move(connection);
            } else {
                std::cerr << "Failed to connect to UDP server: " << ec.message() << std::endl;
            }
        }
    );

    client.start();

    // Wait a bit for connections to establish
    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    std::string input;
    while (true) {
        std::cout << "Enter a message (or 'quit' to exit): ";
        std::getline(std::cin, input);

        if (input == "quit") {
            break;
        }

        ByteVector message(input.begin(), input.end());

        if (tcp_session) {
            tcp_session->write(message);
        } else {
            std::cout << "TCP session not established." << std::endl;
        }

        if (udp_connection) {
            udp_connection->send(message);
        } else {
            std::cout << "UDP connection not established." << std::endl;
        }
    }

    std::cout << "Stopping client..." << std::endl;
    client.stop();

    return 0;
}