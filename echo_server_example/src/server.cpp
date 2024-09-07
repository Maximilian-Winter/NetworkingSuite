//
// Created by maxim on 07.09.2024.
//
// EchoServer.cpp
#include "Server.h"
#include "MessageFraming.h"
#include "MessageHandler.h"
#include "Config.h"
#include <iostream>

class EchoServer {
public:
    explicit EchoServer(const Config& config)
        : thread_pool_(std::make_shared<AsioThreadPool>()),
          framing_(std::make_shared<MagicNumberFraming>(0x12345678, 0x87654321)),
          server_(thread_pool_, framing_, config) {

        auto tcp_handler = std::make_shared<TCPMessageHandler>();
        auto udp_handler = std::make_shared<UDPMessageHandler>();

        tcp_handler->registerHandler(1, [this](const std::shared_ptr<TCPNetworkUtility::Session>& session, const ByteVector& data) {
            handleEcho(session, data);
        });

        udp_handler->registerHandler(1, [this](const std::shared_ptr<UDPNetworkUtility::Connection>& connection, const ByteVector& data) {
            handleEcho(connection, data);
        });

        server_.addTCPPort(8080,
            [](std::shared_ptr<TCPNetworkUtility::Session> session) {
                std::cout << "New TCP connection: " << session->getSessionUuid() << std::endl;
            },
            tcp_handler,
            [](std::shared_ptr<TCPNetworkUtility::Session> session) {
                std::cout << "TCP connection closed: " << session->getSessionUuid() << std::endl;
            }
        );

        server_.addUDPPort(8081,
            [](std::shared_ptr<UDPNetworkUtility::Connection> connection) {
                std::cout << "New UDP connection: " << connection->getConnectionUuid() << std::endl;
            },
            udp_handler,
            [](std::shared_ptr<UDPNetworkUtility::Connection> connection) {
                std::cout << "UDP connection closed: " << connection->getConnectionUuid() << std::endl;
            }
        );
    }

    void start() {
        server_.start();
    }

    void stop() {
        server_.stop();
    }

private:

    void handleEcho(const std::shared_ptr<TCPNetworkUtility::Session>& endpoint, const ByteVector& data) {
        std::cout << "Received: " << std::string(data.begin(), data.end()) << std::endl;
        endpoint->write(data);  // Echo back the received data
    }
    void handleEcho(const std::shared_ptr<UDPNetworkUtility::Connection>& endpoint, const ByteVector& data) {
        std::cout << "Received: " << std::string(data.begin(), data.end()) << std::endl;
        endpoint->send(data);  // Echo back the received data
    }
    std::shared_ptr<AsioThreadPool> thread_pool_;
    std::shared_ptr<MessageFraming> framing_;
    Server server_;
};

int main() {
    Config config;
    // Load configuration if needed
    // config.load("server_config.json");

    EchoServer server(config);
    server.start();

    std::cout << "Echo server started. Press Enter to exit." << std::endl;
    std::cin.get();

    server.stop();
    return 0;
}