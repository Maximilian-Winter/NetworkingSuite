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
          server_(thread_pool_, config) {
        const std::shared_ptr<TCPMessageHandler<MagicNumberFraming, MagicNumberFraming>> tcp_handler = std::make_shared<TCPMessageHandler<MagicNumberFraming, MagicNumberFraming>>();
        const std::shared_ptr<UDPMessageHandler<MagicNumberFraming, MagicNumberFraming>> udp_handler = std::make_shared<UDPMessageHandler<MagicNumberFraming, MagicNumberFraming>>();

        tcp_handler->registerHandler(0, [this](const std::shared_ptr<TCPNetworkUtility::Session<MagicNumberFraming, MagicNumberFraming>>& session, const ByteVector& data) {
            handleEcho(session, data);
        });

        udp_handler->registerHandler(0, [this](const std::shared_ptr<UDPNetworkUtility::Connection<MagicNumberFraming, MagicNumberFraming>>& connection, const ByteVector& data) {
            handleEcho(connection, data);
        });

        server_.addTCPPort<MagicNumberFraming, MagicNumberFraming>(8080,
            [](std::shared_ptr<TCPNetworkUtility::Session<MagicNumberFraming, MagicNumberFraming>> session) {
                std::cout << "New TCP connection: " << session->getSessionUuid() << std::endl;
            },
            tcp_handler,
            [](std::shared_ptr<TCPNetworkUtility::Session<MagicNumberFraming, MagicNumberFraming>> session) {
                std::cout << "TCP connection closed: " << session->getSessionUuid() << std::endl;
            }
        );

        server_.addUDPPort<MagicNumberFraming, MagicNumberFraming>(8081,
            [](std::shared_ptr<UDPNetworkUtility::Connection<MagicNumberFraming, MagicNumberFraming>> connection) {
                std::cout << "New UDP connection: " << connection->getConnectionUuid() << std::endl;
            },
            udp_handler,
            [](std::shared_ptr<UDPNetworkUtility::Connection<MagicNumberFraming, MagicNumberFraming>> connection) {
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

    void handleEcho(const std::shared_ptr<TCPNetworkUtility::Session<MagicNumberFraming, MagicNumberFraming>>& endpoint, const ByteVector& data) {
        NetworkMessages::BinaryMessage<NetworkMessages::ChatMessage> binary_message(0, NetworkMessages::ChatMessage());
        size_t offset = 0;
        binary_message.deserialize(data, offset);
        std::cout << "Received Message from " << binary_message.getPayload().Sender << ": " <<binary_message.getPayload().Message << std::endl;
        endpoint->write(data);  // Echo back the received data
    }
    void handleEcho(const std::shared_ptr<UDPNetworkUtility::Connection<MagicNumberFraming, MagicNumberFraming>>& endpoint, const ByteVector& data) {
        NetworkMessages::BinaryMessage<NetworkMessages::ChatMessage> binary_message(0, NetworkMessages::ChatMessage());
        size_t offset = 0;
        binary_message.deserialize(data, offset);
        std::cout << "Received Message from " << binary_message.getPayload().Sender << ": " <<binary_message.getPayload().Message << std::endl;
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