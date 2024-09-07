//
// Created by maxim on 07.09.2024.
//
// EchoClient.cpp
#include "Client.h"
#include "MessageFraming.h"
#include "MessageHandler.h"
#include "Config.h"
#include <iostream>
#include <thread>
#include <chrono>

class EchoClient {
public:
    explicit EchoClient(const Config& config)
        : thread_pool_(std::make_shared<AsioThreadPool>()),
          framing_(std::make_shared<MagicNumberFraming>(0x12345678, 0x87654321)),
          client_(thread_pool_, framing_, config) {

        tcp_handler_ = std::make_shared<TCPMessageHandler>();
        udp_handler_ = std::make_shared<UDPMessageHandler>();

        tcp_handler_->registerHandler(1, [this](const std::shared_ptr<TCPNetworkUtility::Session>& session, const ByteVector& data) {
            handleEchoResponse(data);
        });

        udp_handler_->registerHandler(1, [this](const std::shared_ptr<UDPNetworkUtility::Connection>& connection, const ByteVector& data) {
            handleEchoResponse(data);
        });
    }

    void start() {
        client_.start();

        connectTCP();
        connectUDP();

        std::thread input_thread([this] { handleUserInput(); });
        input_thread.detach();
    }

    void stop() {
        client_.stop();
    }

private:
    void connectTCP() {
        client_.connectTCP("localhost", "8080",
            [this](std::error_code ec, std::shared_ptr<TCPNetworkUtility::Session> session) {
                if (!ec) {
                    std::cout << "Connected to TCP server" << std::endl;
                    tcp_session_ = session;
                } else {
                    std::cerr << "Failed to connect to TCP server: " << ec.message() << std::endl;
                }
            },
            tcp_handler_,
            [](std::shared_ptr<TCPNetworkUtility::Session> session) {
                std::cout << "TCP connection closed" << std::endl;
            }
        );
    }

    void connectUDP() {
        client_.connectUDP("localhost", "8081",
            [this](std::error_code ec, std::shared_ptr<UDPNetworkUtility::Connection> connection) {
                if (!ec) {
                    std::cout << "Connected to UDP server" << std::endl;
                    udp_connection_ = connection;
                } else {
                    std::cerr << "Failed to connect to UDP server: " << ec.message() << std::endl;
                }
            },
            udp_handler_,
            [](std::shared_ptr<UDPNetworkUtility::Connection> connection) {
                std::cout << "UDP connection closed" << std::endl;
            }
        );
    }

    void handleUserInput() {
        while (true) {
            std::string input;
            std::cout << "Enter message (or 'quit' to exit): ";
            std::getline(std::cin, input);

            if (input == "quit") {
                stop();
                break;
            }

            sendMessage(input);
        }
    }

    void sendMessage(const std::string& message) {
        ByteVector data(message.begin(), message.end());
        NetworkMessages::BinaryMessage<NetworkMessages::MessageTypeData> binary_message(1, NetworkMessages::MessageTypeData());
        auto serialized = binary_message.serialize();
        serialized.insert(serialized.end(), data.begin(), data.end());

        if (tcp_session_) {
            tcp_session_->write(serialized);
        }

        if (udp_connection_) {
            udp_connection_->send(serialized);
        }
    }

    void handleEchoResponse(const ByteVector& data) {
        std::cout << "Received echo: " << std::string(data.begin(), data.end()) << std::endl;
    }

    std::shared_ptr<AsioThreadPool> thread_pool_;
    std::shared_ptr<MessageFraming> framing_;
    Client client_;
    std::shared_ptr<TCPMessageHandler> tcp_handler_;
    std::shared_ptr<UDPMessageHandler> udp_handler_;
    std::shared_ptr<TCPNetworkUtility::Session> tcp_session_;
    std::shared_ptr<UDPNetworkUtility::Connection> udp_connection_;
};

int main() {
    Config config;
    // Load configuration if needed
    // config.load("client_config.json");

    EchoClient client(config);
    client.start();

    std::cout << "Echo client started. Enter messages to send." << std::endl;
    std::cin.get();  // Wait for Enter to exit

    client.stop();
    return 0;
}