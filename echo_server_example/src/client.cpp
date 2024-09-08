#include "Client.h"
#include "MessageFraming.h"
#include "MessageHandler.h"
#include "Config.h"
#include <iostream>
#include <thread>
#include <chrono>
#include <atomic>

class EchoClient {
public:
    EchoClient(const Config& config)
        : thread_pool_(std::make_shared<AsioThreadPool>()),
          framing_(std::make_shared<MagicNumberFraming>(0x12345678, 0x87654321)),
          client_(thread_pool_, framing_, config),
          running_(true) {

        tcp_handler_ = std::make_shared<TCPMessageHandler>();
        udp_handler_ = std::make_shared<UDPMessageHandler>();

        tcp_handler_->registerHandler(0, [this](const std::shared_ptr<TCPNetworkUtility::Session>& session, const ByteVector& data) {
            NetworkMessages::BinaryMessage<NetworkMessages::ChatMessage> binary_message(0, NetworkMessages::ChatMessage());
            size_t offset = 0;
            binary_message.deserialize(data, offset);
            handleEchoResponse(binary_message.getPayload());
        });

        udp_handler_->registerHandler(0, [this](const std::shared_ptr<UDPNetworkUtility::Connection>& connection, const ByteVector& data) {
            NetworkMessages::BinaryMessage<NetworkMessages::ChatMessage> binary_message(0, NetworkMessages::ChatMessage());
            size_t offset = 0;
            binary_message.deserialize(data, offset);
            handleEchoResponse(binary_message.getPayload());
        });
    }

    void start() {
        client_.start();

        connectTCP();
        connectUDP();

        std::thread input_thread([this] { handleUserInput(); });
        input_thread.join(); // Wait for the input thread to finish
    }

    void stop() {
        running_ = false;
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
        while (running_) {
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
        NetworkMessages::BinaryMessage<NetworkMessages::ChatMessage> binary_message(0, NetworkMessages::ChatMessage("MadWizard", message));
        auto serialized = binary_message.serialize();

        if (tcp_session_) {
            tcp_session_->write(serialized);
        }

        if (udp_connection_) {
            udp_connection_->send(serialized);
        }
    }

    void handleEchoResponse(const NetworkMessages::ChatMessage& data) {
        std::cout << "Received echo: " << data.Message << std::endl;
    }

    std::shared_ptr<AsioThreadPool> thread_pool_;
    std::shared_ptr<MessageFraming> framing_;
    Client client_;
    std::shared_ptr<TCPMessageHandler> tcp_handler_;
    std::shared_ptr<UDPMessageHandler> udp_handler_;
    std::shared_ptr<TCPNetworkUtility::Session> tcp_session_;
    std::shared_ptr<UDPNetworkUtility::Connection> udp_connection_;
    std::atomic<bool> running_;
};

int main() {
    Config config;
    // Load configuration if needed
    // config.load("client_config.json");

    EchoClient client(config);
    client.start();

    return 0;
}