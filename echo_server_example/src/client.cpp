#include "Client.h"
#include "TCPMessageFraming.h"
#include "UDPMessageFraming.h"
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
          client_(thread_pool_, config),
          running_(true) {

        tcp_handler_ = std::make_shared<TCPMessageHandler<TCPMagicNumberFraming, TCPMagicNumberFraming>>();
        udp_handler_ = std::make_shared<UDPMessageHandler<UDPMagicNumberFraming, UDPMagicNumberFraming>>();

        tcp_handler_->registerHandler([this](const std::shared_ptr<TCPNetworkUtility::Session<TCPMagicNumberFraming, TCPMagicNumberFraming>>& session, const ByteVector& data) {
            NetworkMessages::BinaryMessage<NetworkMessages::ChatMessage> binary_message(0, NetworkMessages::ChatMessage());
            size_t offset = 0;
            binary_message.deserialize(data, offset);
            handleEchoResponse(binary_message.getPayload());
        });

        udp_handler_->registerHandler([this](const std::shared_ptr<UDPNetworkUtility::Session<UDPMagicNumberFraming, UDPMagicNumberFraming>>& connection, const ByteVector& data) {
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
        json framingInitialData ={};
        framingInitialData["magic_number_start"] = 42;
        framingInitialData["magic_number_end"] = 24;
        client_.connectTCP<TCPMagicNumberFraming, TCPMagicNumberFraming>("localhost", "8080",
            [this](std::error_code ec, std::shared_ptr<TCPNetworkUtility::Session<TCPMagicNumberFraming, TCPMagicNumberFraming>> session) {
                if (!ec) {
                    std::cout << "Connected to TCP server" << std::endl;
                    tcp_session_ = session;
                } else {
                    std::cerr << "Failed to connect to TCP server: " << ec.message() << std::endl;
                }
            },
            tcp_handler_,
            [](std::shared_ptr<TCPNetworkUtility::Session<TCPMagicNumberFraming, TCPMagicNumberFraming>> session) {
                std::cout << "TCP connection closed" << std::endl;
            }, framingInitialData, framingInitialData
        );
    }

    void connectUDP() {
        json framingInitialData ={};
        framingInitialData["magic_number_start"] = 42;
        framingInitialData["magic_number_end"] = 24;
        client_.connectUDP<UDPMagicNumberFraming, UDPMagicNumberFraming>("localhost", "8081",
            [this](std::error_code ec, std::shared_ptr<UDPNetworkUtility::Session<UDPMagicNumberFraming, UDPMagicNumberFraming>> connection) {
                if (!ec) {
                    std::cout << "Connected to UDP server" << std::endl;
                    udp_connection_ = connection;
                } else {
                    std::cerr << "Failed to connect to UDP server: " << ec.message() << std::endl;
                }
            },
            udp_handler_,
            [](std::shared_ptr<UDPNetworkUtility::Session<UDPMagicNumberFraming, UDPMagicNumberFraming>> connection) {
                std::cout << "UDP connection closed" << std::endl;
            }, framingInitialData, framingInitialData
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
    Client client_;
    std::shared_ptr<TCPMessageHandler<TCPMagicNumberFraming, TCPMagicNumberFraming>> tcp_handler_;
    std::shared_ptr<UDPMessageHandler<UDPMagicNumberFraming, UDPMagicNumberFraming>> udp_handler_;
    std::shared_ptr<TCPNetworkUtility::Session<TCPMagicNumberFraming, TCPMagicNumberFraming>> tcp_session_;
    std::shared_ptr<UDPNetworkUtility::Session<UDPMagicNumberFraming, UDPMagicNumberFraming>> udp_connection_;
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