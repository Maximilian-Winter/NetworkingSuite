// HTTPClient.h
#pragma once
#include "Client.h"
#include "HTTPMessageFraming.h"
#include "HttpMessageHandler.h"
#include "Config.h"
#include <future>
#include <sstream>

class HTTPClient {
public:
    struct HTTPResponse {
        int status_code;
        std::unordered_map<std::string, std::string> headers;
        std::string body;
    };

    HTTPClient(const Config& config)
        : thread_pool_(std::make_shared<AsioThreadPool>(1)),
          framing_(std::make_shared<HTTPMessageFraming>(HTTPMessageFraming::MessageType::REQUEST)),
          client_(thread_pool_, framing_, config) {

        tcp_handler_ = std::make_shared<HTTPMessageHandler>();

        tcp_handler_->registerHandler(0, [this](const std::shared_ptr<TCPNetworkUtility::Session>& session, const ByteVector& data) {
            handleHTTPResponse(session, data);
        });

        client_.start();
    }

    ~HTTPClient() {
        client_.stop();
    }

    std::future<HTTPResponse> sendRequest(const std::string& method, const std::string& host, unsigned short port, const std::string& path, const std::unordered_map<std::string, std::string>& headers, const std::string& body = "") {
        auto promise = std::make_shared<std::promise<HTTPResponse>>();
        auto future = promise->get_future();

        client_.connectTCP(host, std::to_string(port),
            [this, method, host, path, headers, body, promise](std::error_code ec, std::shared_ptr<TCPNetworkUtility::Session> session) {
                if (!ec) {
                    std::cout << "Connected to HTTP server" << std::endl;
                    sendHTTPRequest(session, method, host, path, headers, body, promise);
                } else {
                    std::cerr << "Failed to connect to HTTP server: " << ec.message() << std::endl;
                    promise->set_exception(std::make_exception_ptr(std::runtime_error("Connection failed")));
                }
            },
            tcp_handler_,
            [](std::shared_ptr<TCPNetworkUtility::Session> session) {
                std::cout << "HTTP connection closed" << std::endl;
            }
        );

        return future;
    }

private:
    void sendHTTPRequest(const std::shared_ptr<TCPNetworkUtility::Session>& session, const std::string& method, const std::string& host, const std::string& path, const std::unordered_map<std::string, std::string>& headers, const std::string& body, std::shared_ptr<std::promise<HTTPResponse>> promise) {
        std::dynamic_pointer_cast<HTTPMessageFraming>(framing_)->setMessageType(HTTPMessageFraming::MessageType::REQUEST);
        std::dynamic_pointer_cast<HTTPMessageFraming>(framing_)->setRequestMethod(method);
        std::dynamic_pointer_cast<HTTPMessageFraming>(framing_)->setContentType("plain/text");
        std::dynamic_pointer_cast<HTTPMessageFraming>(framing_)->setRequestPath(path);

        std::unordered_map<std::string, std::string> all_headers = headers;
        all_headers["Content-Length"] = std::to_string(body.length());
        std::dynamic_pointer_cast<HTTPMessageFraming>(framing_)->setHeaders(all_headers);

        session->write(ByteVector(body.begin(), body.end()));

        pending_responses_[session->getSessionUuid()] = promise;
    }

    void handleHTTPResponse(const std::shared_ptr<TCPNetworkUtility::Session>& session, const ByteVector& data) {
        ByteVector last_message = std::dynamic_pointer_cast<HTTPMessageFraming>(framing_)->getFullLastMessage();
        std::string response(last_message.begin(), last_message.end());
        std::istringstream response_stream(response);

        HTTPResponse http_response;
        std::string http_version, status_code, status_message;
        response_stream >> http_version >> status_code;
        std::getline(response_stream, status_message);
        http_response.status_code = std::stoi(status_code);

        std::string line;
        while (std::getline(response_stream, line) && line != "\r") {
            auto colon_pos = line.find(':');
            if (colon_pos != std::string::npos) {
                auto key = line.substr(0, colon_pos);
                auto value = line.substr(colon_pos + 2, line.length() - (colon_pos + 2) - 1);  // -3 to remove \r
                http_response.headers[key] = value;
            }
        }

        http_response.body = std::string(data.begin(), data.end());

        auto promise_it = pending_responses_.find(session->getSessionUuid());
        if (promise_it != pending_responses_.end()) {
            promise_it->second->set_value(http_response);
            pending_responses_.erase(promise_it);
        }

        session->close();
    }

    std::shared_ptr<AsioThreadPool> thread_pool_;
    std::shared_ptr<HTTPMessageFraming> framing_;
    Client client_;
    std::shared_ptr<HTTPMessageHandler> tcp_handler_;
    std::unordered_map<std::string, std::shared_ptr<std::promise<HTTPResponse>>> pending_responses_;
};

#include <iostream>

int main() {
    Config config;
    // Load configuration if needed
    // config.load("http_client_config.json");

    HTTPClient client(config);

    // GET request
    auto get_future = client.sendRequest("GET", "localhost", 8080, "/", {});
    auto get_response = get_future.get();
    std::cout << "GET response:\nStatus: " << get_response.status_code << "\nBody: " << get_response.body << std::endl;

    // POST request
    std::unordered_map<std::string, std::string> post_headers = {{"Content-Type", "text/plain"}};
    auto post_future = client.sendRequest("POST", "localhost", 8080, "/echo", post_headers, "Hello, HTTP Server!");
    auto post_response = post_future.get();
    std::cout << "POST response:\nStatus: " << post_response.status_code << "\nBody: " << post_response.body << std::endl;

    return 0;
}