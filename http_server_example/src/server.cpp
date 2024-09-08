//
// Created by maxim on 07.09.2024.
//
// HTTPServer.h
#pragma once

#include "Server.h"
#include "HTTPMessageFraming.h"
#include "HttpMessageHandler.h"
#include "Config.h"
#include <unordered_map>
#include <functional>
#include <sstream>

class HttpServer {
public:
    using RequestHandler = std::function<void(const std::string&, const std::unordered_map<std::string, std::string>&, const std::string&, std::string&, std::unordered_map<std::string, std::string>&)>;

    explicit HttpServer(const Config& config, unsigned short port, unsigned short ssl_port)
        : thread_pool_(std::make_shared<AsioThreadPool>(1)),
          server_(thread_pool_, config) {

        auto tcp_handler = std::make_shared<HttpMessageHandler>();

        tcp_handler->registerHandler(0, [this](const std::shared_ptr<TCPNetworkUtility::Session<HttpMessageFraming, HttpMessageFraming>>& session, const ByteVector& data) {
            handleHTTPRequest(session, data);
        });

        server_.addTcpPort<HttpMessageFraming,HttpMessageFraming>(port,
            [](std::shared_ptr<TCPNetworkUtility::Session<HttpMessageFraming,HttpMessageFraming>> session) {
                std::cout << "New HTTP connection: " << session->getSessionUuid() << std::endl;
            },
            tcp_handler,
            [](std::shared_ptr<TCPNetworkUtility::Session<HttpMessageFraming,HttpMessageFraming>> session) {
                std::cout << "HTTP connection closed: " << session->getSessionUuid() << std::endl;
            }, {}, {}
        );
        auto ssl_handler = std::make_shared<SSLHttpMessageHandler<HttpMessageFraming, HttpMessageFraming>>();
        server_.addSslTcpPort<HttpMessageFraming,HttpMessageFraming>(ssl_port,
            [](std::shared_ptr<SSLNetworkUtility::Session<HttpMessageFraming,HttpMessageFraming>> session) {
                std::cout << "New HTTP connection: " << session->getSessionUuid() << std::endl;
            },
            ssl_handler,
            [](std::shared_ptr<SSLNetworkUtility::Session<HttpMessageFraming,HttpMessageFraming>> session) {
                std::cout << "HTTP connection closed: " << session->getSessionUuid() << std::endl;
            }, {}, {}
        );
    }

    void start() {
        server_.start();
    }

    void stop() {
        server_.stop();
    }

    void addRoute(const std::string& path, RequestHandler handler) {
        routes_[path] = std::move(handler);
    }

private:
    void handleHTTPRequest(const std::shared_ptr<TCPNetworkUtility::Session<HttpMessageFraming,HttpMessageFraming>>& session, const ByteVector& data) {

        std::string method = session->getReceiveFraming().getRequestMethod();
        std::string path = session->getReceiveFraming().getRequestPath();
        std::string http_version = session->getReceiveFraming().getHttpVersion();

        std::unordered_map<std::string, std::string> headers;

        std::string body;
        if (static_cast<int>(data.size()) > 0) {
            body = std::string(data.begin(), data.end());
        }

        std::string response;
        std::unordered_map<std::string, std::string> response_headers;

        auto route_handler = routes_.find(path);
        if (route_handler != routes_.end()) {
            route_handler->second(method, headers, body, response, response_headers);
        } else {
            response = "404 Not Found";
            response_headers["Content-Type"] = "text/plain";
        }
        session->getSendFraming().setMessageType(HttpMessageFraming::MessageType::RESPONSE);

        // Set headers for framing
        session->getSendFraming().setHeaders(response_headers);


        session->write(ByteVector(response.begin(), response.end()));
    }

    std::shared_ptr<AsioThreadPool> thread_pool_;
    Server server_;
    std::unordered_map<std::string, RequestHandler> routes_;
};


#include <iostream>

int main() {
    Config config;
    // Load configuration if needed
    // config.load("http_server_config.json");

    HttpServer server(config, 8080, 8443);

    server.addRoute("/", [](const std::string& method, const std::unordered_map<std::string, std::string>& headers, const std::string& body, std::string& response, std::unordered_map<std::string, std::string>& response_headers) {
        response = "<html><body><h1>Welcome to the HTTP Server</h1></body></html>";
        response_headers["Content-Type"] = "text/html";
        response_headers["Content-Length"] = std::to_string(static_cast<int>(response.size()));
    });

    server.addRoute("/echo", [](const std::string& method, const std::unordered_map<std::string, std::string>& headers, const std::string& body, std::string& response, std::unordered_map<std::string, std::string>& response_headers) {
        response = body;
        response_headers["Content-Type"] = "text/plain";
        response_headers["Content-Length"] = std::to_string(static_cast<int>(response.size()));
    });

    server.start();

    std::cout << "HTTP server started on port 8080. Press Enter to exit." << std::endl;
    std::cin.get();

    server.stop();
    return 0;
}