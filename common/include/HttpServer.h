//
// Created by maxim on 08.09.2024.
//

#pragma once

#include "Server.h"
#include "HttpMessageFraming.h"
#include "HttpMessageHandler.h"
#include "Config.h"
#include <unordered_map>
#include <functional>

class HttpServer {
public:
    using RequestHandler = std::function<void(const std::string&, const std::unordered_map<std::string, std::string>&, const std::string&, std::string&, std::unordered_map<std::string, std::string>&)>;

    explicit HttpServer(const std::string& config_file)
        : config_(std::make_shared<Config>()) {

        config_->load(config_file);

        unsigned int thread_count = config_->get<unsigned int>("thread_count", 4);
        thread_pool_ = std::make_shared<AsioThreadPool>(thread_count);
        server_ = std::make_unique<Server>(thread_pool_, *config_);

        setupHTTPServer();
        setupHTTPSServer();
    }

    void start() {
        server_->start();
    }

    void stop() {
        server_->stop();
    }

    void addRoute(const std::string& path, RequestHandler handler) {
        routes_[path] = std::move(handler);
    }

private:
    void setupHTTPServer() {
        auto http_port = config_->get<unsigned short>("http_port", 80);

        auto tcp_handler = std::make_shared<HttpMessageHandler>();

        tcp_handler->registerHandler(0, [this](const std::shared_ptr<TCPNetworkUtility::Session<HttpMessageFraming, HttpMessageFraming>>& session, const ByteVector& data) {
            handleHTTPRequest(session, data);
        });

        server_->addTcpPort<HttpMessageFraming,HttpMessageFraming>(http_port,
            [](std::shared_ptr<TCPNetworkUtility::Session<HttpMessageFraming,HttpMessageFraming>> session) {
                std::cout << "New HTTP connection: " << session->getSessionUuid() << std::endl;
            },
            tcp_handler,
            [](std::shared_ptr<TCPNetworkUtility::Session<HttpMessageFraming,HttpMessageFraming>> session) {
                std::cout << "HTTP connection closed: " << session->getSessionUuid() << std::endl;
            }, {}, {}
        );
    }

    void setupHTTPSServer() {
        auto https_port = config_->get<unsigned short>("https_port", 443);
        auto ssl_cert = config_->get<std::string>("ssl_cert_file", "");
        auto ssl_key = config_->get<std::string>("ssl_key_file", "");
        auto ssl_dh_file = config_->get<std::string>("ssl_dh_file", "");

        if (ssl_cert.empty() || ssl_key.empty()) {
            std::cout << "SSL configuration is incomplete. HTTPS server will not be started." << std::endl;
            return;
        }

        auto ssl_handler = std::make_shared<SSLHttpMessageHandler<HttpMessageFraming, HttpMessageFraming>>();
        ssl_handler->registerHandler(0, [this](const std::shared_ptr<SSLNetworkUtility::Session<HttpMessageFraming, HttpMessageFraming>>& session, const ByteVector& data) {
            handleHTTPSRequest(session, data);
        });

        server_->addSslTcpPort<HttpMessageFraming,HttpMessageFraming>(https_port, ssl_cert, ssl_key, ssl_dh_file,
            [](std::shared_ptr<SSLNetworkUtility::Session<HttpMessageFraming,HttpMessageFraming>> session) {
                std::cout << "New HTTPS connection: " << session->getSessionUuid() << std::endl;
            },
            ssl_handler,
            [](std::shared_ptr<SSLNetworkUtility::Session<HttpMessageFraming,HttpMessageFraming>> session) {
                std::cout << "HTTPS connection closed: " << session->getSessionUuid() << std::endl;
            }, {}, {}
        );
    }

    void handleHTTPRequest(const std::shared_ptr<TCPNetworkUtility::Session<HttpMessageFraming,HttpMessageFraming>>& session, const ByteVector& data) {
        processRequest(session, data);
    }

    void handleHTTPSRequest(const std::shared_ptr<SSLNetworkUtility::Session<HttpMessageFraming,HttpMessageFraming>>& session, const ByteVector& data) {
        processRequest(session, data);
    }

    template<typename SessionType>
    void processRequest(const std::shared_ptr<SessionType>& session, const ByteVector& data) {
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

    std::shared_ptr<Config> config_;
    std::shared_ptr<AsioThreadPool> thread_pool_;
    std::unique_ptr<Server> server_;
    std::unordered_map<std::string, RequestHandler> routes_;
};
