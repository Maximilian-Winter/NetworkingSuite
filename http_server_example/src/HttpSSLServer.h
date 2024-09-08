//
// Created by maxim on 08.09.2024.
//

#pragma once

#include "Server.h"
#include "HTTPMessageFraming.h"
#include "HttpMessageHandler.h"
#include "Config.h"
#include <unordered_map>
#include <functional>
#include <sstream>

class HTTPServer {
public:
    using RequestHandler = std::function<void(const std::string&, const std::unordered_map<std::string, std::string>&, const std::string&, std::string&, std::unordered_map<std::string, std::string>&)>;

    explicit HTTPServer(const Config& config, unsigned short http_port, unsigned short https_port)
        : thread_pool_(std::make_shared<AsioThreadPool>(1)),
          server_(thread_pool_, config),
          ssl_context_(asio::ssl::context::sslv23) {

        setupSSLContext(config);

        auto tcp_handler = std::make_shared<HttpMessageHandler>();
        tcp_handler->registerHandler(0, [this](const std::shared_ptr<TCPNetworkUtility::Session<HttpMessageFraming, HttpMessageFraming>>& session, const ByteVector& data) {
            handleHTTPRequest(session, data);
        });

        // HTTP
        server_.addTcpPort<HttpMessageFraming, HttpMessageFraming>(http_port,
            [](std::shared_ptr<TCPNetworkUtility::Session<HttpMessageFraming, HttpMessageFraming>> session) {
                std::cout << "New HTTP connection: " << session->getSessionUuid() << std::endl;
            },
            tcp_handler,
            [](std::shared_ptr<TCPNetworkUtility::Session<HttpMessageFraming, HttpMessageFraming>> session) {
                std::cout << "HTTP connection closed: " << session->getSessionUuid() << std::endl;
            }, {}, {}
        );

        // HTTPS
        server_.addTcpPort<HttpMessageFraming, HttpMessageFraming>(https_port,
            [this](std::shared_ptr<TCPNetworkUtility::Session<HttpMessageFraming, HttpMessageFraming>> session) {
                std::cout << "New HTTPS connection: " << session->getSessionUuid() << std::endl;
                auto ssl_session = TCPNetworkUtility::createSSLSession<HttpMessageFraming, HttpMessageFraming>(
                    thread_pool_->get_io_context(), ssl_context_, {}, {});
                ssl_session->start(
                    [this, ssl_session](const ByteVector& data) {
                        handleHTTPRequest(ssl_session, data);
                    },
                    [](std::shared_ptr<TCPNetworkUtility::SSLSession<HttpMessageFraming, HttpMessageFraming>> session) {
                        std::cout << "HTTPS connection closed: " << session->getSessionUuid() << std::endl;
                    }
                );
            },
            tcp_handler,
            [](std::shared_ptr<TCPNetworkUtility::Session<HttpMessageFraming, HttpMessageFraming>> session) {
                std::cout << "HTTPS connection closed: " << session->getSessionUuid() << std::endl;
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
    void setupSSLContext(const Config& config) {
        ssl_context_.set_options(
            asio::ssl::context::default_workarounds
            | asio::ssl::context::no_sslv2
            | asio::ssl::context::single_dh_use);

        ssl_context_.use_certificate_chain_file(config.get<std::string>("ssl_cert_file", "server.crt"));
        ssl_context_.use_private_key_file(config.get<std::string>("ssl_key_file", "server.key"), asio::ssl::context::pem);
        ssl_context_.use_tmp_dh_file(config.get<std::string>("ssl_dh_file", "dh2048.pem"));
    }

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
    asio::ssl::context ssl_context_;
    std::shared_ptr<AsioThreadPool> thread_pool_;
    Server server_;
    std::unordered_map<std::string, RequestHandler> routes_;
};
