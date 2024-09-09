//
// Created by maxim on 08.09.2024.
//

#pragma once

#include "Server.h"
#include "HttpMessageFraming.h"
#include "HttpMessageHandler.h"
#include "Config.h"
#include "FileServer.h"
#include <unordered_map>
#include <functional>
#include <regex>

class HttpServer {
public:
    using RequestHandler = std::function<void(const std::string&, const std::unordered_map<std::string, std::string>&, const std::string&, const std::unordered_map<std::string, std::string>&, const std::unordered_map<std::string, std::string>&, std::string&, std::unordered_map<std::string, std::string>&)>;

    explicit HttpServer(const std::string& config_file)
        : config_(std::make_shared<Config>()) {

        config_->load(config_file);

        unsigned int thread_count = config_->get<unsigned int>("thread_count", 4);
        thread_pool_ = std::make_shared<AsioThreadPool>(thread_count);
        server_ = std::make_unique<Server>(thread_pool_, *config_);

        setupHTTPServer();
        setupHTTPSServer();

        // Initialize FileServer with root directory from config
        std::string root_dir = config_->get<std::string>("file_server_root", "./public");
        file_server_ = std::make_unique<FileServer>(root_dir);
    }

    void start() {
        server_->start();
    }

    void stop() {
        server_->stop();
    }

    void addRoute(const std::string& path, RequestHandler handler) {
        std::string pattern = path + "(\\?.*)?$";
        routes_.push_back({path, std::regex(pattern), handler});
    }

private:
    struct RouteInfo {
        std::string pattern;
        std::regex regex;
        RequestHandler handler;
    };



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
        std::string full_path = session->getReceiveFraming().getRequestPath();
        std::string http_version = session->getReceiveFraming().getHttpVersion();

        // Split the path and query string
        std::string path = full_path;

        size_t query_pos = full_path.find_last_of('?');
        if (query_pos != std::string::npos) {
            path = full_path.substr(0, query_pos);
        }

        std::unordered_map<std::string, std::string> headers = session->getReceiveFraming().getHeaders();

        std::string body;
        if (static_cast<int>(data.size()) > 0) {
            body = std::string(data.begin(), data.end());
        }

        std::string response;
        std::unordered_map<std::string, std::string> response_headers;

        bool route_handled = false;

        // Parse query string
        auto query_params = session->getReceiveFraming().parseQueryString();

        // Check for matching routes
        for (const auto& route : routes_) {
            std::smatch matches;
            if (std::regex_match(path, matches, route.regex)) {
                auto route_params = session->getReceiveFraming().extractRouteParams(route.pattern);
                route.handler(method, headers, body, query_params, route_params, response, response_headers);
                route_handled = true;
                break;
            }
        }

        // If no route handled the request, try to serve a file
        if (!route_handled) {
            std::string content_type;
            if(path == "/") {
                if(file_server_->serveFile(path + "index.html", response, content_type)) {
                    response_headers["Content-Type"] = content_type;
                } else {
                    response = "404 Not Found";
                    response_headers["Content-Type"] = "text/plain";
                }
            } else if (file_server_->serveFile(path, response, content_type)) {
                response_headers["Content-Type"] = content_type;
            } else {
                response = "404 Not Found";
                response_headers["Content-Type"] = "text/plain";
            }
        }

        response_headers["Content-Length"] = std::to_string(static_cast<int>(response.size()));
        session->getSendFraming().setMessageType(HttpMessageFraming::MessageType::RESPONSE);
        session->getSendFraming().setHeaders(response_headers);

        session->write(ByteVector(response.begin(), response.end()));
    }

    std::shared_ptr<Config> config_;
    std::shared_ptr<AsioThreadPool> thread_pool_;
    std::unique_ptr<Server> server_;
    std::vector<RouteInfo> routes_;
    std::unique_ptr<FileServer> file_server_;
};
