//
// Created by maxim on 08.09.2024.
//

#pragma once

#include "Server.h"
#include "HttpMessageFraming.h"
#include "Config.h"
#include "FileServer.h"
#include <unordered_map>
#include <functional>
#include <regex>

class HttpServer {
public:
    using RequestHandler = std::function<void(const std::string&,
                                          const std::unordered_map<std::string, std::string>&,
                                          const std::string&,
                                          const std::unordered_map<std::string, std::string>&,
                                          const std::unordered_map<std::string, std::string>&,
                                          std::string&,
                                          std::unordered_map<std::string, std::string>&,
                                          HttpMessageFraming&)>;
    explicit HttpServer(const std::string& config_file)
        : config_(std::make_shared<Config>()), message_framing_(), ssl_message_framing_()
    {
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

    void addRoute(const std::string& path, const RequestHandler &handler) {
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
        tcp_handler_.set_message_framing_sender(message_framing_);
        tcp_handler_.set_message_framing_receiver(message_framing_2);
        tcp_handler_.set_message_handler([this](const std::shared_ptr<TCPNetworkUtility::Session<HttpMessageFraming, HttpMessageFraming>>& session, const ByteVector& data) {
            handleHTTPRequest(session, data);
        });

        server_->addTcpPort(http_port, tcp_handler_);
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
        ssl_handler_.set_message_framing_sender(ssl_message_framing_);
        ssl_handler_.set_message_framing_receiver(ssl_message_framing_2);
        ssl_handler_.set_message_handler([this](const std::shared_ptr<SSLNetworkUtility::Session<HttpMessageFraming, HttpMessageFraming>>& session, const ByteVector& data) {
            handleHTTPSRequest(session, data);
        });

        server_->addSslTcpPort(https_port, ssl_cert, ssl_key, ssl_dh_file, ssl_handler_);
    }


    void handleHTTPRequest(const std::shared_ptr<TCPNetworkUtility::Session<HttpMessageFraming, HttpMessageFraming>>& session, const ByteVector& data) {
        processRequest(session, data, tcp_handler_);
    }

    void handleHTTPSRequest(const std::shared_ptr<SSLNetworkUtility::Session<HttpMessageFraming, HttpMessageFraming>>& session, const ByteVector& data) {
        processRequest(session, data, ssl_handler_);
    }

    template<typename SessionType, typename SessionContextType>
    void processRequest(const std::shared_ptr<SessionType>& session, const ByteVector& data, SessionContextType& context) {
        auto& receive_framing = context.get_message_framing_receive();
        auto& send_framing = context.get_message_framing_send();

        std::string method = receive_framing.getRequestMethod();
        std::string full_path = receive_framing.getRequestPath();
        std::string http_version = receive_framing.getHttpVersion();

        // Split the path and query string
        std::string path = full_path;

        size_t query_pos = full_path.find_last_of('?');
        if (query_pos != std::string::npos) {
            path = full_path.substr(0, query_pos);
        }

        std::unordered_map<std::string, std::string> headers = receive_framing.getHeaders();

        std::string body;
        if (static_cast<int>(data.size()) > 0) {
            body = std::string(data.begin(), data.end());
        }

        std::string response;
        std::unordered_map<std::string, std::string> response_headers;

        bool route_handled = false;

        // Parse query string
        auto query_params = receive_framing.parseQueryString();

        // Check for matching routes
        for (const auto& route : routes_) {
            std::smatch matches;
            if (std::regex_match(path, matches, route.regex)) {
                auto route_params = receive_framing.extractRouteParams(route.pattern);
                route.handler(method, headers, body, query_params, route_params, response, response_headers, send_framing);
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
                    send_framing.setStatusCode(404);
                    send_framing.setStatusMessage("NOT FOUND");
                    send_framing.setMessageType(HttpMessageFraming::MessageType::RESPONSE);
                }
            } else if (file_server_->serveFile(path, response, content_type)) {
                response_headers["Content-Type"] = content_type;
            } else {
                send_framing.setStatusCode(404);
                send_framing.setStatusMessage("NOT FOUND");
                send_framing.setMessageType(HttpMessageFraming::MessageType::RESPONSE);
            }
        }

        response_headers["Content-Length"] = std::to_string(static_cast<int>(response.size()));
        session->write(ByteVector(response.begin(), response.end()));
        session->close();
    }

    SessionContext<TCPNetworkUtility::Session<HttpMessageFraming, HttpMessageFraming>, HttpMessageFraming, HttpMessageFraming> tcp_handler_;
    HttpMessageFraming message_framing_;
    HttpMessageFraming message_framing_2;
    SessionContext<SSLNetworkUtility::Session<HttpMessageFraming, HttpMessageFraming>, HttpMessageFraming, HttpMessageFraming> ssl_handler_;
    HttpMessageFraming ssl_message_framing_;
    HttpMessageFraming ssl_message_framing_2;
    std::shared_ptr<Config> config_;
    std::shared_ptr<AsioThreadPool> thread_pool_;
    std::unique_ptr<Server> server_;
    std::vector<RouteInfo> routes_;
    std::unique_ptr<FileServer> file_server_;
};
