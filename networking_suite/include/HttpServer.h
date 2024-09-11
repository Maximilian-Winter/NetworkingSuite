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

struct RouteContext {
    std::string pattern;
    std::regex regex;
};

class HttpServer {
public:

    using RequestHandler = std::function<void(RouteContext route_context, const HttpRequest& request, HttpResponse& response)>;
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
        tcp_handler_.set_message_handler([this](const std::shared_ptr<NetworkSession<HttpMessageFraming, HttpMessageFraming>>& session, const ByteVector& data) {
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
        ssl_handler_.set_message_handler([this](const std::shared_ptr<NetworkSession<HttpMessageFraming, HttpMessageFraming>>& session, const ByteVector& data) {
            handleHTTPSRequest(session, data);
        });

        server_->addSslTcpPort(https_port, ssl_cert, ssl_key, ssl_dh_file, ssl_handler_);
    }


    void handleHTTPRequest(const std::shared_ptr<NetworkSession<HttpMessageFraming, HttpMessageFraming>>& session, const ByteVector& data) {
        processRequest(session, data);
    }

    void handleHTTPSRequest(const std::shared_ptr<NetworkSession<HttpMessageFraming, HttpMessageFraming>>& session, const ByteVector& data) {
        processRequest(session, data);
    }

    template<typename SessionType>
    void processRequest(const std::shared_ptr<SessionType>& session, const ByteVector& data) {
        auto request = HttpParser::parseRequest(data) ;
        HttpResponse response;

        std::string method = request.getMethod();
        std::string full_path = request.getPath();
        std::string http_version = request.getHttpVersion();

        // Split the path and query string
        std::string path = full_path;

        size_t query_pos = full_path.find_last_of('?');
        if (query_pos != std::string::npos) {
            path = full_path.substr(0, query_pos);
        }

        HttpHeader headers = request.header();

        std::string body;
        if (static_cast<int>(data.size()) > 0) {
            body = std::string(data.begin(), data.end());
        }

        bool route_handled = false;

        // Check for matching routes
        for (const auto& route : routes_) {
            std::smatch matches;
            if (std::regex_match(path, matches, route.regex)) {
                route.handler(RouteContext{route.pattern, route.regex}, request, response);
                route_handled = true;
                break;
            }
        }

        // If no route handled the request, try to serve a file
        if (!route_handled) {
            std::string content_type;
            std::string content;
            if(path == "/") {
                if(file_server_->serveFile(path + "index.html", content, content_type)) {
                    response.body().setContent(content);
                    response.header().addField("Content-Type", content_type);
                    response.header().addField("Content-Length", std::to_string(content.length()));
                } else {
                    response.setStatusCode(404);
                    response.setStatusMessage("NOT FOUND");
                }
            } else if (file_server_->serveFile(path, content, content_type)) {
                response.body().setContent(content);
                response.header().addField("Content-Type", content_type);
                response.header().addField("Content-Length", std::to_string(content.length()));
            } else {
                response.setStatusCode(404);
                response.setStatusMessage("NOT FOUND");
            }
        }
        std::string response_string = response.toString();
        session->write(ByteVector(response_string.begin(), response_string.end()));
        session->close();
    }

    SessionContext<NetworkSession<HttpMessageFraming, HttpMessageFraming>, HttpMessageFraming, HttpMessageFraming> tcp_handler_;
    HttpMessageFraming message_framing_;
    HttpMessageFraming message_framing_2;
    SessionContext<NetworkSession<HttpMessageFraming, HttpMessageFraming>, HttpMessageFraming, HttpMessageFraming> ssl_handler_;
    HttpMessageFraming ssl_message_framing_;
    HttpMessageFraming ssl_message_framing_2;
    std::shared_ptr<Config> config_;
    std::shared_ptr<AsioThreadPool> thread_pool_;
    std::unique_ptr<Server> server_;
    std::vector<RouteInfo> routes_;
    std::unique_ptr<FileServer> file_server_;
};
