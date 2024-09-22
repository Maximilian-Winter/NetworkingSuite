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

    std::unordered_map<std::string, nlohmann::json> route_data;
};

enum class MiddlewareType {
    PRE_HANDLER,
    POST_HANDLER
};

class Middleware {
public:
    virtual ~Middleware() = default;
    virtual void process(RouteContext& route_context, const HttpRequest& request, HttpResponse& response, std::function<void()> next) = 0;
};



class HttpServer {
public:
    class HttpRoute {
    public:
        using RequestHandler = std::function<void(RouteContext& route_context, const HttpRequest& request, HttpResponse& response)>;

        HttpRoute(const std::string& pattern, const std::regex& regex, const RequestHandler& handler)
            : pattern(pattern), regex(regex), handler(handler) {}

        void addMiddleware(const std::shared_ptr<Middleware>& middleware, const MiddlewareType type) {
            if (type == MiddlewareType::PRE_HANDLER) {
                pre_middlewares.push_back(middleware);
            } else {
                post_middlewares.push_back(middleware);
            }
        }

        std::string pattern;
        std::regex regex;
        RequestHandler handler;
        std::vector<std::shared_ptr<Middleware>> pre_middlewares;
        std::vector<std::shared_ptr<Middleware>> post_middlewares;
    };

    explicit HttpServer(const std::string& config_file)
        : message_framing_(), ssl_message_framing_(), config_(std::make_shared<Config>())
    {
        config_->load(config_file);

        auto thread_count = config_->get<unsigned int>("thread_count", 4);
        thread_pool_ = std::make_shared<AsioThreadPool>(thread_count);
        server_ = std::make_unique<Server>(thread_pool_, *config_);

        setupHTTPServer();
        setupHTTPSServer();

        // Initialize FileServer with root directory from config
        auto root_dir = config_->get<std::string>("file_server_root", "./public");
        file_server_ = std::make_unique<FileServer>(root_dir);
    }

    void start() {
        server_->start();
    }

    void stop() {
        server_->stop();
    }

    std::shared_ptr<HttpRoute> addRoute(const std::string& path, const HttpRoute::RequestHandler &handler) {
        const std::string pattern = path + "(\\?.*)?$";
        routes_.push_back(std::make_shared<HttpRoute>(path, std::regex(pattern), handler));
        return routes_.back();
    }

private:


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
            handleHTTPRequest(session, data);
        });

        server_->addSslTcpPort(https_port, ssl_cert, ssl_key, ssl_dh_file, ssl_handler_);
    }

    void handleHTTPRequest(const std::shared_ptr<NetworkSession<HttpMessageFraming, HttpMessageFraming>>& session, const ByteVector& data) {
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


        bool route_handled = false;

        // Check for matching routes
        for (const auto& route : routes_) {
            std::smatch matches;
            if (std::regex_match(path, matches, route->regex)) {
                // Execute pre-handler middlewares
                RouteContext route_context = {route->pattern, route->regex};
                executeMiddlewares(route->pre_middlewares,route_context, request, response, [&]() {
                    // Execute the main handler
                    route->handler(route_context, request, response);

                    // Execute post-handler middlewares
                    executeMiddlewares(route->post_middlewares,route_context, request, response, []() {});
                });

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

        if (request.header().getField("Connection") != "keep-alive") {
            session->close();
        }
    }

    static void executeMiddlewares(const std::vector<std::shared_ptr<Middleware>>& middlewares, RouteContext& route_context,
                                   const HttpRequest& request, HttpResponse& response,
                                   const std::function<void()> &final_action) {
        std::function<void(size_t)> execute_next = [&](size_t index) {
            if (index < middlewares.size()) {
                middlewares[index]->process(route_context, request, response, [=]() {
                    execute_next(index + 1);
                });
            } else {
                final_action();
            }
        };

        execute_next(0);
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
    std::vector<std::shared_ptr<HttpRoute>> routes_;
    std::unique_ptr<FileServer> file_server_;
};
