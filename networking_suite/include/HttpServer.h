//
// Created by maxim on 08.09.2024.
//

#pragma once

#include "Server.h"
#include "HttpMessageFraming.h"
#include "Config.h"
#include "FileServer.h"
#include "HttpRoute.h"
#include <unordered_map>
#include <functional>
#include <regex>


class HttpServer
{
public:
    explicit HttpServer(const std::string &config_file)
        : message_framing_(), config_(std::make_shared<Config>())
    {
        config_->load(config_file);

        auto thread_count = config_->get<unsigned int>("thread_count", 4);
        thread_pool_ = std::make_shared<AsioThreadPool>(thread_count);
        server_ = std::make_unique<Server>(thread_pool_, *config_);

        session_context_template_ = std::make_shared<SessionContextTemplate>();
        session_context_template_->set_http2(false);
        session_context_template_->set_write_preprocessor([this](const ByteVector &message)
        {
            return message_framing_.frame_message(message);
        });

        session_context_template_->set_read_postprocessor([this](ByteVector &message)
        {
            return message_framing_.extract_next_message(message);
        });

        session_context_template_->set_check_message_state([this](const ByteVector &message)
        {
            return HttpParser::isValidHttpMessage(message) ? MessageState::VALID : MessageState::INVALID;
        });

        session_context_template_->set_message_handler(
            [this](const std::shared_ptr<NetworkSession> &session, const ByteVector &data)
            {
                processHttp1Request(session, data);
            });
        session_context_template_->set_http2_request_handler([this](const HttpRequest &request, HttpResponse &response)
        {
            handleHTTPRequest(request, response);
        });
        setupHTTPServer();
        setupHTTPSServer();

        // Initialize FileServer with root directory from config
        auto root_dir = config_->get<std::string>("file_server_root", "./public");
        file_server_ = std::make_unique<FileServer>(root_dir);
    }

    void start()
    {
        server_->start();
    }

    void stop()
    {
        server_->stop();
    }

    std::shared_ptr<HttpRoute> addRoute(const std::string &path, const HttpRoute::RequestHandler &handler)
    {
        const std::string pattern = path + "(\\?.*)?$";
        routes_.push_back(std::make_shared<HttpRoute>(path, std::regex(pattern), handler));
        return routes_.back();
    }

private:
    void setupHTTPServer() const
    {
        auto http_port = config_->get<unsigned short>("http_port", 80);
        server_->addTcpPort(http_port, session_context_template_);
    }

    void setupHTTPSServer() const
    {
        auto https_port = config_->get<unsigned short>("https_port", 443);
        auto ssl_cert = config_->get<std::string>("ssl_cert_file", "");
        auto ssl_key = config_->get<std::string>("ssl_key_file", "");
        auto ssl_dh_file = config_->get<std::string>("ssl_dh_file", "");

        if (ssl_cert.empty() || ssl_key.empty())
        {
            std::cout << "SSL configuration is incomplete. HTTPS server will not be started." << std::endl;
            return;
        }

        server_->addSslTcpPort(https_port, ssl_cert, ssl_key, ssl_dh_file, session_context_template_);
    }



    void processHttp1Request(const std::shared_ptr<NetworkSession> &session, const ByteVector &data)
    {
        HttpRequest request = HttpParser::parseRequest(data);
        HttpResponse response;
        handleHTTPRequest(request, response);
        std::string response_string = response.toString();
        session->write(ByteVector(response_string.begin(), response_string.end()));

        if (request.header().getField("Connection") != "keep-alive")
        {
            session->close();
        }
    }

    void handleHTTPRequest(const HttpRequest &request, HttpResponse &response)
    {
        std::string method = request.getMethod();
        std::string full_path = request.getPath();

        // Split the path and query string
        std::string path = full_path;

        size_t query_pos = full_path.find_last_of('?');
        if (query_pos != std::string::npos)
        {
            path = full_path.substr(0, query_pos);
        }


        bool route_handled = false;

        // Check for matching routes
        for (const auto &route: routes_)
        {
            std::smatch matches;
            if (std::regex_match(path, matches, route->regex))
            {
                // Execute pre-handler middlewares
                RouteContext route_context = {route->pattern, route->regex};
                executeMiddlewares(route->pre_middlewares, route_context, request, response, [&]()
                {
                    // Execute the main handler
                    route->handler(route_context, request, response);

                    // Execute post-handler middlewares
                    executeMiddlewares(route->post_middlewares, route_context, request, response, []()
                    {
                    });
                });

                route_handled = true;
                break;
            }
        }


        // If no route handled the request, try to serve a file
        if (!route_handled)
        {
            std::string content_type;
            std::string content;
            if (path == "/")
            {
                if (file_server_->serveFile(path + "index.html", content, content_type))
                {
                    response.body().setContent(content);
                    response.header().addField("Content-Type", content_type);
                    response.header().addField("Content-Length", std::to_string(content.length()));
                } else
                {
                    response.setStatusCode(404);
                    response.setStatusMessage("NOT FOUND");
                }
            } else if (file_server_->serveFile(path, content, content_type))
            {
                response.body().setContent(content);
                response.header().addField("Content-Type", content_type);
                response.header().addField("Content-Length", std::to_string(content.length()));
            } else
            {
                response.setStatusCode(404);
                response.setStatusMessage("NOT FOUND");
            }
        }
        size_t content_length = response.body().getSize();
        if (content_length > 0)
        {
            response.header().addField("Content-Length", std::to_string(content_length));
        }
    }

    static void executeMiddlewares(const std::vector<std::shared_ptr<Middleware> > &middlewares,
                                   RouteContext &route_context,
                                   const HttpRequest &request, HttpResponse &response,
                                   const std::function<void()> &final_action)
    {
        std::function<void(size_t)> execute_next = [&](size_t index)
        {
            if (index < middlewares.size())
            {
                middlewares[index]->process(route_context, request, response, [=]()
                {
                    execute_next(index + 1);
                });
            } else
            {
                final_action();
            }
        };

        execute_next(0);
    }

    std::shared_ptr<SessionContextTemplate> session_context_template_;
    HttpMessageFraming message_framing_;
    std::shared_ptr<Config> config_;
    std::shared_ptr<AsioThreadPool> thread_pool_;
    std::unique_ptr<Server> server_;
    std::vector<std::shared_ptr<HttpRoute> > routes_;
    std::unique_ptr<FileServer> file_server_;
};
