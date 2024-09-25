//
// Created by maxim on 24.09.2024.
//
#pragma once
#include <unordered_map>
#include <functional>
#include <regex>

#include "HttpRequest.h"
#include "HttpResponse.h"

#include "nlohmann/json.hpp"

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
