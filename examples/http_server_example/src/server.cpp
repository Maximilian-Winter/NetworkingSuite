#include "HttpServer.h"
#include <iostream>
#include <sstream>

int main() {
    HttpServer server("http_server_config_test.json");

    // Define a middleware
    class LoggingMiddleware : public Middleware {
    public:
        void process(RouteContext& route_context, const HttpRequest& request, HttpResponse& response, std::function<void()> next) override {
            std::cout << "Received request: " << request.getMethod() << " " << request.getPath() << std::endl;
            next();
            std::cout << "Sending response: " << response.getStatusCode() << std::endl;
        }
    };

    // Example request: http://localhost/
    auto route = server.addRoute("/", [](const RouteContext& context, const HttpRequest& request, HttpResponse& response) {
        response.setStatusCode(200);
        response.setStatusMessage("OK");
        std::string content = "<html><body><h1>Welcome to the HTTP Server</h1></body></html>";
        response.body().setContent(content);
        response.header().addField("Content-Type", "text/html");
    });

    route->addMiddleware(std::make_shared<LoggingMiddleware>(), MiddlewareType::PRE_HANDLER);

    // Example request: http://localhost/greet?name=John
    auto route2 = server.addRoute("/greet", [](const RouteContext& context, const HttpRequest& request, HttpResponse& response) {
        std::unordered_map<std::string, std::string> query_params = request.parseQueryString();
        const std::string name = query_params.contains("name") ? query_params.at("name") : "Guest";

        std::string content = "Hello, " + name + "!";

        response.body().setContent(content);
        response.header().addField("Content-Type", "text/plain");

    });
    route2->addMiddleware(std::make_shared<LoggingMiddleware>(), MiddlewareType::PRE_HANDLER);

    // Example request: http://localhost/users/123/posts/42
    auto route3 = server.addRoute("/users/([^/]+)/posts/([^/]+)", [](const RouteContext& context, const HttpRequest& request, HttpResponse& response) {
        std::unordered_map<std::string, std::string> route_params = request.extractRouteParams(context.pattern);
        std::ostringstream oss;
        oss << "User ID: " << route_params.at("param1") << "\n";
        oss << "Post ID: " << route_params.at("param2") << "\n";
        std::string response_string = oss.str();
        response.body().setContent(response_string);
        response.header().addField("Content-Type", "text/plain");
    });
    route3->addMiddleware(std::make_shared<LoggingMiddleware>(), MiddlewareType::PRE_HANDLER);

    // Example request: http://localhost/api/users/posts/123?sort=date&limit=10
    auto route4 = server.addRoute("/api/([^/]+)/([^/]+)/([^/]+)", [](const RouteContext& context, const HttpRequest& request, HttpResponse& response) {
        std::unordered_map<std::string, std::string> query_params = request.parseQueryString();
        std::unordered_map<std::string, std::string> route_params = request.extractRouteParams(context.pattern);
        std::ostringstream oss;
        oss << "API Route Parameters:\n";
        oss << "  Parameter 1: " << route_params.at("param1") << "\n";
        oss << "  Parameter 2: " << route_params.at("param2") << "\n";
        oss << "  Parameter 3: " << route_params.at("param3") << "\n";

        oss << "\nQuery Parameters:\n";
        for (const auto& [key, value] : query_params) {
            oss << "  " << key << ": " << value << "\n";
        }

        std::string response_string = oss.str();
        response.body().setContent(response_string);
        response.header().addField("Content-Type", "text/plain");
    });
    route4->addMiddleware(std::make_shared<LoggingMiddleware>(), MiddlewareType::PRE_HANDLER);

    server.start();

    std::cout << "HTTP server started. Press Enter to exit." << std::endl;
    std::cin.get();

    server.stop();
    return 0;
}