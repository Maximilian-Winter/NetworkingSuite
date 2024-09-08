#pragma once
#include "HttpServer.h"

int main() {
    HttpServer server("http_server_config_test.json");

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

    std::cout << "HTTP server started. Press Enter to exit." << std::endl;
    std::cin.get();

    server.stop();
    return 0;
}