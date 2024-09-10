#include "HttpServer.h"
#include <iostream>
#include <sstream>

int main() {
    HttpServer server("http_server_config_test.json");

    // Example request: http://localhost/
    server.addRoute("/", [](const std::string& method, const std::unordered_map<std::string, std::string>& headers, const std::string& body, const std::unordered_map<std::string, std::string>& query_params, const std::unordered_map<std::string, std::string>& route_params, std::string& response, std::unordered_map<std::string, std::string>& response_headers, HttpMessageFraming& send_message_framing) {
        response = "<html><body><h1>Welcome to the HTTP Server</h1></body></html>";
        response_headers["Content-Type"] = "text/html";
        response_headers["Content-Length"] = std::to_string(response.length());
        send_message_framing.setStatusCode(200);
        send_message_framing.setStatusMessage("OK");
        send_message_framing.setMessageType(HttpMessageFraming::MessageType::RESPONSE);
    });



    // Example request: http://localhost/greet?name=John
    server.addRoute("/greet", [](const std::string& method, const std::unordered_map<std::string, std::string>& headers, const std::string& body, const std::unordered_map<std::string, std::string>& query_params, const std::unordered_map<std::string, std::string>& route_params, std::string& response, std::unordered_map<std::string, std::string>& response_headers, HttpMessageFraming& send_message_framing) {
        std::string name = query_params.count("name") ? query_params.at("name") : "Guest";
        response = "Hello, " + name + "!";
        response_headers["Content-Type"] = "text/plain";
        response_headers["Content-Length"] = std::to_string(response.length());
        send_message_framing.setMessageType(HttpMessageFraming::MessageType::RESPONSE);
    });

    // Example request: http://localhost/users/123/posts/42
    server.addRoute("/users/([^/]+)/posts/([^/]+)", [](const std::string& method, const std::unordered_map<std::string, std::string>& headers, const std::string& body, const std::unordered_map<std::string, std::string>& query_params, const std::unordered_map<std::string, std::string>& route_params, std::string& response, std::unordered_map<std::string, std::string>& response_headers, HttpMessageFraming& send_message_framing) {
        std::ostringstream oss;
        oss << "User ID: " << route_params.at("param1") << "\n";
        oss << "Post ID: " << route_params.at("param2") << "\n";
        response = oss.str();
        response_headers["Content-Type"] = "text/plain";
        response_headers["Content-Length"] = std::to_string(response.length());
        send_message_framing.setMessageType(HttpMessageFraming::MessageType::RESPONSE);
    });

    // Example request: http://localhost/api/users/posts/123?sort=date&limit=10
    server.addRoute("/api/([^/]+)/([^/]+)/([^/]+)", [](const std::string& method, const std::unordered_map<std::string, std::string>& headers, const std::string& body, const std::unordered_map<std::string, std::string>& query_params, const std::unordered_map<std::string, std::string>& route_params, std::string& response, std::unordered_map<std::string, std::string>& response_headers, HttpMessageFraming& send_message_framing) {
        std::ostringstream oss;
        oss << "API Route Parameters:\n";
        oss << "  Parameter 1: " << route_params.at("param1") << "\n";
        oss << "  Parameter 2: " << route_params.at("param2") << "\n";
        oss << "  Parameter 3: " << route_params.at("param3") << "\n";

        oss << "\nQuery Parameters:\n";
        for (const auto& [key, value] : query_params) {
            oss << "  " << key << ": " << value << "\n";
        }

        response = oss.str();
        response_headers["Content-Type"] = "text/plain";
        response_headers["Content-Length"] = std::to_string(response.length());
        send_message_framing.setMessageType(HttpMessageFraming::MessageType::RESPONSE);
    });
    server.start();

    std::cout << "HTTP server started. Press Enter to exit." << std::endl;
    std::cin.get();

    server.stop();
    return 0;
}