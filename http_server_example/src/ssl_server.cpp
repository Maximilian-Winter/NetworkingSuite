//
// Created by maxim on 08.09.2024.
//

#include "HttpSSLServer.h"

#include <iostream>

int main() {
    Config config;
    // Load configuration if needed
    // config.load("http_server_config.json");

    // Add SSL certificate and key file paths to the config
    config.set("ssl_cert_file", "server.crt");
    config.set("ssl_key_file", "server.key");
    config.set("ssl_dh_file", "dh2048.pem");

    HTTPServer server(config, 8080, 8443);  // HTTP on 8080, HTTPS on 8443

    server.addRoute("/", [](const std::string& method, const std::unordered_map<std::string, std::string>& headers, const std::string& body, std::string& response, std::unordered_map<std::string, std::string>& response_headers) {
        response = "<html><body><h1>Welcome to the HTTPS Server</h1></body></html>";
        response_headers["Content-Type"] = "text/html";
        response_headers["Content-Length"] = std::to_string(static_cast<int>(response.size()));
    });

    server.addRoute("/echo", [](const std::string& method, const std::unordered_map<std::string, std::string>& headers, const std::string& body, std::string& response, std::unordered_map<std::string, std::string>& response_headers) {
        response = body;
        response_headers["Content-Type"] = "text/plain";
        response_headers["Content-Length"] = std::to_string(static_cast<int>(response.size()));
    });

    server.start();

    std::cout << "HTTP server started on port 8080" << std::endl;
    std::cout << "HTTPS server started on port 8443" << std::endl;
    std::cout << "Press Enter to exit." << std::endl;
    std::cin.get();

    server.stop();
    return 0;
}