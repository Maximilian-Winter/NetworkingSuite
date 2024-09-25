//
// Created by maxim on 10.09.2024.
//
#include "HttpClient.h"


int main() {
    asio::io_context io_context;
    HttpClient client(io_context, "", true);

    // GET request
    auto future_get = client.get("https://localhost/");
    io_context.run();
    HttpResponse response_get = future_get.get();
    std::cout << "GET Response: " << response_get.toString() << std::endl;


    return 0;
}