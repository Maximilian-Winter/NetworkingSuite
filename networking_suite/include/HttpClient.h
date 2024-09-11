//
// Created by maxim on 11.09.2024.
//
// HttpClient.h
#pragma once

#include <string>
#include <functional>
#include <future>
#include "NetworkSession.h"
#include "HttpRequest.h"
#include "HttpResponse.h"
#include "HttpMessageFraming.h"

class HttpClient {
public:
    explicit HttpClient(asio::io_context& io_context);

    std::future<HttpResponse> get(const std::string& url, const std::unordered_map<std::string, std::string>& headers = {});
    std::future<HttpResponse> post(const std::string& url, const std::string& body, const std::unordered_map<std::string, std::string>& headers = {});

private:
    std::future<HttpResponse> sendRequest(const std::string& url, HttpRequest& request);
    static void parseUrl(const std::string& url, std::string& host, std::string& port, std::string& path);

    asio::io_context& io_context_;
    HttpMessageFraming message_framing_;
    SessionContext<NetworkSession<HttpMessageFraming, HttpMessageFraming>, HttpMessageFraming, HttpMessageFraming> context_;
    std::shared_ptr<NetworkSession<HttpMessageFraming, HttpMessageFraming>> session_;
};


inline HttpClient::HttpClient(asio::io_context& io_context)
    : io_context_(io_context) {}

inline std::future<HttpResponse> HttpClient::get(const std::string& url, const std::unordered_map<std::string, std::string>& headers) {
    HttpRequest request;
    request.setMethod("GET");

    std::string host, port, path;
    parseUrl(url, host, port, path);

    request.setPath(path);
    request.setHttpVersion("HTTP/1.1");
    request.header().addField("Host", host);

    for (const auto& [key, value] : headers) {
        request.header().addField(key, value);
    }

    return sendRequest(url, request);
}

inline std::future<HttpResponse> HttpClient::post(const std::string& url, const std::string& body, const std::unordered_map<std::string, std::string>& headers) {
    HttpRequest request;
    request.setMethod("POST");

    std::string host, port, path;
    parseUrl(url, host, port, path);

    request.setPath(path);
    request.setHttpVersion("HTTP/1.1");
    request.header().addField("Host", host);
    request.header().addField("Content-Length", std::to_string(body.length()));
    request.body().setContent(body);

    for (const auto& [key, value] : headers) {
        request.header().addField(key, value);
    }

    return sendRequest(url, request);
}

inline std::future<HttpResponse> HttpClient::sendRequest(const std::string& url, HttpRequest& request) {
    auto promise = std::make_shared<std::promise<HttpResponse>>();
    auto future = promise->get_future();

    std::string host, port, path;
    parseUrl(url, host, port, path);


    context_.set_message_framing_sender(message_framing_);
    context_.set_message_framing_receiver(message_framing_);

    context_.set_connected_callback([request](const std::shared_ptr<NetworkSession<HttpMessageFraming, HttpMessageFraming>>& session) {
        std::string request_string = request.toString();
        session->write(ByteVector(request_string.begin(), request_string.end()));
    });

    context_.set_message_handler([promise](const std::shared_ptr<NetworkSession<HttpMessageFraming, HttpMessageFraming>>& session, const ByteVector& data) {
        const HttpResponse response = HttpParser::parseResponse(data);
        promise->set_value(response);
        session->close();
    });

    session_ = NetworkSession<HttpMessageFraming, HttpMessageFraming>::connect(io_context_, host, port, context_);

    return future;
}

inline void HttpClient::parseUrl(const std::string& url, std::string& host, std::string& port, std::string& path) {
    std::regex url_regex("(https?)://([^:/]+)(:([0-9]+))?(/.*)?");
    std::smatch matches;

    if (std::regex_match(url, matches, url_regex)) {
        std::string protocol = matches[1].str();
        host = matches[2].str();
        port = matches[4].str();
        path = matches[5].str();

        if (port.empty()) {
            port = (protocol == "https") ? "443" : "80";
        }

        if (path.empty()) {
            path = "/";
        }
    } else {
        throw std::runtime_error("Invalid URL format");
    }
}
