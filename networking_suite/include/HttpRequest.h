//
// Created by maxim on 10.09.2024.
//
// HttpRequest.h
#pragma once
#include "HttpMessage.h"
#include <sstream>
#include <regex>

class HttpRequest : public HttpMessage {
public:
    HttpRequest() : HttpMessage(Type::REQUEST), httpVersion_("HTTP/1.1") {}

    void setMethod(const std::string& method) {
        method_ = method;
    }

    void setPath(const std::string& path) {
        path_ = path;
    }

    void setHttpVersion(const std::string& version) {
        httpVersion_ = version;
    }

    std::string getMethod() const {
        return method_;
    }

    std::string getPath() const {
        return path_;
    }

    std::string getHttpVersion() const {
        return httpVersion_;
    }

    std::string toString() const override {
        std::ostringstream oss;
        oss << method_ << " " << path_ << " " << httpVersion_ << "\r\n";
        oss << header().toString();
        oss << "\r\n";
        const auto& content = body().getContent();
        oss.write(reinterpret_cast<const char*>(content.data()), content.size());
        return oss.str();
    }
    std::unordered_map<std::string, std::string> parseQueryString() const {
        std::unordered_map<std::string, std::string> query_params;
        std::string path = path_;
        size_t query_start = path.find('?');

        if (query_start != std::string::npos) {
            std::string query = path.substr(query_start + 1);
            std::istringstream query_stream(query);
            std::string pair;

            while (std::getline(query_stream, pair, '&')) {
                size_t eq_pos = pair.find('=');
                if (eq_pos != std::string::npos) {
                    std::string key = pair.substr(0, eq_pos);
                    std::string value = pair.substr(eq_pos + 1);
                    query_params[urlDecode(key)] = urlDecode(value);
                }
            }
        }

        return query_params;
    }

    std::unordered_map<std::string, std::string> extractRouteParams(const std::string& route_pattern) const {
        std::unordered_map<std::string, std::string> route_params;
        std::string full_path = path_;
        std::string path = full_path;

        size_t query_pos = full_path.find_last_of('?');
        if (query_pos != std::string::npos) {
            path = full_path.substr(0, query_pos);
        }
        std::regex pattern(route_pattern);
        std::smatch matches;

        if (std::regex_match(path, matches, pattern)) {
            for (size_t i = 1; i < matches.size(); ++i) {
                std::string param_name = "param" + std::to_string(i);
                route_params[param_name] = urlDecode(matches[i].str());
            }
        }

        return route_params;
    }
private:
    static std::string urlDecode(const std::string& encoded) {
        std::string result;
        for (size_t i = 0; i < encoded.length(); ++i) {
            if (encoded[i] == '%' && i + 2 < encoded.length()) {
                int value;
                std::istringstream is(encoded.substr(i + 1, 2));
                if (is >> std::hex >> value) {
                    result += static_cast<char>(value);
                    i += 2;
                } else {
                    result += encoded[i];
                }
            } else if (encoded[i] == '+') {
                result += ' ';
            } else {
                result += encoded[i];
            }
        }
        return result;
    }
    std::string method_;
    std::string path_;
    std::string httpVersion_;
};

