//
// Created by maxim on 10.09.2024.
//

// HttpParser.h
#pragma once
#include "HttpRequest.h"
#include "HttpResponse.h"
#include <vector>
#include <string>
#include <optional>
#include <stdexcept>
#include <algorithm>

class HttpParser {
public:
    enum class MessageType {
        REQUEST,
        RESPONSE,
        UNKNOWN
    };

    static bool isValidHttpMessage(const std::vector<uint8_t>& data) {
        std::string str(data.begin(), data.end());
        return str.find("\r\n\r\n") != std::string::npos;
    }

    static HttpRequest parseRequest(const std::vector<uint8_t>& data) {
        if (!isValidHttpMessage(data)) {
            return HttpRequest();
        }

        std::string str(data.begin(), data.end());
        std::istringstream iss(str);
        std::string line;

        HttpRequest request;

        // Parse request line
        if (!std::getline(iss, line)) {
            return HttpRequest();
        }
        line.erase(line.find_last_not_of("\r\n") + 1);

        std::istringstream request_line(line);
        std::string method, path, version;
        if (!(request_line >> method >> path >> version)) {
            return HttpRequest();
        }

        request.setMethod(method);
        request.setPath(path);
        request.setHttpVersion(version);

        // Parse headers
        while (std::getline(iss, line) && line != "\r") {
            line.erase(line.find_last_not_of("\r\n") + 1);
            auto colon_pos = line.find(':');
            if (colon_pos != std::string::npos) {
                std::string name = line.substr(0, colon_pos);
                std::string value = line.substr(colon_pos + 1);
                value.erase(0, value.find_first_not_of(" "));
                request.header().addField(name, value);
            }
        }

        // Parse body
        std::string body;
        std::getline(iss, body, '\0');
        request.body().setContent(std::vector<uint8_t>(body.begin(), body.end()));

        return request;
    }

    static HttpResponse parseResponse(const std::vector<uint8_t>& data) {
        if (!isValidHttpMessage(data)) {
            return HttpResponse();
        }

        std::string str(data.begin(), data.end());
        std::istringstream iss(str);
        std::string line;

        HttpResponse response;

        // Parse status line
        if (!std::getline(iss, line)) {
            return HttpResponse();
        }
        line.erase(line.find_last_not_of("\r\n") + 1);

        std::istringstream status_line(line);
        std::string version, status_code, status_message;
        if (!(status_line >> version >> status_code)) {
            return HttpResponse();
        }
        std::getline(status_line, status_message);
        status_message.erase(0, status_message.find_first_not_of(" "));

        response.setHttpVersion(version);
        response.setStatusCode(std::stoi(status_code));
        response.setStatusMessage(status_message);

        // Parse headers
        while (std::getline(iss, line) && line != "\r") {
            line.erase(line.find_last_not_of("\r\n") + 1);
            auto colon_pos = line.find(':');
            if (colon_pos != std::string::npos) {
                std::string name = line.substr(0, colon_pos);
                std::string value = line.substr(colon_pos + 1);
                value.erase(0, value.find_first_not_of(" "));
                response.header().addField(name, value);
            }
        }

        // Parse body
        std::string body;
        std::getline(iss, body, '\0');
        response.body().setContent(std::vector<uint8_t>(body.begin(), body.end()));

        return response;
    }

    static MessageType detectMessageType(const std::vector<uint8_t>& data) {
        if (!isValidHttpMessage(data)) {
            return MessageType::UNKNOWN;
        }

        std::string str(data.begin(), data.end());
        std::istringstream iss(str);
        std::string first_line;
        std::getline(iss, first_line);

        if (first_line.find("HTTP/") == 0) {
            return MessageType::RESPONSE;
        } else if (first_line.find("GET ") == 0 || first_line.find("POST ") == 0 ||
                   first_line.find("PUT ") == 0 || first_line.find("DELETE ") == 0 ||
                   first_line.find("HEAD ") == 0 || first_line.find("OPTIONS ") == 0) {
            return MessageType::REQUEST;
        }

        return MessageType::UNKNOWN;
    }


};