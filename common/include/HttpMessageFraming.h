#pragma once

#include <regex>
#include <sstream>
#include <unordered_map>
#include <string>
#include "SessionContext.h"

class HttpMessageFraming: MessageFraming {
public:
    enum class MessageType {
        REQUEST,
        RESPONSE,
        UNKNOWN
    };

    HttpMessageFraming(): MessageFraming()
    {
        initializeConnectionData();
        //initializeContext();
    }

    void initializeConnectionData() {
        connectionData_ = std::make_shared<json>();
        (*connectionData_)["headers"] = std::unordered_map<std::string, std::string>();
        (*connectionData_)["message_type"] = static_cast<int>(MessageType::REQUEST);
        (*connectionData_)["content_type"] = "plain/text";
        (*connectionData_)["status_code"] = 200;
        (*connectionData_)["status_message"] = "OK";
        (*connectionData_)["http_version"] = "HTTP/1.1";
    }

    ByteVector frameMessage(const ByteVector& message) const override {
        std::ostringstream framedMessage;

        if (getMessageType() == MessageType::REQUEST) {
            framedMessage << getRequestLine() << "\r\n";
        } else {
            framedMessage << getStatusLine() << "\r\n";
        }

        for (const auto& [key, value] : getHeaders()) {
            framedMessage << key << ": " << value << "\r\n";
        }

        framedMessage << "\r\n";
        std::string framedMessageStr = framedMessage.str();

        ByteVector output(framedMessageStr.begin(), framedMessageStr.end());
        output.insert(output.end(), message.begin(), message.end());

        return output;
    }

    bool isCompleteMessage(const ByteVector& buffer) const override {
        std::string bufferStr(buffer.begin(), buffer.end());
        std::istringstream bufferStream(bufferStr);

        std::string line;
        int contentLength = 0;
        int headerLength = 0;

        std::getline(bufferStream, line);
        headerLength += line.length() + 1;

        while (std::getline(bufferStream, line) && line != "\r") {
            headerLength += line.length() + 1;
            if (line.find("Content-Length:") == 0) {
                contentLength = std::stoi(line.substr(16));
            }
        }
        headerLength += 2;

        return (buffer.size() >= headerLength + contentLength);
    }

    ByteVector extractMessage(const ByteVector& buffer) override {
        std::string bufferStr(buffer.begin(), buffer.end());
        std::istringstream bufferStream(bufferStr);

        std::string line;
        int contentLength = -1;
        int headerLength = 0;
        std::unordered_map<std::string, std::string> headers;

        std::getline(bufferStream, line);
        headerLength += line.length() + 1;
        MessageType detectedType = parseRequestStatusLine(line);
        setMessageType(detectedType);

        while (std::getline(bufferStream, line) && line != "\r") {
            headerLength += line.length() + 1;
            size_t colonPos = line.find(':');
            if (colonPos != std::string::npos) {
                std::string key = line.substr(0, colonPos);
                std::string value = line.substr(colonPos + 2, line.size() - (colonPos + 2) - 1);
                headers[key] = value;
                if (key == "Content-Length") {
                    contentLength = std::stoi(value);
                }
            }
        }
        headerLength += 2;

        setHeaders(headers);

        (*connectionData_)["last_message"] = buffer;

        if (contentLength > -1) {
            ByteVector messageBody(buffer.begin() + headerLength, buffer.begin() + headerLength + contentLength);
            return messageBody;
        }
        return ByteVector(0);
    }

    void setHeaders(const std::unordered_map<std::string, std::string>& headers) {
        (*connectionData_)["headers"] = headers;
    }

    [[nodiscard]] std::unordered_map<std::string, std::string> getHeaders() const {
        return (*connectionData_)["headers"].get<std::unordered_map<std::string, std::string>>();
    }

    void setMessageType(const MessageType messageType) {
        (*connectionData_)["message_type"] = static_cast<int>(messageType);
    }

    [[nodiscard]] MessageType getMessageType() const {
        return static_cast<MessageType>((*connectionData_)["message_type"].get<int>());
    }

    void setContentType(const std::string& contentType) {
        (*connectionData_)["content_type"] = contentType;
    }

    void setRequestMethod(const std::string& method) {
        (*connectionData_)["request_method"] = method;
    }

    void setRequestPath(const std::string& path) {
        (*connectionData_)["request_path"] = path;
    }

    void setHttpVersion(const std::string& version) {
        (*connectionData_)["http_version"] = version;
    }

    void setStatusCode(int code) {
        (*connectionData_)["status_code"] = code;
    }

    void setStatusMessage(const std::string& message) {
        (*connectionData_)["status_message"] = message;
    }

    std::string getContentType() const {
        return (*connectionData_)["content_type"].get<std::string>();
    }

    std::string getRequestMethod() const {
        return (*connectionData_)["request_method"].get<std::string>();
    }

    std::string getRequestPath() const {
        return (*connectionData_)["request_path"].get<std::string>();
    }

    std::string getHttpVersion() const {
        return (*connectionData_)["http_version"].get<std::string>();
    }

    int getStatusCode() const {
        return (*connectionData_)["status_code"].get<int>();
    }

    std::string getStatusMessage() const {
        return (*connectionData_)["status_message"].get<std::string>();
    }

    ByteVector getFullLastMessage() const {
        return (*connectionData_)["last_message"].get<ByteVector>();
    }
    std::unordered_map<std::string, std::string> parseQueryString() const {
        std::unordered_map<std::string, std::string> query_params;
        std::string path = getRequestPath();
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
        std::string full_path = getRequestPath();
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
    std::vector<std::string> split(const std::string& s, char delimiter) const {
        std::vector<std::string> tokens;
        std::string token;
        std::istringstream tokenStream(s);
        while (std::getline(tokenStream, token, delimiter)) {
            if (!token.empty()) {
                tokens.push_back(token);
            }
        }
        return tokens;
    }

    std::shared_ptr<json> connectionData_;

    std::string getRequestLine() const {
        std::string method = (*connectionData_)["request_method"].get<std::string>();
        std::string path = (*connectionData_)["request_path"].get<std::string>();
        std::string version = (*connectionData_)["http_version"].get<std::string>();
        return method + " " + path + " " + version;
    }

    std::string getStatusLine() const {
        std::string version = (*connectionData_)["http_version"].get<std::string>();
        int code = (*connectionData_)["status_code"].get<int>();
        std::string message = (*connectionData_)["status_message"].get<std::string>();
        return version + " " + std::to_string(code) + " " + message;
    }

    MessageType parseRequestStatusLine(const std::string& line) const {
        std::istringstream iss(line);
        std::string first, second, third;
        iss >> first >> second >> third;

        if (first.substr(0, 4) == "HTTP") {
            // This is a response
            (*connectionData_)["http_version"] = first;
            (*connectionData_)["status_code"] = std::stoi(second);
            (*connectionData_)["status_message"] = third;
            return MessageType::RESPONSE;
        } else {
            // This is a request
            (*connectionData_)["request_method"] = first;
            (*connectionData_)["request_path"] = second;
            (*connectionData_)["http_version"] = third;
            return MessageType::REQUEST;
        }
    }
};