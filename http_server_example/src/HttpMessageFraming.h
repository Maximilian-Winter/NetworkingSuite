#pragma once

#include "MessageFraming.h"
#include <sstream>
#include <unordered_map>
#include <string>

class HTTPMessageFraming : public MessageFraming {
public:


    enum class MessageType {
        REQUEST,
        RESPONSE,
        UNKNOWN
    };

    HTTPMessageFraming(){
        if (!connectionData_) {
            connectionData_ = std::make_shared<json>();
        }
        (*connectionData_)["headers"] = std::unordered_map<std::string, std::string>();
        (*connectionData_)["message_type"] = MessageType::REQUEST;
        (*connectionData_)["content_type"] = "plain/text";
    }

    HTTPMessageFraming(MessageType message_type)
    {
        if (!connectionData_) {
            connectionData_ = std::make_shared<json>();
        }
        (*connectionData_)["headers"] = std::unordered_map<std::string, std::string>();
        (*connectionData_)["message_type"] = message_type;
        (*connectionData_)["content_type"] = "plain/text";
    }


    ByteVector frameMessage(const ByteVector& message) const override {
        std::ostringstream framedMessage;

        // Add request line or status line
        if ((*connectionData_)["message_type"] == MessageType::REQUEST) {
            framedMessage << getRequestLine() << "\r\n";
        } else {
            framedMessage << getStatusLine() << "\r\n";
        }
        size_t message_size = message.size();

        // Add custom headers if any
        if (connectionData_) {
            const auto& headers = connectionData_->at("headers").get<std::unordered_map<std::string, std::string>>();
            for (const auto& [key, value] : headers) {
                if(key == "Content-Length" && std::stoi(value) > 0)
                {
                    framedMessage << key << ": " << value << "\r\n";
                    framedMessage << "Content-Type: " << (*connectionData_)["content_type"] << "\r\n";
                }
            }
        }

        // End of headers
        framedMessage << "\r\n";
        std::string framedMessageStr = framedMessage.str();

        ByteVector output(framedMessageStr.begin(), framedMessageStr.end());
        if(message_size > 0)
        {
            // Add the message body
            output.insert(output.end(), message.begin(), message.end());
        }

        return output;
    }

    bool isCompleteMessage(const ByteVector& buffer) const override {
        std::string bufferStr(buffer.begin(), buffer.end());
        std::istringstream bufferStream(bufferStr);

        std::string line;
        int contentLength = 0;
        int headerLength = 0;

        // Skip the first line (request/status line)
        std::getline(bufferStream, line);
        headerLength += line.length() + 1;

        // Parse headers
        while (std::getline(bufferStream, line) && line != "\r") {
            headerLength += line.length() + 1;
            if (line.find("Content-Length:") == 0) {
                contentLength = std::stoi(line.substr(16));
            }
        }
        headerLength += 2;  // For the empty line after headers

        // Check if we have a complete message
        return (buffer.size() >= headerLength + contentLength);
    }

     ByteVector extractMessage(const ByteVector& buffer) override {
        std::string bufferStr(buffer.begin(), buffer.end());
        std::istringstream bufferStream(bufferStr);

        std::string line;
        int contentLength = -1;
        int headerLength = 0;
        std::unordered_map<std::string, std::string> headers;

        // Parse request/status line
        std::getline(bufferStream, line);
        headerLength += line.length() + 1;  // +1 for \n
        MessageType detectedType = parseRequestStatusLine(line);
        (*connectionData_)["message_type"] = static_cast<int>(detectedType);

        // Parse headers
        while (std::getline(bufferStream, line) && line != "\r") {
            headerLength += line.length() + 1;  // +1 for \n
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
        headerLength += 2;  // For the empty line after headers



        // Store parsed headers in connectionData_
        if (connectionData_) {
            (*connectionData_)["headers"] = headers;
        }

        // Store the full message in connectionData_
        if (connectionData_) {
            (*connectionData_)["last_message"] = buffer;
        }

        if (contentLength > -1) {
            // Extract the message body
            ByteVector messageBody(buffer.begin() + headerLength, buffer.begin() + headerLength + contentLength);
            return messageBody;
        }
        return ByteVector(0);
    }

    MessageType getDetectedMessageType() const {
        if (connectionData_ && connectionData_->contains("message_type")) {
            return static_cast<MessageType>(connectionData_->at("message_type").get<int>());
        }
        return MessageType::UNKNOWN;
    }


    size_t getMaxFramingOverhead() const override {
        // A reasonable estimate for max header size
        return 2048;
    }

    void setHeaders(const std::unordered_map<std::string, std::string>& headers) {
        if (connectionData_) {
            (*connectionData_)["headers"] = headers;
        }
    }

    std::unordered_map<std::string, std::string> getHeaders() const {
        if (connectionData_ && connectionData_->contains("headers")) {
            return connectionData_->at("headers").get<std::unordered_map<std::string, std::string>>();
        }
        return {};
    }

    ByteVector getFullLastMessage() const {
        if (connectionData_ && connectionData_->contains("last_message")) {
            return connectionData_->at("last_message").get<ByteVector>();
        }
        return {};
    }
    void setMessageType(const MessageType messageType) {
       (*connectionData_)["message_type"] = static_cast<int>(messageType);
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
    MessageType getMessageType() const {
        return static_cast<MessageType>((*connectionData_)["message_type"].get<int>());
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

private:

    MessageType messageType_;

    std::string getRequestLine() const {
        std::string method = connectionData_->value("request_method", "GET");
        std::string path = connectionData_->value("request_path", "/");
        std::string version = connectionData_->value("http_version", "HTTP/1.1");
        return method + " " + path + " " + version;
    }

    std::string getStatusLine() const {
        std::string version = connectionData_->value("http_version", "HTTP/1.1");
        int code = connectionData_->value("status_code", 200);
        std::string message = connectionData_->value("status_message", "OK");
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