//
// Created by maxim on 10.09.2024.
//

// HttpResponse.h
#pragma once
#include "HttpMessage.h"
#include <sstream>

class HttpResponse : public HttpMessage {
public:
    HttpResponse() : HttpMessage(Type::RESPONSE), statusCode_(200), statusMessage_("OK"), httpVersion_("HTTP/1.1") {}

    void setStatusCode(int code) {
        statusCode_ = code;
    }

    void setStatusMessage(const std::string& message) {
        statusMessage_ = message;
    }

    void setHttpVersion(const std::string& version) {
        httpVersion_ = version;
    }

    int getStatusCode() const {
        return statusCode_;
    }

    std::string getStatusMessage() const {
        return statusMessage_;
    }

    std::string getHttpVersion() const {
        return httpVersion_;
    }

    std::string toString() const override {
        std::ostringstream oss;
        oss << httpVersion_ << " " << statusCode_ << " " << statusMessage_ << "\r\n";
        oss << header().toString();
        oss << "\r\n";
        const auto& content = body().getContent();
        oss.write(reinterpret_cast<const char*>(content.data()), content.size());
        return oss.str();
    }

private:
    int statusCode_;
    std::string statusMessage_;
    std::string httpVersion_;
};
