#pragma once

#include <regex>
#include <sstream>
#include <unordered_map>
#include <string>
#include "SessionContext.h"
#include "HttpParser.h"

class HttpMessageFraming: MessageFraming {
public:
    enum class MessageType {
        REQUEST,
        RESPONSE,
        UNKNOWN
    };

    HttpMessageFraming(): MessageFraming()
    {
    }

    ByteVector frameMessage(const ByteVector& message) const override {
        return message;
    }

    bool isCompleteMessage(const ByteVector& buffer) const override {
        if(!HttpParser::isValidHttpMessage(buffer))
        {
           return false;
        }
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
        return buffer;
    }


};