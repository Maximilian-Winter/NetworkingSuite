#pragma once

#include <vector>
#include <string>
#include <algorithm>
#include "SessionContext.h"
#include "HttpParser.h"

class HttpMessageFraming final : public MessageFraming {
public:
    HttpMessageFraming() : error_state_(false) {}

    [[nodiscard]] ByteVector frame_message(const ByteVector& message) override {
        return message;
    }

   ByteVector extract_next_message(ByteVector& buffer) override {

        auto result = extractSingleMessage(buffer);
        return result;
    }

    [[nodiscard]] MessageState check_message_state(const ByteVector &buffer) const override
    {
        return HttpParser::isValidHttpMessage(buffer) ? MessageState::VALID : MessageState::INVALID;
    }
protected:
    ByteVector extractSingleMessage(ByteVector& buffer) {
        size_t headerEnd = findMessageBoundary(buffer);
        if (headerEnd == std::string::npos) {
            return {};  // No complete message found
        }

        size_t contentLength = parseContentLength(buffer, headerEnd);
        size_t totalLength = headerEnd + 4 + contentLength;  // 4 for "\r\n\r\n"

        if (buffer.size() < totalLength) {
            return {};  // Message is not complete yet
        }

        ByteVector message(buffer.begin(), buffer.begin() + totalLength);
        buffer.erase(buffer.begin(), buffer.begin() + totalLength);
        return message;
    }

private:
    bool error_state_;
    std::string error_message_;

    [[nodiscard]] size_t findMessageBoundary(const ByteVector& buffer) const {
        const char boundary[] = "\r\n\r\n";
        auto it = std::search(buffer.begin(), buffer.end(),
                              std::begin(boundary), std::end(boundary) - 1); // -1 to exclude null terminator
        return (it != buffer.end()) ? std::distance(buffer.begin(), it) : std::string::npos;
    }

    [[nodiscard]] size_t parseContentLength(const ByteVector& buffer, size_t headerEnd) const {
        std::string headers(buffer.begin(), buffer.begin() + headerEnd);
        size_t pos = headers.find("Content-Length:");
        if (pos != std::string::npos) {
            pos = headers.find_first_not_of(" ", pos + 15);  // 15 is length of "Content-Length:"
            size_t endpos = headers.find_first_of("\r\n", pos);
            if (endpos != std::string::npos) {
                try {
                    return std::stoull(headers.substr(pos, endpos - pos));
                } catch (const std::exception& e) {
                    // Log the error or handle it as appropriate for your application
                    return 0;
                }
            }
        }
        return 0;  // No Content-Length header or invalid format
    }


};