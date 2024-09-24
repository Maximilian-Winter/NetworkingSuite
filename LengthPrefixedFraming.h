//
// Created by maxim on 22.09.2024.
//
#pragma once
#include "SessionContext.h"
class LengthPrefixedFraming : public MessageFraming
{
public:
    LengthPrefixedFraming(uint32_t max_message_size = 1048576) // 1 MB default max size
        : max_message_size_(max_message_size), error_state_(false) {}

    ByteVector frameMessage(const ByteVector& message) const override
    {
        if (message.size() > max_message_size_) {
            throw std::runtime_error("Message size exceeds maximum allowed size");
        }

        ByteVector framed_message;
        framed_message.reserve(sizeof(uint32_t) + message.size());

        uint32_t size = static_cast<uint32_t>(message.size());
        framed_message.insert(framed_message.end(), reinterpret_cast<uint8_t*>(&size), reinterpret_cast<uint8_t*>(&size) + sizeof(uint32_t));
        framed_message.insert(framed_message.end(), message.begin(), message.end());

        return framed_message;
    }

    std::vector<ByteVector> processIncomingData(ByteVector& buffer) override
    {
        std::vector<ByteVector> completed_messages;

        while (hasCompleteMessage(buffer)) {
            completed_messages.push_back(extractSingleMessage(buffer));
        }

        return completed_messages;
    }

    bool hasCompleteMessage(const ByteVector& buffer) const override
    {
        return buffer.size() >= sizeof(uint32_t) &&
               buffer.size() >= sizeof(uint32_t) + *reinterpret_cast<const uint32_t*>(buffer.data());
    }

    size_t getBytesNeededForNextMessage(const ByteVector& buffer) const override
    {
        if (buffer.size() < sizeof(uint32_t)) {
            return sizeof(uint32_t) - buffer.size();
        }

        uint32_t message_size = *reinterpret_cast<const uint32_t*>(buffer.data());
        if (message_size > max_message_size_) {
            error_state_ = true;
            error_message_ = "Message size exceeds maximum allowed size";
            return 0;
        }

        return sizeof(uint32_t) + message_size - buffer.size();
    }

    void reset() override
    {
        error_state_ = false;
        error_message_.clear();
    }

    bool isInErrorState() const override
    {
        return error_state_;
    }

    std::string getErrorMessage() const override
    {
        return error_message_;
    }

protected:
    ByteVector extractSingleMessage(ByteVector& buffer) override
    {
        uint32_t message_size = *reinterpret_cast<const uint32_t*>(buffer.data());
        ByteVector message(buffer.begin() + sizeof(uint32_t), buffer.begin() + sizeof(uint32_t) + message_size);
        buffer.erase(buffer.begin(), buffer.begin() + sizeof(uint32_t) + message_size);
        return message;
    }

private:
    uint32_t max_message_size_;
    mutable bool error_state_;
    mutable std::string error_message_;
};
