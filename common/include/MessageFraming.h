//
// Created by maxim on 07.09.2024.
//

#pragma once

#include <vector>
#include <cstdint>
#include <stdexcept>
#include <memory>
#include <nlohmann/json.hpp>

using ByteVector = std::vector<uint8_t>;
using json = nlohmann::json;

class MessageFraming {
public:
    virtual ~MessageFraming() = default;

    // Frame a message for sending
    virtual ByteVector frameMessage(const ByteVector& message) const = 0;

    // Check if a received buffer contains a complete message
    virtual bool isCompleteMessage(const ByteVector& buffer) const = 0;

    // Extract the message from a framed buffer
    virtual ByteVector extractMessage(const ByteVector& buffer) = 0;

    // Get the maximum overhead added by framing
    virtual size_t getMaxFramingOverhead() const = 0;

    // Set connection-specific data
    void setConnectionData(const json& data) {
        connectionData_ = std::make_shared<json>(data);
    }

    // Get connection-specific data
    std::shared_ptr<json> getConnectionData() const {
        return connectionData_;
    }

protected:
    std::shared_ptr<json> connectionData_;
};

class MagicNumberFraming : public MessageFraming {
public:
    MagicNumberFraming(uint32_t startMagic, uint32_t endMagic)
        : startMagicNumber_(startMagic), endMagicNumber_(endMagic) {}

    ByteVector frameMessage(const ByteVector& message) const override {
        ByteVector framedMessage;
        framedMessage.reserve(sizeof(uint32_t) * 3 + message.size());

        appendToVector(framedMessage, startMagicNumber_);
        appendToVector(framedMessage, static_cast<uint32_t>(message.size()));
        framedMessage.insert(framedMessage.end(), message.begin(), message.end());
        appendToVector(framedMessage, endMagicNumber_);

        return framedMessage;
    }

    bool isCompleteMessage(const ByteVector& buffer) const override {
        if (buffer.size() < sizeof(uint32_t) * 3) return false;

        uint32_t startMagic, messageSize, endMagic;
        std::memcpy(&startMagic, buffer.data(), sizeof(uint32_t));
        std::memcpy(&messageSize, buffer.data() + sizeof(uint32_t), sizeof(uint32_t));
        std::memcpy(&endMagic, buffer.data() + buffer.size() - sizeof(uint32_t), sizeof(uint32_t));

        return startMagic == startMagicNumber_ &&
               endMagic == endMagicNumber_ &&
               buffer.size() == messageSize + sizeof(uint32_t) * 3;
    }

    ByteVector extractMessage(const ByteVector& buffer) override {
        if (!isCompleteMessage(buffer)) {
            throw std::runtime_error("Incomplete or invalid message");
        }

        uint32_t messageSize;
        std::memcpy(&messageSize, buffer.data() + sizeof(uint32_t), sizeof(uint32_t));

        return ByteVector(buffer.begin() + sizeof(uint32_t) * 2,
                          buffer.begin() + sizeof(uint32_t) * 2 + messageSize);
    }

    size_t getMaxFramingOverhead() const override {
        return sizeof(uint32_t) * 3;  // Start magic, size, and end magic
    }

private:
    uint32_t startMagicNumber_;
    uint32_t endMagicNumber_;

    static void appendToVector(ByteVector& vec, uint32_t value) {
        vec.insert(vec.end(),
                   reinterpret_cast<const uint8_t*>(&value),
                   reinterpret_cast<const uint8_t*>(&value) + sizeof(uint32_t));
    }
};