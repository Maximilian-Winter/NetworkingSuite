//
// Created by maxim on 23.08.2024.
//

#pragma once

#include "BinaryData.h"
#include "TCPNetworkUtility.h"
#include "UDPNetworkUtility.h"
#include <functional>
#include <unordered_map>
#include <memory>

template<typename EndpointType>
class MessageHandler {
public:
    virtual ~MessageHandler() = default;

    using MessageCallback = std::function<void(const EndpointType&, const ByteVector&)>;

    virtual void registerHandler(short messageType, MessageCallback callback) = 0;

    virtual void handleMessage(const EndpointType& endpoint, const ByteVector& data) = 0;

protected:

};
class TCPMessageHandler: MessageHandler<std::shared_ptr<TCPNetworkUtility::Session>>
{
public:
    void handleMessage(const std::shared_ptr<TCPNetworkUtility::Session> &endpoint, const ByteVector &data) override
    {
        try {
            NetworkMessages::MessageTypeData typeData;
            size_t offset = 0;
            typeData.deserialize(data, offset);
            short messageType = typeData.Type;

            auto it = m_handlers.find(messageType);
            if (it != m_handlers.end()) {
                it->second(endpoint, data);
            } else {
                LOG_ERROR("No handler registered for message type: %d", messageType);
            }
        } catch (const std::exception& e) {
            LOG_ERROR("Error handling message: %s", e.what());
        }
    }

    void registerHandler(short messageType, MessageCallback callback) override{
        m_handlers[messageType] = std::move(callback);
    }

private:

    std::unordered_map<short, MessageCallback> m_handlers;
};

class UDPMessageHandler: MessageHandler<std::shared_ptr<UDPNetworkUtility::Connection>>
{
public:
    void registerHandler(short messageType, MessageCallback callback) override{
        m_handlers[messageType] = std::move(callback);
    }
    void handleMessage(const std::shared_ptr<UDPNetworkUtility::Connection> &endpoint, const ByteVector &data) override
    {
        try {
            NetworkMessages::MessageTypeData typeData;
            size_t offset = 0;
            typeData.deserialize(data, offset);
            short messageType = typeData.Type;

            auto it = m_handlers.find(messageType);
            if (it != m_handlers.end()) {
                it->second(endpoint, data);
            } else {
                LOG_ERROR("No handler registered for message type: %d", messageType);
            }
        } catch (const std::exception& e) {
            LOG_ERROR("Error handling message: %s", e.what());
        }
    }
private:

    std::unordered_map<short, MessageCallback> m_handlers;
};


