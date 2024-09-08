//
// Created by maxim on 23.08.2024.
//

#pragma once

#include "BinaryData.h"
#include "TCPNetworkUtility.h"
#include "UDPNetworkUtility.h"
#include "SSLNetworkUtility.h"
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

template<typename SendFraming, typename ReceiveFraming>
class TCPMessageHandler: MessageHandler<std::shared_ptr<TCPNetworkUtility::Session<SendFraming, ReceiveFraming>>>
{
public:
    void handleMessage(const std::shared_ptr<TCPNetworkUtility::Session<SendFraming, ReceiveFraming>> &endpoint, const ByteVector &data) override
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

    void registerHandler(short messageType, typename MessageHandler<std::shared_ptr<TCPNetworkUtility::Session<SendFraming, ReceiveFraming>>>::MessageCallback callback) override{
        m_handlers[messageType] = std::move(callback);
    }

private:

    std::unordered_map<short, typename MessageHandler<std::shared_ptr<TCPNetworkUtility::Session<SendFraming, ReceiveFraming>>>::MessageCallback> m_handlers;
};

template<typename SendFraming, typename ReceiveFraming>
class UDPMessageHandler: MessageHandler<std::shared_ptr<UDPNetworkUtility::Connection<SendFraming, ReceiveFraming>>>
{
public:
    void registerHandler(short messageType, typename MessageHandler<std::shared_ptr<UDPNetworkUtility::Connection<SendFraming, ReceiveFraming>>>::MessageCallback callback) override{
        m_handlers[messageType] = std::move(callback);
    }
    void handleMessage(const std::shared_ptr<UDPNetworkUtility::Connection<SendFraming, ReceiveFraming>> &endpoint, const ByteVector &data) override
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

    std::unordered_map<short, typename MessageHandler<std::shared_ptr<UDPNetworkUtility::Connection<SendFraming, ReceiveFraming>>>::MessageCallback> m_handlers;
};


