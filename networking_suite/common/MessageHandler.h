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
    using MessageCallback = std::function<void(const EndpointType&, const ByteVector&)>;

    void registerHandler(short messageType, MessageCallback callback) {
        m_handlers[messageType] = std::move(callback);
    }

    void handleMessage(const EndpointType& endpoint, const ByteVector& data) {
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

// Specialization for TCP (using std::shared_ptr<NetworkUtility::Session> as endpoint)
using TCPMessageHandler = MessageHandler<std::shared_ptr<TCPNetworkUtility::Session>>;

using UDPMessageHandler = MessageHandler<std::shared_ptr<UDPNetworkUtility::Connection>>;

