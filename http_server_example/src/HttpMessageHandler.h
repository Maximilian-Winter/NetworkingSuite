//
// Created by maxim on 08.09.2024.
//
#pragma once

#include "MessageHandler.h"
#include "TCPNetworkUtility.h"
#include <functional>
#include <unordered_map>
#include <memory>
class HTTPMessageHandler : public MessageHandler<std::shared_ptr<TCPNetworkUtility::Session>> {
public:
    using HTTPCallback = std::function<void(const std::shared_ptr<TCPNetworkUtility::Session>&, const ByteVector&)>;

    void registerHandler(short messageType, MessageCallback callback) override {
        // For HTTP, we don't use message types, so we'll ignore the messageType parameter
        m_handler = std::move(callback);
    }

    void handleMessage(const std::shared_ptr<TCPNetworkUtility::Session>& endpoint, const ByteVector& data) override {
        try {
            if (m_handler) {
                // Pass through the entire message without parsing
                m_handler(endpoint, data);
            } else {
                LOG_ERROR("No HTTP handler registered");
            }
        } catch (const std::exception& e) {
            LOG_ERROR("Error handling HTTP message: %s", e.what());
        }
    }

private:
    HTTPCallback m_handler;
};
