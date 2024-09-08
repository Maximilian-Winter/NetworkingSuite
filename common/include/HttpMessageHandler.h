//
// Created by maxim on 08.09.2024.
//
#pragma once

#include "MessageHandler.h"
#include "TCPNetworkUtility.h"
#include <functional>
#include <unordered_map>
#include <memory>

#include "HttpMessageFraming.h"

class HttpMessageHandler : public TCPMessageHandler<HttpMessageFraming, HttpMessageFraming> {
public:
    using HttpCallback = std::function<void(const std::shared_ptr<TCPNetworkUtility::Session<HttpMessageFraming,HttpMessageFraming>>&, const ByteVector&)>;

    void registerHandler(short messageType, HttpCallback callback) override {
        // For HTTP, we don't use message types, so we'll ignore the messageType parameter
        m_handler = std::move(callback);
    }

    void handleMessage(const std::shared_ptr<TCPNetworkUtility::Session<HttpMessageFraming,HttpMessageFraming>>& endpoint, const ByteVector& data) override {
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
    HttpCallback m_handler;
};

template<typename SendFraming, typename ReceiveFraming>
class SSLHttpMessageHandler : public MessageHandler<std::shared_ptr<SSLNetworkUtility::Session<SendFraming, ReceiveFraming>>> {
public:
    using SSLHttpCallback = std::function<void(const std::shared_ptr<SSLNetworkUtility::Session<HttpMessageFraming,HttpMessageFraming>>&, const ByteVector&)>;
    void registerHandler(short messageType, SSLHttpCallback callback) override {
        // For HTTP, we don't use message types, so we'll ignore the messageType parameter
        m_handler = std::move(callback);
    }

    void handleMessage(const std::shared_ptr<SSLNetworkUtility::Session<HttpMessageFraming,HttpMessageFraming>>& endpoint, const ByteVector& data) override {
        try {
            if (m_handler) {
                m_handler(endpoint, data);
            } else {
                LOG_ERROR("No HTTP handler registered");
            }
        } catch (const std::exception& e) {
            LOG_ERROR("Error handling HTTP message: %s", e.what());
        }
    }

private:
    SSLHttpCallback m_handler;
};