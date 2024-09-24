//
// Created by maxim on 07.09.2024.
//

#pragma once

#include <Logger.h>
#include <utility>
#include <vector>
#include <memory>
#include "AsioThreadPool.h"
#include "Config.h"
#include "Port.h"


class Server {
public:
    Server(std::shared_ptr<AsioThreadPool> thread_pool, Config  config)
        : thread_pool_(std::move(thread_pool)), config_(std::move(config))
    {
        //auto port = config_.get<short>("port", 8080);
        std::string defaultLevel = "INFO";
        auto log_level = config_.get<std::string>("log_level", "DEBUG");
        auto log_file = config_.get<std::string>("log_file", "client.log");
        auto log_file_size_in_mb = config_.get<float>("max_log_file_size_in_mb", 1.0f);
        AsyncLogger& logger = AsyncLogger::getInstance();
        logger.setLogLevel(AsyncLogger::parseLogLevel(log_level));
        logger.addDestination(std::make_shared<AsyncLogger::ConsoleDestination>());
        logger.addDestination(std::make_shared<AsyncLogger::FileDestination>(log_file, log_file_size_in_mb * (1024 * 1024)));
    }

    void addTcpPort(unsigned short port_number, const std::shared_ptr<SessionContextTemplate>& connection_context_template) {
        auto tcp_port = std::make_shared<TcpPort>(thread_pool_->get_io_context(), port_number, connection_context_template);
        ports_.push_back(tcp_port);
    }


    void addSslTcpPort(unsigned short port_number, const std::string& ssl_cert_file, const std::string& ssl_key_file, const std::string& ssl_dh_file, std::shared_ptr<SessionContextTemplate> connection_context_template) {
        ssl_contexts_.emplace_back(std::make_shared<asio::ssl::context>(asio::ssl::context::tls));
        ssl_contexts_.back()->set_options(
                        asio::ssl::context::default_workarounds
                        | asio::ssl::context::no_sslv2
                        | asio::ssl::context::no_sslv3
                          | asio::ssl::context::single_dh_use);
        ssl_contexts_.back()->use_certificate_chain_file(ssl_cert_file);
        ssl_contexts_.back()->use_private_key_file(ssl_key_file, asio::ssl::context::pem);
        SSL_CTX_set_alpn_select_cb(ssl_contexts_.back()->native_handle(), alpn_select_proto_cb, nullptr);
        //ssl_contexts_.back()->use_tmp_dh_file(ssl_dh_file);
        auto tcp_port = std::make_shared<TcpPort>(thread_pool_->get_io_context(), port_number, connection_context_template, ssl_contexts_.back().get());
        ports_.push_back(tcp_port);
    }

    template< typename SenderFramingType, typename ReceiverFramingType>
    void addUdpPort(unsigned short port_number, std::shared_ptr<SessionContext>& connection_context) {
        auto udp_port = std::make_shared<UdpPort<SenderFramingType, ReceiverFramingType>>(thread_pool_->get_io_context(), port_number,connection_context);
        ports_.push_back(udp_port);
    }

    void start() {
        for (auto& port : ports_) {
            port->start();
        }
        thread_pool_->start_threads();
    }

    void stop() {
        for (auto& port : ports_) {
            port->stop();
        }
        thread_pool_->stop();
    }

private:
    static int alpn_select_proto_cb(SSL *ssl, const unsigned char **out,
                                        unsigned char *outlen, const unsigned char *in,
                                        unsigned int inlen, void *arg)
    {
        int rv = nghttp2_select_next_protocol((unsigned char **) out, outlen, in, inlen);
        if (rv != 1)
        {
            return SSL_TLSEXT_ERR_NOACK;
        }
        return SSL_TLSEXT_ERR_OK;
    }
    std::vector<std::shared_ptr<asio::ssl::context>> ssl_contexts_;
    std::shared_ptr<AsioThreadPool> thread_pool_;
    std::vector<std::shared_ptr<Port>> ports_;
    Config config_;
};
