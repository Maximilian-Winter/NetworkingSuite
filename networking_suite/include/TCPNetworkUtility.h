#pragma once

#include <asio/ssl.hpp>
#include <asio.hpp>
#include <functional>
#include <memory>
#include <atomic>
#include <utility>
#include <SessionContext.h>

#include "BufferPool.h"
#include "Logger.h"
#include "TCPMessageFraming.h"
#include "Utilities.h"


class TCPNetworkUtility {
public:

    template< typename SenderFramingType, typename ReceiverFramingType>
    class Session : public std::enable_shared_from_this<Session<SenderFramingType, ReceiverFramingType>> {
    protected:
        asio::ip::tcp::socket socket_;
        std::string sessionUuid_;
        asio::strand<asio::io_context::executor_type> strand_;
        std::shared_ptr<BufferPool> buffer_pool_;
        LockFreeQueue<ByteVector*, 1024> write_queue_;
        std::atomic<bool> is_closed_{false};
        SessionContext<Session, SenderFramingType, ReceiverFramingType> connection_context_;
        ByteVector read_buffer_;

    public:
        virtual ~Session() = default;

        auto get_shared_this() {
            return this->shared_from_this();
        }
        explicit Session(asio::io_context& io_context)
            : socket_(io_context),
              strand_(asio::make_strand(io_context)),
              buffer_pool_(std::make_shared<BufferPool>(32728)),
              sessionUuid_(Utilities::generateUuid())
        {
            read_buffer_.reserve(buffer_pool_->getBufferSize());
        }

        void start(const SessionContext<Session, SenderFramingType, ReceiverFramingType>& connection_context) {
            connection_context_ = connection_context;
            connection_context_.set_port(get_shared_this());
            connection_context_.on_connect();
            do_read();
        }

        bool is_closed() const { return is_closed_.load(std::memory_order_acquire); }

        asio::ip::tcp::socket& socket() { return socket_; }

        std::string getSessionUuid() { return sessionUuid_; }

        void write(const ByteVector& message) {
            if (is_closed()) {
                return;
            }

            ByteVector* buffer = buffer_pool_->acquire();
            *buffer = connection_context_.preprocess_write(message);

            asio::post(strand_, [this, buffer]() {
                write_queue_.push(buffer);
                if (write_queue_.size() == 1) {
                    do_write();
                }
            });
        }

        void close() {
            asio::post(strand_, [this, self = get_shared_this()]() {
                do_close();
            });
        }

    protected:
        virtual void do_read() {
            auto read_buffer = buffer_pool_->acquire();
            socket_.async_read_some(
                asio::buffer(*read_buffer),
                asio::bind_executor(strand_, [this, self = get_shared_this(), read_buffer](
                    const asio::error_code& ec, std::size_t bytes_transferred) {
                    if (!ec) {
                        read_buffer->resize(bytes_transferred);
                        process_read_data(*read_buffer);
                        do_read();
                    } else if (ec != asio::error::operation_aborted) {
                        LOG_DEBUG("Error in read: %s", ec.message().c_str());
                        close();
                    }
                    buffer_pool_->release(read_buffer);
                }));
        }

        void process_read_data(const ByteVector& new_data) {
            read_buffer_.insert(read_buffer_.end(), new_data.begin(), new_data.end());

            while (true) {
                if (connection_context_.checkIfIsCompleteMessage(read_buffer_)) {
                    ByteVector message = connection_context_.postprocess_read(read_buffer_);
                    size_t message_size = read_buffer_.size();
                    read_buffer_.erase(read_buffer_.begin(), read_buffer_.begin() + static_cast<int>(message_size));

                    connection_context_.on_message(message);
                } else {
                    break;
                }
            }

            if (read_buffer_.size() > buffer_pool_->getBufferSize()) {
                LOG_WARNING("Read buffer overflow, discarding old data");
                read_buffer_.erase(read_buffer_.begin(), read_buffer_.end() - static_cast<int>(buffer_pool_->getBufferSize()));
            }
        }

        virtual void do_write() {
            if (is_closed()) {
                return;
            }

            auto buffer = write_queue_.pop();
            if (!buffer) {
                return;
            }

            asio::async_write(socket_, asio::buffer(**buffer),
                asio::bind_executor(strand_, [this, self = get_shared_this(), buffer](
                    const asio::error_code& ec, std::size_t bytes_written) {
                    buffer_pool_->release(*buffer);

                    if (!ec) {
                        LOG_DEBUG("Wrote %zu bytes", bytes_written);
                        if (!write_queue_.empty()) {
                            do_write();
                        }
                    } else if (ec != asio::error::operation_aborted) {
                        LOG_DEBUG("Error in write: %s", ec.message().c_str());
                        close();
                    }
                }));
        }

        void do_close()
        {
            if (is_closed_.exchange(true, std::memory_order_acq_rel)) {
                return;
            }
            // Clear the write queue
            while (auto opt_buffer = write_queue_.pop()) {
                buffer_pool_->release(*opt_buffer);
            }

            if (!socket_.is_open())
            {
                connection_context_.on_close();
                return; // Socket is already closed
            }

            std::error_code ec;

            // Cancel any pending asynchronous operations
            socket_.cancel(ec);
            if (ec)
            {
                LOG_ERROR("Error cancelling pending operations: %s", ec.message().c_str());
            }

            // Shutdown the socket
            socket_.shutdown(asio::ip::tcp::socket::shutdown_both, ec);
            if (ec && ec != asio::error::not_connected)
            {
                LOG_ERROR("Error shutting down socket: %s", ec.message().c_str());
            }

            // Close the socket
            socket_.close(ec);
            if (ec)
            {
                LOG_ERROR("Error closing socket: %s", ec.message().c_str());
            }

            connection_context_.on_close();
        }
    };
    template< typename SenderFramingType, typename ReceiverFramingType>
    static std::shared_ptr<Session<SenderFramingType, ReceiverFramingType>> createSession(asio::io_context& io_context, asio::ip::tcp::socket& socket) {
        auto session = std::make_shared<Session<SenderFramingType, ReceiverFramingType>>(io_context);
        session->socket() = std::move(socket);
        return session;
    }
    template< typename SenderFramingType, typename ReceiverFramingType>
    static std::shared_ptr<Session<SenderFramingType, ReceiverFramingType>> connect(
        asio::io_context& io_context,
        const std::string& host,
        const std::string& port,
        const SessionContext<Session<SenderFramingType, ReceiverFramingType>, SenderFramingType, ReceiverFramingType>& connection_context) {

        auto session = std::make_shared<Session<SenderFramingType, ReceiverFramingType>>(io_context);

        asio::ip::tcp::resolver resolver(io_context);
        auto endpoints = resolver.resolve(host, port);

        asio::async_connect(session->socket(), endpoints,
            [session, connection_context](const std::error_code& ec, const asio::ip::tcp::endpoint&) {
                if (!ec) {
                    session->start(connection_context);
                }
            });

        return session;
    }





};