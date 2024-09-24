//
// Created by maxim on 24.09.2024.
//
#include "SessionContext.h"

#include <NetworkSession.h>

SessionContext::SessionContext() = default;

SessionContext::~SessionContext() = default;

SessionContext::SessionContext(const SessionContext &other) = default;

SessionContext::SessionContext(SessionContext &&other) noexcept: network_session_(std::move(other.network_session_)),
                                                                 connected_callback_(std::move(other.connected_callback_)),
                                                                 closed_callback_(std::move(other.closed_callback_)),
                                                                 error_handler_(std::move(other.error_handler_)),
                                                                 message_handler_(std::move(other.message_handler_)),
                                                                 write_preprocessor_(std::move(other.write_preprocessor_)),
                                                                 read_postprocessor_(std::move(other.read_postprocessor_)),
                                                                 message_state_check_(std::move(other.message_state_check_))
{
}

SessionContext & SessionContext::operator=(const SessionContext &other)
{
    if (this == &other)
        return *this;
    network_session_ = other.network_session_;
    connected_callback_ = other.connected_callback_;
    closed_callback_ = other.closed_callback_;
    message_handler_ = other.message_handler_;
    write_preprocessor_ = other.write_preprocessor_;
    read_postprocessor_ = other.read_postprocessor_;
    error_handler_ = other.error_handler_;
    message_state_check_ = other.message_state_check_;
    return *this;
}

SessionContext & SessionContext::operator=(SessionContext &&other) noexcept
{
    if (this == &other)
        return *this;
    network_session_ = std::move(other.network_session_);
    connected_callback_ = std::move(other.connected_callback_);
    closed_callback_ = std::move(other.closed_callback_);
    message_handler_ = std::move(other.message_handler_);
    write_preprocessor_ = std::move(other.write_preprocessor_);
    read_postprocessor_ = std::move(other.read_postprocessor_);
    error_handler_ = std::move(other.error_handler_);
    message_state_check_ = std::move(other.message_state_check_);
    return *this;
}

void SessionContext::set_session(std::weak_ptr<NetworkSession> port)
{
    network_session_ = std::move(port);
}

void SessionContext::set_connected_callback(ConnectedCallback callback)
{
    connected_callback_ = std::move(callback);
}

void SessionContext::set_closed_callback(ClosedCallback callback)
{
    closed_callback_ = std::move(callback);
}

void SessionContext::set_error_handler(ErrorHandler handler)
{
    error_handler_ = std::move(handler);
}

void SessionContext::set_message_handler(MessageHandler handler)
{
    message_handler_ = std::move(handler);
}

void SessionContext::set_write_preprocessor(WritePreProcessor write_preprocessor)
{
    write_preprocessor_ = std::move(write_preprocessor);
}

void SessionContext::set_read_postprocessor(ReadPostProcessor read_post_processor)
{
    read_postprocessor_ = std::move(read_post_processor);
}

void SessionContext::set_check_message_state_handler(CheckMessageState message_state_check)
{
    message_state_check_ = std::move(message_state_check);
}

void SessionContext::set_read_completion_handler(ReadCompletionHandler read_completion_handler)
{
    read_completion_handler_ = std::move(read_completion_handler);
}

void SessionContext::set_write_completion_handler(WriteCompletionHandler write_completion_handler)
{
    write_completion_handler_ = std::move(write_completion_handler);
}

void SessionContext::on_connect()
{
    if (connected_callback_)
    {
        connected_callback_(std::shared_ptr(network_session_));
    }
}

void SessionContext::on_close() const
{
    if (closed_callback_)
    {
        closed_callback_(std::shared_ptr(network_session_));
    }
}

void SessionContext::on_message(const ByteVector &data)
{
    if (message_handler_)
    {
        message_handler_(std::shared_ptr(network_session_), data);
    }
}

void SessionContext::on_error(const std::error_code &ec, const std::string &what) const
{
    if (error_handler_)
    {
        error_handler_(std::shared_ptr(network_session_), ec, what);
    }
}

ByteVector SessionContext::write_preprocess(const ByteVector &buffer) const
{
    return write_preprocessor_ ? write_preprocessor_(buffer) : buffer;
}

MessageState SessionContext::check_message_state(const ByteVector &buffer) const
{
    return message_state_check_ ? message_state_check_(buffer) : MessageState::VALID;
}

ByteVector SessionContext::extract_message(ByteVector &buffer) const
{
    return read_postprocessor_ ? read_postprocessor_(buffer) : buffer;
}

void SessionContext::read_completion_handler(ByteVector &buffer, const asio::error_code &ec,
    std::size_t bytes_transferred, const SessionDoRead &do_read_function)
{
    if (read_completion_handler_)
    {
        read_completion_handler_(std::shared_ptr(network_session_), ec, bytes_transferred, buffer, do_read_function);
    }
}

void SessionContext::write_completion_handler(const asio::error_code &ec, std::size_t bytes_transferred,
    const SessionDoWrite &do_write_function) const
{
    if (write_completion_handler_)
    {
        write_completion_handler_(std::shared_ptr(network_session_), ec, bytes_transferred, do_write_function);
    }
}

bool SessionContext::has_read_completion_handler() const
{
    if(read_completion_handler_)
    {
        return true;
    }
    return false;
}

bool SessionContext::has_write_completion_handler() const
{
    if(write_completion_handler_)
    {
        return true;
    }
    return false;
}
