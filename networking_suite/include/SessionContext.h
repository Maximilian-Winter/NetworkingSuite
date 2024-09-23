//
// Created by maxim on 09.09.2024.
//
#pragma once
#include "BufferPool.h"
#include <utility>


using ByteVector = std::vector<uint8_t>;

// Enum for different message states
enum class MessageState
{
    INVALID,        // Should be returned by check_message_state when buffer contains an invalid message
    INCOMPLETE,     // Should be returned by check_message_state when buffer contains an incomplete message and more data is needed
    FINISHED        // Should be returned by check_message_state when buffer contains a complete message that can be extracted
};


class MessageFraming
{
public:
    virtual ~MessageFraming() = default;

    // Frame a message for sending
    [[nodiscard]] virtual ByteVector frame_message(const ByteVector& message) = 0;

    // Extract the next complete message from the buffer and returns it (Will remove the message from the buffer)
    virtual ByteVector extract_next_message(ByteVector& buffer) = 0;

    // Check the message state based on the content of the buffer
    [[nodiscard]] virtual MessageState check_message_state(const ByteVector& buffer) const = 0;
};


class NetworkSession;

class SessionContext
{
public:
    using ConnectedCallback = std::function<void(const std::shared_ptr<NetworkSession> &session)>;
    using ClosedCallback = std::function<void(const std::shared_ptr<NetworkSession> &session)>;
    using ErrorHandler = std::function<void(const std::shared_ptr<NetworkSession> &session, const std::error_code &ec, const std::string &what)>;
    using MessageHandler = std::function<void(const std::shared_ptr<NetworkSession> &session, const ByteVector &)>;
    using WritePreProcessor = std::function<ByteVector(const ByteVector &)>;
    using ReadPostProcessor = std::function<ByteVector(ByteVector &)>;
    using CheckMessageState = std::function<MessageState(const ByteVector&)>;

    using SessionDoRead = std::function<void()>;
    using SessionDoWrite = std::function<void()>;

    using ReadCompletionHandler = std::function<void(const std::shared_ptr<NetworkSession> &session, const asio::error_code &ec, std::size_t bytes_transferred, ByteVector& buffer, SessionDoRead do_read_function)>;
    using WriteCompletionHandler = std::function<void(const std::shared_ptr<NetworkSession> &session, const asio::error_code &ec, std::size_t bytes_written, SessionDoWrite do_write_function)>;

    SessionContext() = default;
    ~SessionContext() = default;

    SessionContext(const SessionContext &other) = default;

    SessionContext(SessionContext &&other) noexcept
        : session_(std::move(other.session_)),
          connected_callback_(std::move(other.connected_callback_)),
          closed_callback_(std::move(other.closed_callback_)),
          error_handler_(std::move(other.error_handler_)),
          message_handler_(std::move(other.message_handler_)),
          write_preprocessor_(std::move(other.write_preprocessor_)),
          read_postprocessor_(std::move(other.read_postprocessor_)),
          message_state_check_(std::move(other.message_state_check_))
    {
    }

    SessionContext & operator=(const SessionContext &other)
    {
        if (this == &other)
            return *this;
        session_ = other.session_;
        connected_callback_ = other.connected_callback_;
        closed_callback_ = other.closed_callback_;
        message_handler_ = other.message_handler_;
        write_preprocessor_ = other.write_preprocessor_;
        read_postprocessor_ = other.read_postprocessor_;
        error_handler_ = other.error_handler_;
        message_state_check_ = other.message_state_check_;
        return *this;
    }

    SessionContext & operator=(SessionContext &&other) noexcept
    {
        if (this == &other)
            return *this;
        session_ = std::move(other.session_);
        connected_callback_ = std::move(other.connected_callback_);
        closed_callback_ = std::move(other.closed_callback_);
        message_handler_ = std::move(other.message_handler_);
        write_preprocessor_ = std::move(other.write_preprocessor_);
        read_postprocessor_ = std::move(other.read_postprocessor_);
        error_handler_ = std::move(other.error_handler_);
        message_state_check_ = std::move(other.message_state_check_);
        return *this;
    }

    void set_session(std::shared_ptr<NetworkSession> port)
    {
        session_ = std::move(port);
    }

    void set_connected_callback(ConnectedCallback callback)
    {
        connected_callback_ = std::move(callback);
    }

    void set_closed_callback(ClosedCallback callback)
    {
        closed_callback_ = std::move(callback);
    }

    void set_error_handler(ErrorHandler handler)
    {
        error_handler_ = std::move(handler);
    }
    void set_message_handler(MessageHandler handler)
    {
        message_handler_ = std::move(handler);
    }

    void set_write_preprocessor(WritePreProcessor write_preprocessor)
    {
        write_preprocessor_ = std::move(write_preprocessor);
    }

    void set_read_postprocessor(ReadPostProcessor read_post_processor)
    {
        read_postprocessor_ = std::move(read_post_processor);
    }

    void set_check_message_state_handler(CheckMessageState message_state_check)
    {
        message_state_check_ = std::move(message_state_check);
    }

    void set_read_completion_handler(ReadCompletionHandler read_completion_handler)
    {
        read_completion_handler_ = std::move(read_completion_handler);
    }

    void set_write_completion_handler(WriteCompletionHandler write_completion_handler)
    {
        write_completion_handler_ = std::move(write_completion_handler);
    }

    void on_connect() const
    {
        if (connected_callback_)
        {
            connected_callback_(session_);
        }
    }

    void on_close() const
    {
        if (closed_callback_)
        {
            closed_callback_(session_);
        }
    }

    void on_message(const ByteVector &data) const
    {
        if (message_handler_)
        {
            message_handler_(session_, data);
        }
    }


    void on_error(const std::error_code &ec, const std::string &what) const
    {
        if (error_handler_)
        {
            error_handler_(session_, ec, what);
        }
    }

    [[nodiscard]] ByteVector write_preprocess(const ByteVector &buffer) const
    {
        return write_preprocessor_ ? write_preprocessor_(buffer) : buffer;
    }

    [[nodiscard]] MessageState check_message_state(const ByteVector &buffer) const
    {
        return message_state_check_ ? message_state_check_(buffer) : MessageState::FINISHED;
    }

    ByteVector extract_message(ByteVector &buffer) const
    {
        return read_postprocessor_ ? read_postprocessor_(buffer) : buffer;
    }

    void read_completion_handler(ByteVector& buffer, const asio::error_code &ec, std::size_t bytes_transferred, const SessionDoRead& do_read_function) const
    {
        if (read_completion_handler_)
        {
            read_completion_handler_(session_, ec, bytes_transferred, buffer, do_read_function);
        }
    }

    void write_completion_handler(const asio::error_code &ec, std::size_t bytes_transferred, const SessionDoWrite& do_write_function) const
    {
        if (write_completion_handler_)
        {
            write_completion_handler_(session_, ec, bytes_transferred, do_write_function);
        }
    }

    [[nodiscard]] ReadCompletionHandler get_read_completion_handler() const
    {
        return read_completion_handler_;
    }

    [[nodiscard]] WriteCompletionHandler get_write_completion_handler() const
    {
        return write_completion_handler_;
    }
private:
    std::shared_ptr<NetworkSession> session_{};

    ConnectedCallback connected_callback_{};
    ClosedCallback closed_callback_{};

    ErrorHandler error_handler_{};
    MessageHandler message_handler_{};

    WritePreProcessor write_preprocessor_{};
    ReadPostProcessor read_postprocessor_{};

    CheckMessageState message_state_check_{};

    ReadCompletionHandler read_completion_handler_{};
    WriteCompletionHandler write_completion_handler_{};
};

