#include <utility>

//
// Created by maxim on 09.09.2024.
//
#pragma once

using ByteVector = std::vector<uint8_t>;

class MessageFraming
{
public:
    virtual ~MessageFraming() = default;

    // Frame a message for sending
    [[nodiscard]] virtual ByteVector frameMessage(const ByteVector& message) = 0;

    // Process incoming data and extract complete messages
    virtual ByteVector process_next_message(ByteVector& buffer) = 0;

    // Check if the buffer contains a complete message
    [[nodiscard]] virtual bool hasCompleteMessage(const ByteVector& buffer) const = 0;

    // Get the number of bytes needed to start parsing the next message
    [[nodiscard]] virtual size_t getBytesNeededForNextMessage(const ByteVector& buffer) const = 0;

    // Reset the internal state of the framing mechanism
    virtual void reset() = 0;

    // Check if the framing mechanism is in an error state
    [[nodiscard]] virtual bool isInErrorState() const = 0;

    // Get an error message if in an error state
    [[nodiscard]] virtual std::string getErrorMessage() const = 0;

protected:
    // Helper method to extract a single message from the buffer
    virtual ByteVector extractSingleMessage(ByteVector& buffer) = 0;
};

enum class MessageState
{
    INVALID,
    NEEDS_MORE_DATA,
    FINISHED
};

class NetworkSession;

class SessionContext
{
public:
    using ConnectedCallback = std::function<void(const std::shared_ptr<NetworkSession> &port)>;
    using ClosedCallback = std::function<void(const std::shared_ptr<NetworkSession> &port)>;
    using ErrorHandler = std::function<void(const std::shared_ptr<NetworkSession> &port, const std::error_code &ec, const std::string &what)>;
    using MessageHandler = std::function<void(const std::shared_ptr<NetworkSession> &port, const ByteVector &)>;
    using WritePreProcessor = std::function<ByteVector(const ByteVector &)>;
    using ReadPostProcessor = std::function<ByteVector(ByteVector &)>;
    using CheckMessageState = std::function<MessageState(const ByteVector&)>;

    virtual ~SessionContext() = default;

    virtual void set_session(std::shared_ptr<NetworkSession> session) = 0;

    virtual void on_connect() = 0;

    virtual void on_close() = 0;

    virtual void on_error(const std::error_code &ec, const std::string &what) = 0;

    virtual void on_message(const ByteVector& message) = 0;

    virtual ByteVector write_preprocess(const ByteVector& buffer) = 0;

    virtual MessageState check_message_state(const ByteVector& buffer) = 0;

    virtual ByteVector extract_message(ByteVector& buffer) = 0;
};

class DefaultSessionContext final : public SessionContext
{
public:
    DefaultSessionContext() = default;
    ~DefaultSessionContext() override = default;

    DefaultSessionContext(const DefaultSessionContext &other)
        : session_(other.session_),
          connected_callback_(other.connected_callback_),
          closed_callback_(other.closed_callback_),
          message_handler_(other.message_handler_),
          write_preprocessor_(other.write_preprocessor_),
          read_postprocessor_(other.read_postprocessor_),
          error_handler_(other.error_handler_),
          message_state_check_(other.message_state_check_)
    {
    }

    DefaultSessionContext(DefaultSessionContext &&other) noexcept
        : session_(std::move(other.session_)),
          connected_callback_(std::move(other.connected_callback_)),
          closed_callback_(std::move(other.closed_callback_)),
          message_handler_(std::move(other.message_handler_)),
          write_preprocessor_(std::move(other.write_preprocessor_)),
          read_postprocessor_(std::move(other.read_postprocessor_)),
          error_handler_(std::move(other.error_handler_)),
          message_state_check_(std::move(other.message_state_check_))
    {
    }

    DefaultSessionContext & operator=(const DefaultSessionContext &other)
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

    DefaultSessionContext & operator=(DefaultSessionContext &&other) noexcept
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

    void set_message_check(CheckMessageState message_state_check)
    {
        message_state_check_ = std::move(message_state_check);
    }

    void set_session(std::shared_ptr<NetworkSession> port) override
    {
        session_ = std::move(port);
    }

    void on_connect() override
    {
        if (connected_callback_)
        {
            connected_callback_(session_);
        }
    }

    void on_close() override
    {
        if (closed_callback_)
        {
            closed_callback_(session_);
        }
    }

    void on_message(const ByteVector &data) override
    {
        if (message_handler_)
        {
            message_handler_(session_, data);
        }
    }


    void on_error(const std::error_code &ec, const std::string &what) override
    {
        if (error_handler_)
        {
            error_handler_(session_, ec, what);
        }
    }

    ByteVector write_preprocess(const ByteVector &buffer) override
    {
        return write_preprocessor_ ? write_preprocessor_(buffer) : buffer;
    }

    MessageState check_message_state(const ByteVector &buffer) override
    {
        return message_state_check_ ? message_state_check_(buffer) : MessageState::FINISHED;
    }

    ByteVector extract_message(ByteVector &buffer) override
    {
        return read_postprocessor_ ? read_postprocessor_(buffer) : buffer;
    }

private:
    std::shared_ptr<NetworkSession> session_{};
    ConnectedCallback connected_callback_{};
    ClosedCallback closed_callback_{};
    MessageHandler message_handler_{};

    WritePreProcessor write_preprocessor_;
    ReadPostProcessor read_postprocessor_;

    ErrorHandler error_handler_{};

    CheckMessageState message_state_check_;
};

