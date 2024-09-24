//
// Created by maxim on 09.09.2024.
//
#pragma once
#include <string>
#include <system_error>

#include "BufferPool.h"
#include <utility>
#include <asio/error_code.hpp>


class NetworkSession;
using ByteVector = std::vector<uint8_t>;

// Enum for different message states
enum class MessageState
{
    INVALID, // Should be returned by check_message_state when buffer contains an invalid message
    INCOMPLETE,
    // Should be returned by check_message_state when buffer contains an incomplete message and more data is needed
    VALID // Should be returned by check_message_state when buffer contains a complete message that can be extracted
};


class MessageFraming
{
public:
    virtual ~MessageFraming() = default;

    // Frame a message for sending
    [[nodiscard]] virtual ByteVector frame_message(const ByteVector &message) = 0;

    // Extract the next complete message from the buffer and returns it (Will remove the message from the buffer)
    virtual ByteVector extract_next_message(ByteVector &buffer) = 0;

    // Check the message state based on the content of the buffer
    [[nodiscard]] virtual MessageState check_message_state(const ByteVector &buffer) const = 0;
};


class SessionContext
{
public:
    using ConnectedCallback = std::function<void(const std::shared_ptr<NetworkSession> &session)>;
    using ClosedCallback = std::function<void(const std::shared_ptr<NetworkSession> &session)>;
    using ErrorHandler = std::function<void(const std::shared_ptr<NetworkSession> &session, const std::error_code &ec,
                                            const std::string &what)>;
    using MessageHandler = std::function<void(const std::shared_ptr<NetworkSession> &session, const ByteVector &)>;
    using WritePreProcessor = std::function<ByteVector(const ByteVector &)>;
    using ReadPostProcessor = std::function<ByteVector(ByteVector &)>;
    using CheckMessageState = std::function<MessageState(const ByteVector &)>;

    using SessionDoRead = std::function<void()>;
    using SessionDoWrite = std::function<void()>;

    using ReadCompletionHandler = std::function<void(const std::shared_ptr<NetworkSession> &session,
                                                     const asio::error_code &ec, std::size_t bytes_transferred,
                                                     ByteVector &buffer, SessionDoRead do_read_function)>;
    using WriteCompletionHandler = std::function<void(const std::shared_ptr<NetworkSession> &session,
                                                      const asio::error_code &ec, std::size_t bytes_written,
                                                      SessionDoWrite do_write_function)>;

    SessionContext();

    virtual ~SessionContext();

    SessionContext(const SessionContext &other);

    SessionContext(SessionContext &&other) noexcept;

    SessionContext &operator=(const SessionContext &other);

    SessionContext &operator=(SessionContext &&other) noexcept;

    virtual void set_session(std::weak_ptr<NetworkSession> port);

    void set_connected_callback(ConnectedCallback callback);

    void set_closed_callback(ClosedCallback callback);

    void set_error_handler(ErrorHandler handler);

    void set_message_handler(MessageHandler handler);

    void set_write_preprocessor(WritePreProcessor write_preprocessor);

    void set_read_postprocessor(ReadPostProcessor read_post_processor);

    void set_check_message_state_handler(CheckMessageState message_state_check);

    void set_read_completion_handler(ReadCompletionHandler read_completion_handler);

    void set_write_completion_handler(WriteCompletionHandler write_completion_handler);

    virtual void on_connect();

    virtual void on_close() const;

    virtual void on_message(const ByteVector &data);


    virtual void on_error(const std::error_code &ec, const std::string &what) const;

    [[nodiscard]] virtual ByteVector write_preprocess(const ByteVector &buffer) const;

    [[nodiscard]] virtual MessageState check_message_state(const ByteVector &buffer) const;

    virtual ByteVector extract_message(ByteVector &buffer) const;

    virtual void read_completion_handler(ByteVector &buffer, const asio::error_code &ec, std::size_t bytes_transferred,
                                         const SessionDoRead &do_read_function);

    virtual void write_completion_handler(const asio::error_code &ec, std::size_t bytes_transferred,
                                          const SessionDoWrite &do_write_function) const;

    [[nodiscard]] virtual bool has_read_completion_handler() const;

    [[nodiscard]] virtual bool has_write_completion_handler() const;

protected:
    std::weak_ptr<NetworkSession> network_session_{};

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



