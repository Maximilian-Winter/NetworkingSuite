//
// Created by maxim on 24.09.2024.
//
#pragma once
#include <SessionContext.h>

class SessionContextTemplate
{
public:
    using ConnectedCallback = SessionContext::ConnectedCallback;
    using ClosedCallback = SessionContext::ClosedCallback;
    using ErrorHandler = SessionContext::ErrorHandler;
    using MessageHandler = SessionContext::MessageHandler;
    using WritePreProcessor = SessionContext::WritePreProcessor;
    using ReadPostProcessor = SessionContext::ReadPostProcessor;
    using CheckMessageState = SessionContext::CheckMessageState;
    using ReadCompletionHandler = SessionContext::ReadCompletionHandler;
    using WriteCompletionHandler = SessionContext::WriteCompletionHandler;

    SessionContextTemplate();

    // Setters for all properties
    void set_connected_callback(ConnectedCallback callback);

    void set_closed_callback(ClosedCallback callback);

    void set_error_handler(ErrorHandler handler);

    void set_message_handler(MessageHandler handler);

    void set_write_preprocessor(WritePreProcessor preprocessor);

    void set_read_postprocessor(ReadPostProcessor postprocessor);

    void set_check_message_state(CheckMessageState checker);

    void set_read_completion_handler(ReadCompletionHandler handler);

    void set_write_completion_handler(WriteCompletionHandler handler);

    void set_http2(bool is_http2);

    [[nodiscard]] bool is_http2() const;

    // Create a SessionContext instance based on the template
    [[nodiscard]] std::unique_ptr<SessionContext> create_instance() const;

private:
    bool is_http2_{};
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
