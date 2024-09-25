//
// Created by maxim on 24.09.2024.
//
#include "SessionContextTemplate.h"
#include "Http2SessionContext.h"

SessionContextTemplate::SessionContextTemplate() = default;

void SessionContextTemplate::set_connected_callback(ConnectedCallback callback)
{ connected_callback_ = std::move(callback); }

void SessionContextTemplate::set_closed_callback(ClosedCallback callback)
{ closed_callback_ = std::move(callback); }

void SessionContextTemplate::set_error_handler(ErrorHandler handler)
{ error_handler_ = std::move(handler); }

void SessionContextTemplate::set_message_handler(MessageHandler handler)
{ message_handler_ = std::move(handler); }

void SessionContextTemplate::set_write_preprocessor(WritePreProcessor preprocessor)
{ write_preprocessor_ = std::move(preprocessor); }

void SessionContextTemplate::set_read_postprocessor(ReadPostProcessor postprocessor)
{ read_postprocessor_ = std::move(postprocessor); }

void SessionContextTemplate::set_check_message_state(CheckMessageState checker)
{ message_state_check_ = std::move(checker); }

void SessionContextTemplate::set_read_completion_handler(ReadCompletionHandler handler)
{ read_completion_handler_ = std::move(handler); }

void SessionContextTemplate::set_write_completion_handler(WriteCompletionHandler handler)
{
    write_completion_handler_ = std::move(handler);
}

void SessionContextTemplate::set_http2_request_handler(RequestHandler handler)
{
    request_handler_ = std::move(handler);
}

void SessionContextTemplate::set_http2(bool use_http2)
{ this->is_http2_ = use_http2; }

bool SessionContextTemplate::is_http2() const
{ return is_http2_; }

std::unique_ptr<SessionContext> SessionContextTemplate::create_instance() const
{

    if (is_http2_)
    {
         std::unique_ptr<Http2SessionContext> context_ = std::make_unique<Http2SessionContext>();
        context_->set_request_handler(request_handler_);
        return std::move(context_);
    }
    std::unique_ptr<SessionContext> context = nullptr;
    context = std::make_unique<SessionContext>();
    if (connected_callback_) context->set_connected_callback(connected_callback_);
    if (closed_callback_) context->set_closed_callback(closed_callback_);
    if (error_handler_) context->set_error_handler(error_handler_);
    if (message_handler_) context->set_message_handler(message_handler_);
    if (write_preprocessor_) context->set_write_preprocessor(write_preprocessor_);
    if (read_postprocessor_) context->set_read_postprocessor(read_postprocessor_);
    if (message_state_check_) context->set_check_message_state_handler(message_state_check_);
    if (read_completion_handler_) context->set_read_completion_handler(read_completion_handler_);
    if (write_completion_handler_) context->set_write_completion_handler(write_completion_handler_);

    return context;
}
