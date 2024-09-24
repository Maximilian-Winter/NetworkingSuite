//
// Created by maxim on 23.09.2024.
//
#pragma once
using ssize_t = size_t;
#include <nghttp2/nghttp2.h>
#include <functional>
#include <memory>
#include <string>
#include <vector>
#include <unordered_map>

class Http2Session;

class Http2SessionContext {
public:
    using ConnectedCallback = std::function<void(const std::shared_ptr<Http2Session>&)>;
    using ClosedCallback = std::function<void(const std::shared_ptr<Http2Session>&)>;
    using DataReceivedCallback = std::function<void(const std::shared_ptr<Http2Session>&, const uint8_t*, size_t)>;
    using StreamBeginCallback = std::function<void(const std::shared_ptr<Http2Session>&, int32_t)>;
    using HeaderReceivedCallback = std::function<void(const std::shared_ptr<Http2Session>&, int32_t, const std::string&, const std::string&)>;
    using StreamEndCallback = std::function<void(const std::shared_ptr<Http2Session>&, int32_t)>;
    using ErrorCallback = std::function<void(const std::shared_ptr<Http2Session>&, const std::string&)>;

    void set_connected_callback(ConnectedCallback callback) { connected_callback_ = std::move(callback); }
    void set_closed_callback(ClosedCallback callback) { closed_callback_ = std::move(callback); }
    void set_data_received_callback(DataReceivedCallback callback) { data_received_callback_ = std::move(callback); }
    void set_stream_begin_callback(StreamBeginCallback callback) { stream_begin_callback_ = std::move(callback); }
    void set_header_received_callback(HeaderReceivedCallback callback) { header_received_callback_ = std::move(callback); }
    void set_stream_end_callback(StreamEndCallback callback) { stream_end_callback_ = std::move(callback); }
    void set_error_callback(ErrorCallback callback) { error_callback_ = std::move(callback); }

    void on_connect(const std::shared_ptr<Http2Session>& session) { if (connected_callback_) connected_callback_(session); }
    void on_close(const std::shared_ptr<Http2Session>& session) { if (closed_callback_) closed_callback_(session); }
    void on_data_received(const std::shared_ptr<Http2Session>& session, const uint8_t* data, size_t length) {
        if (data_received_callback_) data_received_callback_(session, data, length);
    }
    void on_stream_begin(const std::shared_ptr<Http2Session>& session, int32_t stream_id) {
        if (stream_begin_callback_) stream_begin_callback_(session, stream_id);
    }
    void on_header_received(const std::shared_ptr<Http2Session>& session, int32_t stream_id, const std::string& name, const std::string& value) {
        if (header_received_callback_) header_received_callback_(session, stream_id, name, value);
    }
    void on_stream_end(const std::shared_ptr<Http2Session>& session, int32_t stream_id) {
        if (stream_end_callback_) stream_end_callback_(session, stream_id);
    }
    void on_error(const std::shared_ptr<Http2Session>& session, const std::string& error_message) {
        if (error_callback_) error_callback_(session, error_message);
    }

private:
    ConnectedCallback connected_callback_;
    ClosedCallback closed_callback_;
    DataReceivedCallback data_received_callback_;
    StreamBeginCallback stream_begin_callback_;
    HeaderReceivedCallback header_received_callback_;
    StreamEndCallback stream_end_callback_;
    ErrorCallback error_callback_;
};

class Http2Session : public std::enable_shared_from_this<Http2Session> {
public:
    Http2Session(Http2SessionContext context) : context_(std::move(context)) {
        nghttp2_session_callbacks* callbacks;
        nghttp2_session_callbacks_new(&callbacks);

        nghttp2_session_callbacks_set_on_frame_recv_callback(callbacks, on_frame_recv_callback);
        nghttp2_session_callbacks_set_on_stream_close_callback(callbacks, on_stream_close_callback);
        nghttp2_session_callbacks_set_on_header_callback(callbacks, on_header_callback);
        nghttp2_session_callbacks_set_on_data_chunk_recv_callback(callbacks, on_data_chunk_recv_callback);
        nghttp2_session_callbacks_set_send_callback(callbacks, send_callback);

        nghttp2_session_server_new(&session_, callbacks, this);

        nghttp2_session_callbacks_del(callbacks);
    }

    ~Http2Session() {
        if (session_) {
            nghttp2_session_del(session_);
        }
    }

    void start() {
        nghttp2_settings_entry iv[1] = {
            {NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS, 100}
        };
        nghttp2_submit_settings(session_, NGHTTP2_FLAG_NONE, iv, 1);
        send();
        context_.on_connect(shared_from_this());
    }

    int receive(const uint8_t* data, size_t length) {
        ssize_t result = nghttp2_session_mem_recv(session_, data, length);
        if (result < 0) {
            context_.on_error(shared_from_this(), "Error receiving data: " + std::to_string(result));
            return -1;
        }
        send();
        return 0;
    }

    int send() {
        const uint8_t* data;
        ssize_t length;
        while ((length = nghttp2_session_mem_send(session_, &data)) > 0) {
            context_.on_data_received(shared_from_this(), data, length);
        }
        if (length < 0) {
            context_.on_error(shared_from_this(), "Error sending data: " + std::to_string(length));
            return -1;
        }
        return 0;
    }

    void submit_response(int32_t stream_id, const std::vector<nghttp2_nv>& headers, const std::string& body) {
        auto stream_data = std::make_unique<StreamData>();
        stream_data->body = body;

        nghttp2_data_provider data_provider;
        data_provider.source.ptr = stream_data.get();
        data_provider.read_callback = data_read_callback;

        int result = nghttp2_submit_response(session_, stream_id, headers.data(), headers.size(), &data_provider);
        if (result == 0) {
            streams_[stream_id] = std::move(stream_data);
        } else {
            context_.on_error(shared_from_this(), "Error submitting response: " + std::to_string(result));
        }
        send();
    }

private:
    static int on_frame_recv_callback(nghttp2_session* session, const nghttp2_frame* frame, void* user_data) {
        auto self = static_cast<Http2Session*>(user_data);
        if (frame->hd.type == NGHTTP2_HEADERS) {
            if (frame->headers.cat == NGHTTP2_HCAT_REQUEST) {
                self->context_.on_stream_begin(self->shared_from_this(), frame->hd.stream_id);
            }
        }
        return 0;
    }

    static int on_stream_close_callback(nghttp2_session* session, int32_t stream_id, uint32_t error_code, void* user_data) {
        auto self = static_cast<Http2Session*>(user_data);
        self->context_.on_stream_end(self->shared_from_this(), stream_id);
        self->streams_.erase(stream_id);
        return 0;
    }

    static int on_header_callback(nghttp2_session* session, const nghttp2_frame* frame,
                                  const uint8_t* name, size_t namelen,
                                  const uint8_t* value, size_t valuelen,
                                  uint8_t flags, void* user_data) {
        auto self = static_cast<Http2Session*>(user_data);
        if (frame->hd.type == NGHTTP2_HEADERS) {
            std::string header_name(reinterpret_cast<const char*>(name), namelen);
            std::string header_value(reinterpret_cast<const char*>(value), valuelen);
            self->context_.on_header_received(self->shared_from_this(), frame->hd.stream_id, header_name, header_value);
        }
        return 0;
    }

    static int on_data_chunk_recv_callback(nghttp2_session* session, uint8_t flags,
                                           int32_t stream_id, const uint8_t* data,
                                           size_t len, void* user_data) {
        // Handle received data chunks if needed
        return 0;
    }

    static ssize_t send_callback(nghttp2_session* session, const uint8_t* data,
                                 size_t length, int flags, void* user_data) {
        auto self = static_cast<Http2Session*>(user_data);
        self->context_.on_data_received(self->shared_from_this(), data, length);
        return static_cast<ssize_t>(length);
    }

    static ssize_t data_read_callback(nghttp2_session* session, int32_t stream_id,
                                      uint8_t* buf, size_t length, uint32_t* data_flags,
                                      nghttp2_data_source* source, void* user_data) {
        auto stream_data = static_cast<StreamData*>(source->ptr);
        if (stream_data->body.empty()) {
            *data_flags |= NGHTTP2_DATA_FLAG_EOF;
            return 0;
        }
        size_t to_copy = std::min(length, stream_data->body.size());
        std::memcpy(buf, stream_data->body.data(), to_copy);
        stream_data->body.erase(0, to_copy);
        if (stream_data->body.empty()) {
            *data_flags |= NGHTTP2_DATA_FLAG_EOF;
        }
        return static_cast<ssize_t>(to_copy);
    }

    struct StreamData {
        std::string body;
    };

    Http2SessionContext context_;
    nghttp2_session* session_;
    std::unordered_map<int32_t, std::unique_ptr<StreamData>> streams_;
};


class Http2SessionContext: SessionContext {
public:
    using DataReceivedCallback = std::function<void(const std::shared_ptr<NetworkSession>&, const uint8_t*, size_t)>;
    using StreamBeginCallback = std::function<void(const std::shared_ptr<NetworkSession>&, int32_t)>;
    using HeaderReceivedCallback = std::function<void(const std::shared_ptr<NetworkSession>&, int32_t, const std::string&, const std::string&)>;
    using StreamEndCallback = std::function<void(const std::shared_ptr<NetworkSession>&, int32_t)>;

    void set_connected_callback(ConnectedCallback callback) { connected_callback_ = std::move(callback); }
    void set_closed_callback(ClosedCallback callback) { closed_callback_ = std::move(callback); }
    void set_data_received_callback(DataReceivedCallback callback) { data_received_callback_ = std::move(callback); }
    void set_stream_begin_callback(StreamBeginCallback callback) { stream_begin_callback_ = std::move(callback); }
    void set_header_received_callback(HeaderReceivedCallback callback) { header_received_callback_ = std::move(callback); }
    void set_stream_end_callback(StreamEndCallback callback) { stream_end_callback_ = std::move(callback); }
    void set_error_callback(ErrorHandler callback) { error_callback_ = std::move(callback); }

    void on_connect() override { if (connected_callback_) connected_callback_(session_); }
    void on_close() override { if (closed_callback_) closed_callback_(session_); }
    void on_data_received(const uint8_t* data, size_t length) const
    {
        if (data_received_callback_) data_received_callback_(session_, data, length);
    }
    void on_stream_begin(int32_t stream_id) const
    {
        if (stream_begin_callback_) stream_begin_callback_(session_, stream_id);
    }
    void on_header_received(int32_t stream_id, const std::string& name, const std::string& value) const
    {
        if (header_received_callback_) header_received_callback_(session_, stream_id, name, value);
    }
    void on_stream_end(int32_t stream_id) const
    {
        if (stream_end_callback_) stream_end_callback_(session_, stream_id);
    }

    void set_session(std::shared_ptr<NetworkSession> session) override
    {
        session_ = std::move(session);
    }

    void on_error(const std::error_code &ec, const std::string &what) override
    {
        if (error_callback_) error_callback_(session_, ec, what);
    }

    ByteVector write_preprocess(const ByteVector &buffer) override
    {
        return write_preprocessor_ ? write_preprocessor_(buffer) : buffer;
    }

    MessageState check_message_state(const ByteVector &buffer) override
    {
        return message_state_check_ ? message_state_check_(buffer) : MessageState::FINISHED;
    }

    ByteVector extract_message(const ByteVector &buffer) override
    {
        return read_postprocessor_ ? read_postprocessor_(buffer) : buffer;
    }

private:
    std::shared_ptr<NetworkSession> session_{};
    MessageHandler message_handler_{};
    ConnectedCallback connected_callback_;
    ClosedCallback closed_callback_;
    DataReceivedCallback data_received_callback_;
    StreamBeginCallback stream_begin_callback_;
    HeaderReceivedCallback header_received_callback_;
    StreamEndCallback stream_end_callback_;
    ErrorHandler error_callback_;
    WritePreProcessor write_preprocessor_;
    ReadPostProcessor read_postprocessor_;
    CheckMessageState message_state_check_;
};