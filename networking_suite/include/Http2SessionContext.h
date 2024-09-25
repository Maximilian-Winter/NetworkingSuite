//
// Created by maxim on 24.09.2024.
//
#pragma once
#include "NetworkSession.h"
#include "Http2Headers.h"
#include <map>

#include <iostream>
#include <string>
#include <utility>
#include <vector>
#include <memory>
#include <functional>
#include <filesystem>
#include <fstream>
#include <cstdint>
#include <asio.hpp>
#include <HttpRequest.h>
#include <HttpResponse.h>
#include <Logger.h>
#include <asio/ssl.hpp>
#include <nghttp2/nghttp2.h>
#include <openssl/err.h>
#include <openssl/ssl.h>


inline bool check_path(const std::string &path)
{
    return !path.empty() && path[0] == '/' &&
           path.find('\\') == std::string::npos &&
           path.find("/../") == std::string::npos &&
           path.find("/./") == std::string::npos &&
           path.substr(path.length() - 3) != "/.." &&
           path.substr(path.length() - 2) != "/.";
}


inline std::string percent_decode(const std::string &value)
{
    std::string result;
    for (size_t i = 0; i < value.length(); ++i)
    {
        if (value[i] == '%' && i + 2 < value.length())
        {
            int hex = std::stoi(value.substr(i + 1, 2), nullptr, 16);
            result += static_cast<char>(hex);
            i += 2;
        } else
        {
            result += value[i];
        }
    }
    return result;
}



class DataStream {
public:
    virtual ~DataStream() = default;
    virtual ssize_t read(uint8_t* buf, size_t length, uint32_t* data_flags) const = 0;
};

class FileDataStream : public DataStream
{
public:
    explicit FileDataStream(const std::string &filename)
        : file_(filename, std::ios::binary)
    {
        if (!file_)
        {
            throw std::runtime_error("Failed to open file: " + filename);
        }
    }

    ssize_t read(uint8_t *buf, size_t length, uint32_t *data_flags) const override
    {
        file_.read(reinterpret_cast<char *>(buf), length);
        ssize_t n = file_.gcount();
        if (file_.eof())
        {
            *data_flags |= NGHTTP2_DATA_FLAG_EOF;
        }
        return n;
    }

private:
    mutable std::ifstream file_;
};

class StringDataStream : public DataStream {
public:
    explicit StringDataStream(const std::string& data)
        : data_(data), offset_(0)
    {
    }

    ssize_t read(uint8_t *buf, size_t length, uint32_t *data_flags) const override {
        if (offset_ >= data_.size()) {
            *data_flags |= NGHTTP2_DATA_FLAG_EOF;
            return 0;
        }

        size_t remaining = data_.size() - offset_;
        size_t n = std::min(length, remaining);
        std::memcpy(buf, data_.data() + offset_, n);
        offset_ += n;

        if (offset_ >= data_.size()) {
            *data_flags |= NGHTTP2_DATA_FLAG_EOF;
        }

        return static_cast<ssize_t>(n);
    }

private:
    std::string data_;
    mutable size_t offset_;
};

class Http2Stream {
public:
    explicit Http2Stream(int32_t stream_id)
        : stream_id_(stream_id) {}

    [[nodiscard]] int32_t getStreamId() const { return stream_id_; }

    void setDataStream(std::shared_ptr<DataStream> data_stream) {
        data_stream_ = std::move(data_stream);
    }

    [[nodiscard]] std::shared_ptr<DataStream> getDataStream() const {
        return data_stream_;
    }

    HttpRequest request;
    HttpResponse response;

private:
    int32_t stream_id_;
    std::shared_ptr<DataStream> data_stream_;
};


class Http2SessionContext : public SessionContext {
public:
    using RequestHandler = std::function<void(const HttpRequest &request, HttpResponse &response)>;

    Http2SessionContext() = default;
    ~Http2SessionContext() override {
        if (session_) {
            nghttp2_session_del(session_);
        }
    }

    void on_connect() override {
        SessionContext::on_connect();
        initialize_nghttp2_session();
        send_connection_header();
    }

    void read_completion_handler(ByteVector& buffer, const asio::error_code& ec, std::size_t bytes_transferred,
                                 const SessionDoRead& do_read_function) override {
        if (!ec) {
            ssize_t readlen = nghttp2_session_mem_recv2(session_, buffer.data(), bytes_transferred);
            if (readlen < 0) {
                LOG_ERROR("nghttp2_session_mem_recv error: %s", nghttp2_strerror(readlen));
                return;
            }
            if (session_send() != 0) {
                LOG_ERROR("session_send error");
                return;
            }

            do_read_function();
        } else if (ec != asio::error::operation_aborted) {
            LOG_ERROR("Read error: %s", ec.message());
        }
    }

    [[nodiscard]] bool has_read_completion_handler() const override {
        return true;
    }

    void set_request_handler(RequestHandler handler) {
        request_handler_ = std::move(handler);
    }

private:
    nghttp2_session* session_ = nullptr;
    std::map<int32_t, std::shared_ptr<Http2Stream>> streams_;
    std::mutex streams_mutex_;
    RequestHandler request_handler_;

    void initialize_nghttp2_session() {
        nghttp2_session_callbacks* callbacks;
        nghttp2_session_callbacks_new(&callbacks);

        nghttp2_session_callbacks_set_on_begin_frame_callback(callbacks, on_begin_frame_callback);
        nghttp2_session_callbacks_set_send_callback2(callbacks, send_callback);
        nghttp2_session_callbacks_set_on_frame_recv_callback(callbacks, on_frame_recv_callback);
        nghttp2_session_callbacks_set_on_stream_close_callback(callbacks, on_stream_close_callback);
        nghttp2_session_callbacks_set_on_header_callback(callbacks, on_header_callback);
        nghttp2_session_callbacks_set_on_begin_headers_callback(callbacks, on_begin_headers_callback);

        nghttp2_session_server_new(&session_, callbacks, this);

        nghttp2_session_callbacks_del(callbacks);
    }

    static int on_begin_frame_callback(nghttp2_session* session, const nghttp2_frame_hd* hd, void* user_data) {
        auto* self = static_cast<Http2SessionContext*>(user_data);
        return self->on_begin_frame(hd);
    }

    static ssize_t send_callback(nghttp2_session* session, const uint8_t* data, size_t length, int flags, void* user_data) {
        auto* self = static_cast<Http2SessionContext*>(user_data);
        return self->send_callback(data, length);
    }

    static int on_frame_recv_callback(nghttp2_session* session, const nghttp2_frame* frame, void* user_data) {
        auto* self = static_cast<Http2SessionContext*>(user_data);
        return self->on_frame_recv(frame);
    }

    static int on_stream_close_callback(nghttp2_session* session, int32_t stream_id, uint32_t error_code, void* user_data) {
        auto* self = static_cast<Http2SessionContext*>(user_data);
        return self->on_stream_close(stream_id, error_code);
    }

    static int on_header_callback(nghttp2_session* session, const nghttp2_frame* frame,
                                  const uint8_t* name, size_t namelen,
                                  const uint8_t* value, size_t valuelen,
                                  uint8_t flags, void* user_data) {
        auto* self = static_cast<Http2SessionContext*>(user_data);
        return self->on_header(frame, name, namelen, value, valuelen, flags);
    }

    static int on_begin_headers_callback(nghttp2_session* session, const nghttp2_frame* frame, void* user_data) {
        auto* self = static_cast<Http2SessionContext*>(user_data);
        return self->on_begin_headers(frame);
    }

    int on_begin_frame(const nghttp2_frame_hd *hd) const
    {

        if (hd->type == NGHTTP2_SETTINGS && hd->flags & NGHTTP2_FLAG_ACK)
        {
            const unsigned char *alpn = nullptr;
            unsigned int alpnlen = 0;
            if (std::shared_ptr(network_session_)->is_ssl_stream())
            {
                SSL_get0_alpn_selected(std::shared_ptr(network_session_)->ssl_stream().native_handle(), &alpn,
                                       &alpnlen);
                if (alpn == nullptr || alpnlen != 2 || memcmp("h2", alpn, 2) != 0)
                {
                    std::cerr << "Error: h2 is not negotiated" << std::endl;
                    return NGHTTP2_ERR_CALLBACK_FAILURE;
                }
            }
        }
        return 0;
    }

    int session_send()
    {
        LOG_DEBUG("session_send");
        int rv = nghttp2_session_send(session_);
        if (rv != 0)
        {
            if (rv == NGHTTP2_ERR_WOULDBLOCK)
            {
                // Do nothing, we'll resume later
                return 0;
            }
            std::cerr << "nghttp2_session_send error: " << nghttp2_strerror(rv) << std::endl;
            return -1;
        }
        return 0;
    }

    ssize_t send_callback(const uint8_t *data, size_t length)
    {
        LOG_DEBUG("send_callback");
        std::shared_ptr(network_session_)->write(ByteVector(data, data + length), true);
        return static_cast<ssize_t>(length);
    }

    int on_frame_recv(const nghttp2_frame* frame) {
        switch (frame->hd.type) {
            case NGHTTP2_DATA:
            case NGHTTP2_HEADERS:
                if (frame->hd.flags & NGHTTP2_FLAG_END_STREAM) {
                    return on_request_recv(frame->hd.stream_id);
                }
                break;
        }
        return 0;
    }

    int on_stream_close(int32_t stream_id, uint32_t error_code) {
        std::lock_guard<std::mutex> lock(streams_mutex_);
        streams_.erase(stream_id);
        return 0;
    }

    int on_header(const nghttp2_frame* frame, const uint8_t* name, size_t namelen,
                  const uint8_t* value, size_t valuelen, uint8_t flags) {
        if (frame->hd.type == NGHTTP2_HEADERS && frame->headers.cat == NGHTTP2_HCAT_REQUEST) {
            std::lock_guard<std::mutex> lock(streams_mutex_);
            auto it = streams_.find(frame->hd.stream_id);
            if (it != streams_.end()) {
                std::string header_name(reinterpret_cast<const char*>(name), namelen);
                std::string header_value(reinterpret_cast<const char*>(value), valuelen);
                it->second->request.header().addField(header_name, header_value);

                if (header_name == ":method") {
                    it->second->request.setMethod(header_value);
                } else if (header_name == ":path") {
                    it->second->request.setPath(header_value);
                }
            }
        }
        return 0;
    }

    int on_begin_headers(const nghttp2_frame* frame) {
        if (frame->hd.type == NGHTTP2_HEADERS && frame->headers.cat == NGHTTP2_HCAT_REQUEST) {
            std::lock_guard<std::mutex> lock(streams_mutex_);
            auto stream = std::make_shared<Http2Stream>(frame->hd.stream_id);
            streams_[frame->hd.stream_id] = stream;
        }
        return 0;
    }

    int on_request_recv(int32_t stream_id) {
        std::shared_ptr<Http2Stream> stream;
        {
            std::lock_guard<std::mutex> lock(streams_mutex_);
            auto it = streams_.find(stream_id);
            if (it == streams_.end()) {
                return 0;
            }
            stream = it->second;
        }

        if (request_handler_) {
            request_handler_(stream->request,stream->response);
            return send_response(stream);
        } else {
            return error_reply(stream, 500, "Internal Server Error");
        }
    }

    int send_response(const std::shared_ptr<Http2Stream> &stream) {
        stream->response.setHttpVersion("HTTP/2");
        Http2Headers headers = Http2Headers::fromHttpHeaders(stream->response.header().getFields());
        headers.add(":status", std::to_string(stream->response.getStatusCode()));

        stream->setDataStream(std::make_shared<StringDataStream>(stream->response.body().getStrContent()));

        nghttp2_data_provider data_prd;
        data_prd.source.ptr = stream.get();
        data_prd.read_callback = data_read_callback;
        std::vector<nghttp2_nv> hdrs = headers.to_nv_array();
        int rv = nghttp2_submit_response(session_, stream->getStreamId(), hdrs.data(), hdrs.size(), &data_prd);
        if (rv != 0) {
            LOG_ERROR("nghttp2_submit_response error: %s", nghttp2_strerror(rv));
            return -1;
        }
        return session_send();
    }

    int error_reply(const std::shared_ptr<Http2Stream>& stream, int status_code, const std::string& error_message) {
        stream->response.setStatusCode(status_code);
        stream->response.setStatusMessage(error_message);
        stream->response.body().setContent("<html><body><h1>" + std::to_string(status_code) + "</h1><p>" + error_message + "</p></body></html>");
        return send_response(stream);
    }

    static ssize_t data_read_callback(nghttp2_session* session, int32_t stream_id,
                                      uint8_t* buf, size_t length, uint32_t* data_flags,
                                      nghttp2_data_source* source, void* user_data) {
        auto stream = static_cast<Http2Stream*>(source->ptr);
        auto data_stream = stream->getDataStream();
        ssize_t result = data_stream->read(buf, length, data_flags);

        return result;
    }

    void send_connection_header() {
        nghttp2_settings_entry iv[2] = {
            {NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS, 100},
            {NGHTTP2_SETTINGS_INITIAL_WINDOW_SIZE, 1048576}
        };

        int rv = nghttp2_submit_settings(session_, NGHTTP2_FLAG_NONE, iv, 2);
        if (rv != 0) {
            LOG_ERROR("Fatal error: %s", nghttp2_strerror(rv));
            return;
        }
        session_send();
    }
};
