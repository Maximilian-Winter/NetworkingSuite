//
// Created by maxim on 24.09.2024.
//
#pragma once
#include "NetworkSession.h"
#include <map>

#include <iostream>
#include <string>
#include <utility>
#include <vector>
#include <memory>
#include <functional>
#include <filesystem>
#include <fstream>

#include <asio.hpp>
#include <Logger.h>
#include <asio/ssl.hpp>
#include <nghttp2/nghttp2.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#define MAKE_NV(NAME, VALUE)\
{\
(uint8_t *)NAME,   (uint8_t *)VALUE,     sizeof(NAME) - 1,\
sizeof(VALUE) - 1, NGHTTP2_NV_FLAG_NONE,\
}

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


class DataStream
{
public:
    virtual ~DataStream() = default;

    virtual ssize_t read(uint8_t *buf, size_t length, uint32_t *data_flags) = 0;
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

    ssize_t read(uint8_t *buf, size_t length, uint32_t *data_flags) override
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
    std::ifstream file_;
};

class StringDataStream : public DataStream
{
public:
    explicit StringDataStream(std::string data)
        : data_(std::move(data)), offset_(0)
    {
    }

    ssize_t read(uint8_t *buf, size_t length, uint32_t *data_flags) override
    {
        size_t remaining = data_.size() - offset_;
        size_t n = std::min(length, remaining);
        if (n > 0)
        {
            memcpy(buf, data_.data() + offset_, n);
            offset_ += n;
        }
        if (offset_ >= data_.size())
        {
            *data_flags |= NGHTTP2_DATA_FLAG_EOF;
        }
        return n;
    }

private:
    std::string data_;
    size_t offset_;
};

class Http2Stream
{
public:
    Http2Stream(int32_t stream_id, std::string request_path)
        : stream_id_(stream_id), request_path_(std::move(request_path))
    {
    }

    [[nodiscard]] int32_t getStreamId() const { return stream_id_; }
    [[nodiscard]] const std::string &getRequestPath() const { return request_path_; }

    void setRequestPath(const std::string &path)
    {
        request_path_ = path;
    }

    void setDataStream(std::shared_ptr<DataStream> data_stream)
    {
        data_stream_ = std::move(data_stream);
    }

    [[nodiscard]] std::shared_ptr<DataStream> getDataStream() const
    {
        return data_stream_;
    }

private:
    int32_t stream_id_;
    std::string request_path_;
    std::shared_ptr<DataStream> data_stream_;
};


class Http2SessionContext : public SessionContext
{
public:
    Http2SessionContext()
    = default;

    ~Http2SessionContext() override
    {
        if (session_)
        {
            nghttp2_session_del(session_);
        }
    }

    void on_connect() override
    {
        SessionContext::on_connect();
        initialize_nghttp2_session();
        send_connection_header();
    }

    void read_completion_handler(ByteVector &buffer, const asio::error_code &ec, std::size_t bytes_transferred,
                                 const SessionDoRead &do_read_function) override
    {
        if (!ec)
        {
            ssize_t readlen = nghttp2_session_mem_recv2(session_,
                                                        buffer.data(), bytes_transferred);
            if (readlen < 0)
            {
                std::cerr << "nghttp2_session_mem_recv error: "
                        << nghttp2_strerror(readlen) << std::endl;
                return;
            }
            if (session_send() != 0)
            {
                std::cerr << "session_send error" << std::endl;
                return;
            }

            do_read_function();
        } else if (ec != asio::error::operation_aborted)
        {
            std::cerr << "Read error: " << ec.message() << std::endl;
        }
    }

    [[nodiscard]] bool has_read_completion_handler() const override
    {
        return true;
    }

private:
    nghttp2_session *session_ = nullptr;
    std::map<int32_t, std::shared_ptr<Http2Stream> > streams_;
    std::mutex streams_mutex_;

    void initialize_nghttp2_session()
    {
        LOG_DEBUG("Initialize nghttp2_session");
        nghttp2_session_callbacks *callbacks;
        nghttp2_session_callbacks_new(&callbacks);

        nghttp2_session_callbacks_set_on_begin_frame_callback(callbacks,
                                                              [](nghttp2_session *session, const nghttp2_frame_hd *hd,
                                                                 void *user_data) -> int
                                                              {
                                                                  LOG_DEBUG("nghttp2_session_callbacks_set_on_begin_frame");
                                                                  auto self = static_cast<Http2SessionContext *>(
                                                                      user_data);
                                                                  return self->on_begin_frame(hd);
                                                              });

        nghttp2_session_callbacks_set_send_callback2(callbacks,
                                                     [](nghttp2_session *session, const uint8_t *data, size_t length,
                                                        int flags, void *user_data) -> ssize_t
                                                     {
                                                         LOG_DEBUG("nghttp2_session_callbacks_set_send_callback2");
                                                         auto self = static_cast<Http2SessionContext *>(user_data);
                                                         return self->send_callback(data, length);
                                                     });

        nghttp2_session_callbacks_set_on_frame_recv_callback(callbacks,
                                                             [](nghttp2_session *session, const nghttp2_frame *frame,
                                                                void *user_data) -> int
                                                             {
                                                                 LOG_DEBUG("nghttp2_session_callbacks_set_on_frame_recv_callback");
                                                                 auto self = static_cast<Http2SessionContext *>(
                                                                     user_data);
                                                                 return self->on_frame_recv(frame);
                                                             });

        nghttp2_session_callbacks_set_on_stream_close_callback(callbacks,
                                                               [](nghttp2_session *session, int32_t stream_id,
                                                                  uint32_t error_code, void *user_data) -> int
                                                               {
                                                                   LOG_DEBUG("nghttp2_session_callbacks_set_on_stream_close_callback");
                                                                   auto self = static_cast<Http2SessionContext *>(
                                                                       user_data);
                                                                   return self->on_stream_close(stream_id, error_code);
                                                               });

        nghttp2_session_callbacks_set_on_header_callback(callbacks,
                                                         [](nghttp2_session *session, const nghttp2_frame *frame,
                                                            const uint8_t *name, size_t namelen,
                                                            const uint8_t *value, size_t valuelen,
                                                            uint8_t flags, void *user_data) -> int
                                                         {
                                                             LOG_DEBUG("nghttp2_session_callbacks_set_on_header_callback");
                                                             auto self = static_cast<Http2SessionContext *>(user_data);
                                                             return self->on_header(
                                                                 frame, name, namelen, value, valuelen, flags);
                                                         });

        nghttp2_session_callbacks_set_on_begin_headers_callback(callbacks,
                                                                [](nghttp2_session *session, const nghttp2_frame *frame,
                                                                   void *user_data) -> int
                                                                {
                                                                    LOG_DEBUG("nghttp2_session_callbacks_set_on_begin_headers_callback");
                                                                    auto self = static_cast<Http2SessionContext *>(
                                                                        user_data);
                                                                    return self->on_begin_headers(frame);
                                                                });

        nghttp2_session_server_new(&session_, callbacks, this);

        nghttp2_session_callbacks_del(callbacks);
    }

    int on_begin_frame(const nghttp2_frame_hd *hd) const
    {
        LOG_DEBUG("on_begin_frame");
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

    int on_frame_recv(const nghttp2_frame *frame)
    {
        LOG_DEBUG("on_frame_recv");
        switch (frame->hd.type)
        {
            case NGHTTP2_DATA:
            case NGHTTP2_HEADERS:
                if (frame->hd.flags & NGHTTP2_FLAG_END_STREAM)
                {
                    return on_request_recv(frame->hd.stream_id);
                }
                break;
            default:
                break;
        }
        return 0;
    }

    int on_stream_close(int32_t stream_id, uint32_t error_code)
    {
        LOG_DEBUG("on_stream_close");
        std::lock_guard<std::mutex> lock(streams_mutex_);
        streams_.erase(stream_id);
        return 0;
    }

    int on_header(const nghttp2_frame *frame, const uint8_t *name, size_t namelen,
                  const uint8_t *value, size_t valuelen, uint8_t flags)
    {
        LOG_DEBUG("on_header");
        if (frame->hd.type == NGHTTP2_HEADERS &&
            frame->headers.cat == NGHTTP2_HCAT_REQUEST)
        {
            if (namelen == 5 && memcmp(":path", name, namelen) == 0)
            {
                std::lock_guard<std::mutex> lock(streams_mutex_);
                auto it = streams_.find(frame->hd.stream_id);
                if (it != streams_.end())
                {
                    it->second->setRequestPath(
                        std::string(reinterpret_cast<const char *>(value), valuelen));
                }
            }
        }
        return 0;
    }

    int on_begin_headers(const nghttp2_frame *frame)
    {
        LOG_DEBUG("on_begin_headers");
        if (frame->hd.type == NGHTTP2_HEADERS &&
            frame->headers.cat == NGHTTP2_HCAT_REQUEST)
        {
            std::lock_guard<std::mutex> lock(streams_mutex_);
            auto stream = std::make_shared<Http2Stream>(frame->hd.stream_id, "");
            streams_[frame->hd.stream_id] = stream;
        }
        return 0;
    }

    int on_request_recv(int32_t stream_id)
    {
        LOG_DEBUG("on_request_recv");
        std::shared_ptr<Http2Stream> stream;
        {
            std::lock_guard<std::mutex> lock(streams_mutex_);
            auto it = streams_.find(stream_id);
            if (it == streams_.end())
            {
                return 0;
            }
            stream = it->second;
        }

        std::cout << "Received request for: " << stream->getRequestPath() << std::endl;

        // Decode the path
        std::string decoded_path = percent_decode(stream->getRequestPath());

        // Check path security
        if (!check_path(decoded_path))
        {
            std::cerr << "Invalid path: " << decoded_path << std::endl;
            return error_reply(stream_id);
        }

        std::string file_path = "." + decoded_path;
        try
        {
            auto data_stream = std::make_shared<FileDataStream>(file_path);
            stream->setDataStream(data_stream);
        } catch (const std::exception &e)
        {
            std::cerr << e.what() << std::endl;
            return error_reply(stream_id);
        }

        const nghttp2_nv hdrs[] = {
            MAKE_NV(":status", "200")
        };

        nghttp2_data_provider data_prd;
        data_prd.source.ptr = stream.get();
        data_prd.read_callback = [](nghttp2_session *session, int32_t stream_id,
                                    uint8_t *buf, size_t length, uint32_t *data_flags,
                                    nghttp2_data_source *source, void *user_data) -> ssize_t
        {
            auto stream = static_cast<Http2Stream *>(source->ptr);
            auto data_stream = stream->getDataStream();
            return data_stream->read(buf, length, data_flags);
        };

        int rv = nghttp2_submit_response(session_, stream_id, hdrs, 1, &data_prd);
        if (rv != 0)
        {
            std::cerr << "nghttp2_submit_response error: " << nghttp2_strerror(rv) << std::endl;
            return -1;
        }
        return session_send();
    }

    void send_connection_header()
    {
        LOG_DEBUG("send_connection_header");
        nghttp2_settings_entry iv[2] = {
            {NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS, 100},
            {NGHTTP2_SETTINGS_INITIAL_WINDOW_SIZE, 1048576}
        };

        int rv = nghttp2_submit_settings(session_, NGHTTP2_FLAG_NONE, iv, 2);
        if (rv != 0)
        {
            std::cerr << "Fatal error: " << nghttp2_strerror(rv) << std::endl;
            return;
        }
        session_send();
    }

    int error_reply(int32_t stream_id)
    {
        LOG_DEBUG("error_reply");
        static const std::string ERROR_HTML = "<html><body><h1>404</h1></body></html>";

        auto stream = std::make_shared<Http2Stream>(stream_id, "");
        streams_[stream_id] = stream;

        auto data_stream = std::make_shared<StringDataStream>(ERROR_HTML);
        stream->setDataStream(data_stream);

        const nghttp2_nv hdrs[] = {
            MAKE_NV(":status", "404")
        };

        nghttp2_data_provider data_prd;
        data_prd.source.ptr = stream.get();
        data_prd.read_callback = [](nghttp2_session *session, int32_t stream_id,
                                    uint8_t *buf, size_t length, uint32_t *data_flags,
                                    nghttp2_data_source *source, void *user_data) -> ssize_t
        {
            auto stream = static_cast<Http2Stream *>(source->ptr);
            auto data_stream = stream->getDataStream();
            return data_stream->read(buf, length, data_flags);
        };

        nghttp2_submit_response(session_, stream_id, hdrs, 1, &data_prd);
        return session_send();
    }
};
