//
// Created by maxim on 23.09.2024.
//

#include <map>
#ifdef _WIN64
typedef __int64 ssize_t;
#else
#include <unistd.h>
#endif
#include <iostream>
#include <string>
#include <utility>
#include <vector>
#include <memory>
#include <functional>
#include <filesystem>
#include <fstream>

#include <asio.hpp>
#include <asio/ssl.hpp>
#include <nghttp2/nghttp2.h>
#include <openssl/err.h>
#include <openssl/ssl.h>

#define MAKE_NV(NAME, VALUE)\
{\
(uint8_t *)NAME,   (uint8_t *)VALUE,     sizeof(NAME) - 1,\
sizeof(VALUE) - 1, NGHTTP2_NV_FLAG_NONE,\
}

#include <iostream>
#include <sstream>
#include <chrono>
#include <iomanip>

#define DEBUG_LOG(msg) do { \
auto now = std::chrono::system_clock::now(); \
auto in_time_t = std::chrono::system_clock::to_time_t(now); \
std::stringstream ss; \
ss << std::put_time(std::localtime(&in_time_t), "%Y-%m-%d %X"); \
std::cerr << ss.str() << " [" << __FILE__ << ":" << __LINE__ << "] " << msg << std::endl; \
} while(0)


// Add this function for path security check
bool check_path(const std::string &path)
{
    return !path.empty() && path[0] == '/' &&
           path.find('\\') == std::string::npos &&
           path.find("/../") == std::string::npos &&
           path.find("/./") == std::string::npos &&
           path.substr(path.length() - 3) != "/.." &&
           path.substr(path.length() - 2) != "/.";
}

// Add this function for percent decoding
std::string percent_decode(const std::string &value)
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
    virtual ssize_t read(uint8_t* buf, size_t length, uint32_t* data_flags) = 0;
};

class FileDataStream : public DataStream {
public:
    explicit FileDataStream(const std::string& filename)
        : file_(filename, std::ios::binary)
    {
        if (!file_) {
            throw std::runtime_error("Failed to open file: " + filename);
        }
    }

    ssize_t read(uint8_t* buf, size_t length, uint32_t* data_flags) override {
        file_.read(reinterpret_cast<char*>(buf), length);
        ssize_t n = file_.gcount();
        if (file_.eof()) {
            *data_flags |= NGHTTP2_DATA_FLAG_EOF;
        }
        return n;
    }

private:
    std::ifstream file_;
};

class StringDataStream : public DataStream {
public:
    explicit StringDataStream(std::string data)
        : data_(std::move(data)), offset_(0)
    {}

    ssize_t read(uint8_t* buf, size_t length, uint32_t* data_flags) override {
        size_t remaining = data_.size() - offset_;
        size_t n = std::min(length, remaining);
        if (n > 0) {
            memcpy(buf, data_.data() + offset_, n);
            offset_ += n;
        }
        if (offset_ >= data_.size()) {
            *data_flags |= NGHTTP2_DATA_FLAG_EOF;
        }
        return n;
    }

private:
    std::string data_;
    size_t offset_;
};

class Http2Stream {
public:
    Http2Stream(int32_t stream_id, std::string request_path)
        : stream_id_(stream_id), request_path_(std::move(request_path))
    {}

    [[nodiscard]] int32_t getStreamId() const { return stream_id_; }
    [[nodiscard]] const std::string& getRequestPath() const { return request_path_; }

    void setRequestPath(const std::string& path) {
        request_path_ = path;
    }

    void setDataStream(std::shared_ptr<DataStream> data_stream) {
        data_stream_ = std::move(data_stream);
    }

    [[nodiscard]] std::shared_ptr<DataStream> getDataStream() const {
        return data_stream_;
    }

private:
    int32_t stream_id_;
    std::string request_path_;
    std::shared_ptr<DataStream> data_stream_;
};


class Http2Session : public std::enable_shared_from_this<Http2Session>
{
public:
    explicit Http2Session(asio::io_context &io_context,
                          std::shared_ptr<asio::ssl::stream<asio::ip::tcp::socket> > socket)
        : socket_(std::move(socket)), strand_(asio::make_strand(io_context))
    {
        initialize_nghttp2_session();

        // Set TCP_NODELAY
        asio::ip::tcp::no_delay option(true);
        socket_->lowest_layer().set_option(option);
    }

    void start()
    {
        send_connection_header();
        do_read();
    }

private:

    std::shared_ptr<asio::ssl::stream<asio::ip::tcp::socket> > socket_;
    nghttp2_session *session_ = nullptr;
    std::vector<uint8_t> read_buffer_;
    std::map<int32_t, std::shared_ptr<Http2Stream>> streams_;
    std::mutex streams_mutex_;
    asio::strand<asio::io_context::executor_type> strand_;
    std::vector<uint8_t> output_buffer_;
    bool write_in_progress_ = false;

    void initialize_nghttp2_session()
    {
        DEBUG_LOG("initialize_nghttp2_session");
        nghttp2_session_callbacks *callbacks;
        nghttp2_session_callbacks_new(&callbacks);

        nghttp2_session_callbacks_set_on_begin_frame_callback(callbacks,
                                                              [](nghttp2_session *session, const nghttp2_frame_hd *hd,
                                                                 void *user_data) -> int
                                                              {
                                                                  auto self = static_cast<Http2Session *>(user_data);
                                                                  return self->on_begin_frame(hd);
                                                              });

        nghttp2_session_callbacks_set_send_callback2(callbacks,
                                                     [](nghttp2_session *session, const uint8_t *data, size_t length,
                                                        int flags, void *user_data) -> ssize_t
                                                     {
                                                         auto self = static_cast<Http2Session *>(user_data);
                                                         return self->send_callback(data, length);
                                                     });

        nghttp2_session_callbacks_set_on_frame_recv_callback(callbacks,
                                                             [](nghttp2_session *session, const nghttp2_frame *frame,
                                                                void *user_data) -> int
                                                             {
                                                                 auto self = static_cast<Http2Session *>(user_data);
                                                                 return self->on_frame_recv(frame);
                                                             });

        nghttp2_session_callbacks_set_on_stream_close_callback(callbacks,
                                                               [](nghttp2_session *session, int32_t stream_id,
                                                                  uint32_t error_code, void *user_data) -> int
                                                               {
                                                                   auto self = static_cast<Http2Session *>(user_data);
                                                                   return self->on_stream_close(stream_id, error_code);
                                                               });

        nghttp2_session_callbacks_set_on_header_callback(callbacks,
                                                         [](nghttp2_session *session, const nghttp2_frame *frame,
                                                            const uint8_t *name, size_t namelen,
                                                            const uint8_t *value, size_t valuelen,
                                                            uint8_t flags, void *user_data) -> int
                                                         {
                                                             auto self = static_cast<Http2Session *>(user_data);
                                                             return self->on_header(
                                                                 frame, name, namelen, value, valuelen, flags);
                                                         });

        nghttp2_session_callbacks_set_on_begin_headers_callback(callbacks,
                                                                [](nghttp2_session *session, const nghttp2_frame *frame,
                                                                   void *user_data) -> int
                                                                {
                                                                    auto self = static_cast<Http2Session *>(user_data);
                                                                    return self->on_begin_headers(frame);
                                                                });

        nghttp2_session_server_new(&session_, callbacks, this);

        nghttp2_session_callbacks_del(callbacks);
        DEBUG_LOG("End of initialize_nghttp2_session");
    }

    int on_begin_frame(const nghttp2_frame_hd *hd) const
    {
        if (hd->type == NGHTTP2_SETTINGS && hd->flags & NGHTTP2_FLAG_ACK)
        {
            const unsigned char *alpn = nullptr;
            unsigned int alpnlen = 0;
            SSL_get0_alpn_selected(socket_->native_handle(), &alpn, &alpnlen);
            if (alpn == nullptr || alpnlen != 2 || memcmp("h2", alpn, 2) != 0)
            {
                std::cerr << "Error: h2 is not negotiated" << std::endl;
                return NGHTTP2_ERR_CALLBACK_FAILURE;
            }
        }
        return 0;
    }

    void send_connection_header()
    {
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


    void do_read()
    {
        DEBUG_LOG("do_read");
        auto self = shared_from_this();
        auto buffer = std::make_shared<std::vector<uint8_t> >(32768);

        auto read_handler = [this, self, buffer](
            const asio::error_code &ec, std::size_t bytes_transferred)
        {
            if (!ec)
            {
                DEBUG_LOG("nghttp2_session_mem_recv call");
                ssize_t readlen = nghttp2_session_mem_recv2(session_,
                                                            buffer->data(), bytes_transferred);
                if (readlen < 0)
                {
                    std::cerr << "nghttp2_session_mem_recv error: "
                            << nghttp2_strerror(readlen) << std::endl;
                    return;
                }
                DEBUG_LOG("session_send call");
                if (session_send() != 0)
                {
                    std::cerr << "session_send error" << std::endl;
                    return;
                }
                DEBUG_LOG("do_read call");
                do_read();
            } else if (ec != asio::error::operation_aborted)
            {
                std::cerr << "Read error: " << ec.message() << std::endl;
            }
        };

        socket_->async_read_some(asio::buffer(*buffer), read_handler);
        DEBUG_LOG("end of do_read");
    }

    int session_send()
    {
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

        // If there's data in the output buffer and no write in progress, start writing
        if (!output_buffer_.empty() && !write_in_progress_)
        {
            do_write();
        }

        return 0;
    }

    ssize_t send_callback(const uint8_t *data, size_t length)
    {
        DEBUG_LOG("send_callback");

        size_t OUTPUT_WOULDBLOCK_THRESHOLD = 64;
        // Check if we need to apply backpressure
        if (output_buffer_.size() >= OUTPUT_WOULDBLOCK_THRESHOLD)
        {
            // Signal nghttp2 to stop sending more data
            return NGHTTP2_ERR_WOULDBLOCK;
        }
        // Append data to the output buffer
        output_buffer_.insert(output_buffer_.end(), data, data + length);

        // If no write is in progress, initiate an async write
        if (!write_in_progress_)
        {
            do_write();
        }
        return (ssize_t) length;
    }

    void do_write()
    {
        if (output_buffer_.empty() || write_in_progress_)
        {
            return;
        }

        write_in_progress_ = true;

        auto self = shared_from_this();
        asio::async_write(
            *socket_,
            asio::buffer(output_buffer_),
            asio::bind_executor(
                strand_,
                [this, self](const asio::error_code &ec, std::size_t bytes_transferred)
                {
                    write_in_progress_ = false;

                    if (!ec)
                    {
                        // Remove the data that was sent
                        output_buffer_.erase(output_buffer_.begin(), output_buffer_.begin() + bytes_transferred);

                        // If there's more data to send, initiate another write
                        if (!output_buffer_.empty())
                        {
                            do_write();
                        } else
                        {
                            // Check if nghttp2 wants to send more data
                            if (nghttp2_session_want_write(session_))
                            {
                                if (session_send() != 0)
                                {
                                    std::cerr << "session_send error after write" << std::endl;
                                    // Handle error, possibly close the session
                                }
                            }
                        }
                    } else if (ec != asio::error::operation_aborted)
                    {
                        std::cerr << "Write error: " << ec.message() << std::endl;
                        // Handle error, possibly close the session
                    }
                }));
    }

    int on_frame_recv(const nghttp2_frame *frame)
    {
        DEBUG_LOG("on_frame_recv");
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
        DEBUG_LOG("End of on_frame_recv");
        return 0;
    }

    int on_stream_close(int32_t stream_id, uint32_t error_code)
    {
        DEBUG_LOG("on_stream_close");
        std::lock_guard<std::mutex> lock(streams_mutex_);
        streams_.erase(stream_id);
        DEBUG_LOG("End of on_stream_close");
        return 0;
    }

    int on_header(const nghttp2_frame *frame, const uint8_t *name, size_t namelen,
              const uint8_t *value, size_t valuelen, uint8_t flags)
    {
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
        try {
            auto data_stream = std::make_shared<FileDataStream>(file_path);
            stream->setDataStream(data_stream);
        } catch (const std::exception& e) {
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

    int error_reply(int32_t stream_id)
    {
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

class Http2Server
{
public:
    Http2Server(asio::io_context &io_context, unsigned short port,
                const std::string &cert_file, const std::string &key_file)
        : io_context(io_context), acceptor_(io_context, asio::ip::tcp::endpoint(asio::ip::tcp::v4(), port)),
          ssl_context_(asio::ssl::context::tls)
    {
        ssl_context_.set_options(
            asio::ssl::context::default_workarounds
            | asio::ssl::context::no_sslv2
            | asio::ssl::context::no_sslv3
            | asio::ssl::context::single_dh_use);
        ssl_context_.use_certificate_chain_file(cert_file);
        ssl_context_.use_private_key_file(key_file, asio::ssl::context::pem);
        SSL_CTX_set_alpn_select_cb(ssl_context_.native_handle(), alpn_select_proto_cb, nullptr);
        do_accept();
    }

private:
    asio::io_context &io_context;
    asio::ip::tcp::acceptor acceptor_;
    asio::ssl::context ssl_context_;
    std::vector<std::shared_ptr<Http2Session> > sessions_;

    static int alpn_select_proto_cb(SSL *ssl, const unsigned char **out,
                                    unsigned char *outlen, const unsigned char *in,
                                    unsigned int inlen, void *arg)
    {
        int rv = nghttp2_select_next_protocol((unsigned char **) out, outlen, in, inlen);
        if (rv != 1)
        {
            return SSL_TLSEXT_ERR_NOACK;
        }
        return SSL_TLSEXT_ERR_OK;
    }

    void do_accept()
    {

        acceptor_.async_accept([this](std::error_code ec, asio::ip::tcp::socket socket)
        {
            if (!ec)
            {
                auto endpoint = socket.remote_endpoint();
                std::cout << "New connection from: " << endpoint.address().to_string()
                        << ":" << endpoint.port() << std::endl;

                std::shared_ptr<asio::ssl::stream<asio::ip::tcp::socket> > ssl_stream_ =
                        std::make_shared<asio::ssl::stream<asio::ip::tcp::socket> >(std::move(socket), ssl_context_);

                ssl_stream_->async_handshake(asio::ssl::stream_base::server,
                                             [this, ssl_stream_, endpoint](std::error_code ec)
                                             {
                                                 if (!ec)
                                                 {
                                                     std::cout << "SSL Handshake completed with "
                                                             << endpoint.address().to_string() << ":" << endpoint.port()
                                                             << ". Protocol: " << SSL_get_version(
                                                                 ssl_stream_->native_handle()) << std::endl;
                                                     sessions_.emplace_back(
                                                         std::make_shared<Http2Session>(io_context, ssl_stream_));
                                                     sessions_.back()->start();
                                                 } else
                                                 {
                                                     std::cerr << "SSL Handshake failed: " << ec.message() << std::endl;
                                                 }
                                             });
            } else
            {
                std::cerr << "Accept error: " << ec.message() << std::endl;
            }

            do_accept();
        });
    }
};

#include <csignal>

std::function<void(int)> shutdown_handler;
void signal_handler(int signal) { shutdown_handler(signal); }

int main(int argc, char *argv[])
{
    unsigned short port = static_cast<unsigned short>(std::atoi("12345"));
    std::string cert_file = "localhost.crt";
    std::string key_file = "localhost.key";

    try
    {
        asio::io_context io_context;

        // Set up signal handling
        asio::signal_set signals(io_context, SIGINT, SIGTERM);
        signals.async_wait([&io_context](std::error_code const &, int)
        {
            io_context.stop();
        });

        shutdown_handler = [&io_context](int signal)
        {
            std::cout << "Received signal " << signal << ". Shutting down." << std::endl;
            io_context.stop();
        };
        std::signal(SIGINT, signal_handler);
        std::signal(SIGTERM, signal_handler);

        Http2Server server(io_context, port, cert_file, key_file);

        std::cout << "Server started on port " << port << std::endl;
        io_context.run();
    } catch (std::exception &e)
    {
        std::cerr << "Exception: " << e.what() << std::endl;
        return 1;
    }

    std::cout << "Server shut down cleanly" << std::endl;
    return 0;
}
