//
// Created by maxim on 11.09.2024.
//
// HttpClient.h
#pragma once
#include <asio.hpp>
#include <asio/ssl.hpp>
#include <string>
#include <stdexcept>
#include <vector>


#include <Config.h>
#include <functional>
#include <future>
#include "NetworkSession.h"
#include "HttpRequest.h"
#include "HttpResponse.h"
#include "HttpMessageFraming.h"

#ifdef _WIN32
#include <windows.h>
#include <wincrypt.h>
#pragma comment(lib, "crypt32.lib")
#endif


class HttpClient {
public:
    explicit HttpClient(asio::io_context& io_context, const std::string& cert_file = "", bool allow_self_signed = false);

    std::future<HttpResponse> get(const std::string& url, const std::unordered_map<std::string, std::string>& headers = {});
    std::future<HttpResponse> post(const std::string& url, const std::string& body, const std::unordered_map<std::string, std::string>& headers = {});

private:
    void load_cert_file(const std::string& file_path) const;

    void load_default_cert_file();

#ifdef _WIN32
    void load_windows_cert_store() const;
#else
    void load_unix_cert_file();
#endif

    bool verify_certificate(bool preverified, asio::ssl::verify_context& ctx) const;

    bool is_ssl_ = false;
    bool allow_self_signed_;
    Config config_;
    std::future<HttpResponse> sendRequest(const std::string& url, HttpRequest& request);
    static void parseUrl(const std::string& url, std::string& host, std::string& port, std::string& path);
    std::unique_ptr<asio::ssl::context> ssl_context_;
    asio::io_context& io_context_;
    HttpMessageFraming message_framing_;
    SessionContext<NetworkSession<HttpMessageFraming, HttpMessageFraming>, HttpMessageFraming, HttpMessageFraming> context_;
    std::shared_ptr<NetworkSession<HttpMessageFraming, HttpMessageFraming>> session_;
};

inline HttpClient::HttpClient(asio::io_context& io_context, const std::string& cert_file , bool allow_self_signed)
        : ssl_context_(std::make_unique<asio::ssl::context>(asio::ssl::context::tls_client)),
          io_context_(io_context),
          allow_self_signed_(allow_self_signed)
{
    AsyncLogger& logger = AsyncLogger::getInstance();
    logger.setLogLevel(AsyncLogger::parseLogLevel("ERROR"));
    logger.addDestination(std::make_shared<AsyncLogger::ConsoleDestination>());
    logger.addDestination(std::make_shared<AsyncLogger::FileDestination>("client.log", 1 * (1024 * 1024)));
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();

    ssl_context_->set_options(
        asio::ssl::context::default_workarounds |
        asio::ssl::context::no_sslv2 |
        asio::ssl::context::no_sslv3 |
        asio::ssl::context::no_tlsv1 |
        asio::ssl::context::no_tlsv1_1
    );

    ssl_context_->set_verify_mode(asio::ssl::verify_peer);

    if (!cert_file.empty()) {
        load_cert_file(cert_file);
    } else {
        load_default_cert_file();
    }

    ssl_context_->set_verify_callback(
        [this](bool preverified, asio::ssl::verify_context& ctx) {
            return verify_certificate(preverified, ctx);
        });
}


inline std::future<HttpResponse> HttpClient::get(const std::string& url, const std::unordered_map<std::string, std::string>& headers) {
    HttpRequest request;
    request.setMethod("GET");

    std::string host, port, path;
    parseUrl(url, host, port, path);

    request.setPath(path);
    request.setHttpVersion("HTTP/1.1");
    request.header().addField("Host", host);

    for (const auto& [key, value] : headers) {
        request.header().addField(key, value);
    }

    return sendRequest(url, request);
}

inline std::future<HttpResponse> HttpClient::post(const std::string& url, const std::string& body, const std::unordered_map<std::string, std::string>& headers) {
    HttpRequest request;
    request.setMethod("POST");

    std::string host, port, path;
    parseUrl(url, host, port, path);

    request.setPath(path);
    request.setHttpVersion("HTTP/1.1");
    request.header().addField("Host", host);
    request.header().addField("Content-Length", std::to_string(body.length()));
    request.body().setContent(body);

    for (const auto& [key, value] : headers) {
        request.header().addField(key, value);
    }

    return sendRequest(url, request);
}

inline void HttpClient::load_cert_file(const std::string &file_path) const
{
    std::error_code ec;
    ssl_context_->load_verify_file(file_path, ec);
    if (ec) {
        LOG_ERROR("Failed to load certificate file: %s. Error: %s", file_path.c_str(), ec.message().c_str());
        throw std::runtime_error("Failed to load certificate file");
    }
}

inline void HttpClient::load_default_cert_file()
{
#ifdef _WIN32
    load_windows_cert_store();
#else
        load_unix_cert_file();
#endif
}

#ifdef _WIN32
inline void HttpClient::load_windows_cert_store() const
{
    HCERTSTORE hStore = CertOpenSystemStore(0, "ROOT");
    if (!hStore) {
        LOG_ERROR("Failed to open Windows certificate store");
        throw std::runtime_error("Failed to open Windows certificate store");
    }

    X509_STORE* store = SSL_CTX_get_cert_store(ssl_context_->native_handle());

    PCCERT_CONTEXT pContext = nullptr;
    while ((pContext = CertEnumCertificatesInStore(hStore, pContext)) != nullptr) {
        X509* x509 = d2i_X509(nullptr,
                              (const unsigned char**)&pContext->pbCertEncoded,
                              pContext->cbCertEncoded);
        if (x509) {
            X509_STORE_add_cert(store, x509);
            X509_free(x509);
        }
    }

    CertCloseStore(hStore, 0);
    LOG_INFO("Successfully loaded certificates from Windows certificate store");
}

inline bool HttpClient::verify_certificate(bool preverified, asio::ssl::verify_context &ctx) const
{
    X509* cert = X509_STORE_CTX_get_current_cert(ctx.native_handle());
    if (!cert) {
        LOG_ERROR("No certificate found in verify context");
        return false;
    }

    char subject_name[256];
    X509_NAME_oneline(X509_get_subject_name(cert), subject_name, sizeof(subject_name));
    LOG_INFO("Verifying certificate: %s", subject_name);

    if (!preverified) {
        int err = X509_STORE_CTX_get_error(ctx.native_handle());
        LOG_ERROR("Certificate verification failed: %s", X509_verify_cert_error_string(err));

        if (allow_self_signed_ && err == X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT) {
            LOG_WARNING("Allowing self-signed certificate");
            return true;
        }
    }

    return preverified;
}
#else
void load_unix_cert_file() {
    const std::vector<std::string> default_cert_paths = {
        "/etc/ssl/certs/ca-certificates.crt",  // Debian/Ubuntu/Gentoo etc.
        "/etc/pki/tls/certs/ca-bundle.crt",    // Fedora/RHEL 6
        "/etc/ssl/ca-bundle.pem",              // OpenSUSE
        "/etc/pki/tls/cacert.pem",             // OpenELEC
        "/etc/ssl/cert.pem",                   // MacOS
    };

    for (const auto& path : default_cert_paths) {
        std::error_code ec;
        ssl_context_->load_verify_file(path, ec);
        if (!ec) {
            LOG_INFO("Successfully loaded certificates from: %s", path.c_str());
            return;
        }
    }

    LOG_ERROR("Failed to load any default certificate files");
    throw std::runtime_error("No valid certificate file found");
}
#endif

inline std::future<HttpResponse> HttpClient::sendRequest(const std::string& url, HttpRequest& request) {
    auto promise = std::make_shared<std::promise<HttpResponse>>();
    auto future = promise->get_future();

    std::string host, port, path;
    parseUrl(url, host, port, path);

    bool is_https = (port == "443");

    context_.set_message_framing_sender(message_framing_);
    context_.set_message_framing_receiver(message_framing_);

    context_.set_connected_callback([request](const std::shared_ptr<NetworkSession<HttpMessageFraming, HttpMessageFraming>>& session) {
        std::string request_string = request.toString();
        session->write(ByteVector(request_string.begin(), request_string.end()));
    });

    context_.set_message_handler([promise](const std::shared_ptr<NetworkSession<HttpMessageFraming, HttpMessageFraming>>& session, const ByteVector& data) {
        const HttpResponse response = HttpParser::parseResponse(data);
        promise->set_value(response);
        session->close();
    });

    session_ = NetworkSession<HttpMessageFraming, HttpMessageFraming>::connect(
        io_context_,
        host,
        port,
        context_,
        is_https ? ssl_context_.get() : nullptr
    );

    return future;
}

inline void HttpClient::parseUrl(const std::string& url, std::string& host, std::string& port, std::string& path) {
    std::regex url_regex("(https?)://([^:/]+)(:([0-9]+))?(/.*)?");
    std::smatch matches;

    if (std::regex_match(url, matches, url_regex)) {
        std::string protocol = matches[1].str();
        host = matches[2].str();
        port = matches[4].str();
        path = matches[5].str();

        if (port.empty()) {
            port = (protocol == "https") ? "443" : "80";
        }

        if (path.empty()) {
            path = "/";
        }
    } else {
        throw std::runtime_error("Invalid URL format");
    }
}
