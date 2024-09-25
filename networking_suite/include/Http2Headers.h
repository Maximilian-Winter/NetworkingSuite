#pragma once
#include <unordered_map>
#include <string>
#include <vector>
#include <cstring>
#include <algorithm>
#include <nghttp2/nghttp2.h>

inline std::string toLowercase(const std::string& header) {
    std::string result = header;
    std::transform(result.begin(), result.end(), result.begin(),
                   [](unsigned char c) { return std::tolower(c); });
    return result;
}

class Http2HeaderField {
public:
    Http2HeaderField(const std::string& name, const std::string& value, uint8_t flags = NGHTTP2_NV_FLAG_NONE)
        : name_(name), value_(value), flags_(flags) {}

    nghttp2_nv to_nv() const {
        nghttp2_nv nv;
        nv.name = reinterpret_cast<uint8_t*>(const_cast<char*>(name_.c_str()));
        nv.value = reinterpret_cast<uint8_t*>(const_cast<char*>(value_.c_str()));
        nv.namelen = name_.length();
        nv.valuelen = value_.length();
        nv.flags = flags_;
        return nv;
    }

    void set_no_index() {
        flags_ |= NGHTTP2_NV_FLAG_NO_INDEX;
    }

    void set_no_copy_name() {
        flags_ |= NGHTTP2_NV_FLAG_NO_COPY_NAME;
    }

    void set_no_copy_value() {
        flags_ |= NGHTTP2_NV_FLAG_NO_COPY_VALUE;
    }

    [[nodiscard]] const std::string& name() const { return name_; }
    [[nodiscard]] const std::string& value() const { return value_; }
    [[nodiscard]] uint8_t flags() const { return flags_; }

private:
    std::string name_;
    std::string value_;
    uint8_t flags_;
};

class Http2Headers {
public:
    void add(const Http2HeaderField& field) {
        headers_.push_back(field);
    }

    void add(const std::string& name, const std::string& value, uint8_t flags = NGHTTP2_NV_FLAG_NONE) {
        headers_.emplace_back(name, value, flags);
    }

    std::vector<nghttp2_nv> to_nv_array() const {
        std::vector<nghttp2_nv> nv_array;
        nv_array.reserve(headers_.size());

        // First, add pseudo-headers
        for (const auto& header : headers_) {
            if (header.name()[0] == ':') {
                nv_array.push_back(header.to_nv());
            }
        }

        // Then, add regular headers
        for (const auto& header : headers_) {
            if (header.name()[0] != ':') {
                nv_array.push_back(header.to_nv());
            }
        }

        return nv_array;
    }

    size_t size() const { return headers_.size(); }

    static Http2Headers fromHttpHeaders(const std::unordered_map<std::string, std::string>& headers)
    {
        Http2Headers http2Headers;
        for (const auto& header : headers)
        {
            http2Headers.add(toLowercase(header.first), header.second);
        }

        return http2Headers;
    }

private:
    std::vector<Http2HeaderField> headers_;
};