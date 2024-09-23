//
// Created by maxim on 10.09.2024.
//

// HttpBody.h
#pragma once
#include <string>
#include <vector>

class HttpBody {
public:
    void setContent(const std::string& content) {
        content_ = std::vector<uint8_t>(content.begin(), content.end());
    }

    void setContent(const std::vector<uint8_t>& content) {
        content_ = content;
    }

    const std::vector<uint8_t>& getContent() const {
        return content_;
    }
    const std::string getStrContent() const {
        return reinterpret_cast<const char*>(content_.data());
    }
    size_t getSize() const {
        return content_.size();
    }

private:
    std::vector<uint8_t> content_;
};

