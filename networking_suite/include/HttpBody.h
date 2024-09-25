//
// Created by maxim on 10.09.2024.
//

#pragma once
#include <string>
#include <vector>
#include <cstring>

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

    std::string getStrContent() const {
        return std::string(reinterpret_cast<const char*>(content_.data()), content_.size());
    }

    size_t getSize() const {
        return content_.size();
    }

private:
    std::vector<uint8_t> content_;
};