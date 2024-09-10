//
// Created by maxim on 10.09.2024.
//

// HttpHeader.h
#pragma once
#include <unordered_map>
#include <string>
#include <sstream>
#include <algorithm>

class HttpHeader {
public:
    void addField(const std::string& name, const std::string& value) {
        fields_[name] = value;
    }

    std::string getField(const std::string& name) const {
        auto it = fields_.find(name);
        return (it != fields_.end()) ? it->second : "";
    }

    bool hasField(const std::string& name) const {
        return fields_.find(name) != fields_.end();
    }

    void removeField(const std::string& name) {
        fields_.erase(name);
    }

    std::string toString() const {
        std::ostringstream oss;
        for (const auto& [name, value] : fields_) {
            oss << name << ": " << value << "\r\n";
        }
        return oss.str();
    }

private:
    std::unordered_map<std::string, std::string> fields_;
};




