//
// Created by maxim on 09.09.2024.
//

#pragma once

#include <string>
#include <filesystem>
#include <fstream>
#include <unordered_map>
#include "Logger.h"

class FileServer {
public:
    explicit FileServer(const std::string& root_directory)
        : root_directory_(root_directory) {
        // Initialize MIME types
        mime_types_[".html"] = "text/html";
        mime_types_[".css"] = "text/css";
        mime_types_[".js"] = "application/javascript";
        mime_types_[".jpg"] = "image/jpeg";
        mime_types_[".png"] = "image/png";
        mime_types_[".gif"] = "image/gif";
        // Add more MIME types as needed
    }

    bool serveFile(const std::string& path, std::string& content, std::string& content_type) {
        std::filesystem::path file_path = std::filesystem::path(root_directory_) / std::filesystem::path(path.substr(1));

        // Ensure the requested file is within the root directory
        if (!isPathInRoot(file_path)) {
            LOG_WARNING("Attempted access to file outside root directory: %s", file_path.string().c_str());
            return false;
        }

        if (!std::filesystem::exists(file_path)) {
            return false;
        }

        std::ifstream file(file_path, std::ios::binary);
        if (!file) {
            LOG_ERROR("Failed to open file: %s", file_path.string().c_str());
            return false;
        }

        content.assign(std::istreambuf_iterator<char>(file), std::istreambuf_iterator<char>());
        content_type = getMimeType(file_path.extension().string());
        return true;
    }

private:
    std::string root_directory_;
    std::unordered_map<std::string, std::string> mime_types_;

    bool isPathInRoot(const std::filesystem::path& path) const {
        return std::filesystem::weakly_canonical(path).string().find(
            std::filesystem::weakly_canonical(root_directory_).string()) == 0;
    }

    std::string getMimeType(const std::string& extension) const {
        auto it = mime_types_.find(extension);
        if (it != mime_types_.end()) {
            return it->second;
        }
        return "application/octet-stream"; // Default MIME type
    }
};
