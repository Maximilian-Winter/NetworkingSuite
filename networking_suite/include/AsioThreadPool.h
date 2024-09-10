//
// Created by maxim on 19.08.2024.
//

#pragma once
#include <asio.hpp>
#include <thread>
#include <vector>

class AsioThreadPool {
public:
    explicit AsioThreadPool(size_t thread_count = 0)
            : thread_count_(),
              io_context_(),
              work_guard_(asio::make_work_guard(io_context_)) {
        if (thread_count == 0) {
            thread_count_ = std::thread::hardware_concurrency();
        } else
        {
            thread_count_ = thread_count;
        }

    }

    ~AsioThreadPool() {
        stop();
    }

    asio::io_context& get_io_context() {
        return io_context_;
    }

    void stop() {
        work_guard_.reset();
        io_context_.stop();
        for (auto& thread : threads_) {
            if (thread.joinable()) {
                thread.join();
            }
        }
    }
    void start_threads() {
        threads_.reserve(thread_count_);
        for (size_t i = 0; i < std::max(static_cast<int>(thread_count_) - 1, 1); ++i) {
            threads_.emplace_back([this]() {
                io_context_.run();
            });
        }

    }
private:

    size_t thread_count_;
    asio::io_context io_context_;
    asio::executor_work_guard<asio::io_context::executor_type> work_guard_;
    std::vector<std::thread> threads_;
};
