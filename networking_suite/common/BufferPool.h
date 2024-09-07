//
// Created by maxim on 07.09.2024.
//

#pragma once
#include <functional>
#include <memory>
#include <utility>
#include <vector>
#include <atomic>
#include <array>
#include <optional>
#include <cstddef>

using ByteVector = std::vector<uint8_t>;

template<typename T, size_t Capacity>
class LockFreeQueue {
    struct Node {
        std::atomic<T*> data;
        std::atomic<size_t> next;
    };

    std::array<Node, Capacity> buffer_;
    std::atomic<size_t> head_{0};
    std::atomic<size_t> tail_{0};
    std::atomic<size_t> size_{0};

public:
    LockFreeQueue() {
        for (size_t i = 0; i < Capacity; ++i) {
            buffer_[i].data.store(nullptr, std::memory_order_relaxed);
            buffer_[i].next.store((i + 1) % Capacity, std::memory_order_relaxed);
        }
    }

    bool push(T item) {
        T* new_data = new T(std::move(item));
        size_t curr_tail = tail_.load(std::memory_order_relaxed);
        for (;;) {
            if (size_.load(std::memory_order_acquire) == Capacity) {
                delete new_data;
                return false;  // Queue is full
            }
            size_t next = buffer_[curr_tail].next.load(std::memory_order_relaxed);
            if (tail_.compare_exchange_weak(curr_tail, next, std::memory_order_release, std::memory_order_relaxed)) {
                buffer_[curr_tail].data.store(new_data, std::memory_order_release);
                size_.fetch_add(1, std::memory_order_release);
                return true;
            }
        }
    }

    std::optional<T> pop() {
        size_t curr_head = head_.load(std::memory_order_relaxed);
        for (;;) {
            if (size_.load(std::memory_order_acquire) == 0) {
                return std::nullopt;  // Queue is empty
            }
            T* data = buffer_[curr_head].data.load(std::memory_order_acquire);
            size_t next = buffer_[curr_head].next.load(std::memory_order_relaxed);
            if (head_.compare_exchange_weak(curr_head, next, std::memory_order_release, std::memory_order_relaxed)) {
                std::optional<T> result;
                if (data) {
                    result = std::move(*data);
                    delete data;
                    buffer_[curr_head].data.store(nullptr, std::memory_order_release);
                    size_.fetch_sub(1, std::memory_order_release);
                }
                return result;
            }
        }
    }

    bool empty() const {
        return size_.load(std::memory_order_acquire) == 0;
    }

    size_t size() const {
        return size_.load(std::memory_order_acquire);
    }
};

class BufferPool {
public:

    explicit BufferPool(const size_t buffer_size, const size_t initial_pool_size = 100)
        : buffer_size_(buffer_size) {
        for (size_t i = 0; i < initial_pool_size; ++i) {
            free_buffers_.push(new ByteVector(buffer_size));
        }
    }

    ~BufferPool() {
        while (auto opt_buffer = free_buffers_.pop()) {
            delete *opt_buffer;
        }
    }

    ByteVector* acquire() {
        if (auto opt_buffer = free_buffers_.pop()) {
            return *opt_buffer;
        }
        return new ByteVector(buffer_size_);
    }

    size_t getBufferSize() const
    {
        return buffer_size_;
    }
    void release(ByteVector* buffer) {
        buffer->clear();
        if (!free_buffers_.push(buffer)) {
            delete buffer;  // If queue is full, delete the buffer
        }
    }

private:
    size_t buffer_size_;
    LockFreeQueue<ByteVector*, 1024> free_buffers_;  // Adjust capacity as needed
};
