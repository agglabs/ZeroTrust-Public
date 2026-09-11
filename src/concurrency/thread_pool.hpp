// thread_pool.hpp

#pragma once

#include <functional>
#include <cstddef>
#include <vector>
#include <queue>
#include <thread>
#include <mutex>
#include <condition_variable>

namespace concurrency {

class ThreadPool {
    public:
        explicit ThreadPool(std::size_t num_threads);
        ~ThreadPool();

        ThreadPool(const ThreadPool&) = delete;
        ThreadPool& operator=(const ThreadPool&) = delete;

        void enqueue(std::function<void()> task);

    private:
        std::vector<std::thread> workers;
        std::queue<std::function<void()>> tasks;

        std::mutex queue_mutex;
        std::condition_variable condition;
        bool stop = false;

        void worker_loop();
    };
} 
