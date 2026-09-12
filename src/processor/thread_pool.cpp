// thread_pool.cpp

#include "thread_pool.hpp"

namespace concurrency {
    ThreadPool::ThreadPool(std::size_t num_threads) {
        for (std::size_t i = 0; i < num_threads; i++) {
            workers.emplace_back(&ThreadPool::worker_loop, this);
        }
    }

    ThreadPool::~ThreadPool() {
        {
            std::lock_guard<std::mutex> lock(queue_mutex);
            stop = true;
        }

        condition.notify_all();

        for (std::thread& worker : workers) {
            worker.join();
        }
    }

    void ThreadPool::enqueue(std::function<void()> task) {
        {
            std::lock_guard<std::mutex> lock(queue_mutex);
            tasks.push(std::move(task));
        }

        condition.notify_one();
    }

    void ThreadPool::worker_loop() {
        while (true) {
            std::function<void()> task;

            {
                std::unique_lock<std::mutex> lock(queue_mutex);

                condition.wait(lock, [this] {
                    return stop || !tasks.empty();
                });

                if (stop && tasks.empty()) {
                    return;
                }

                task = std::move(tasks.front());
                tasks.pop();
            }

            task();
        }
    }
} 
