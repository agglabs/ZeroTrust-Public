// reporter.hpp

#pragma once

#include <atomic>
#include <mutex>
#include <string>

namespace progress {
    class Reporter {
    public:
        virtual ~Reporter() = default;

        virtual void begin(const std::string& stage, int total) = 0;
        virtual void tick() = 0;
        virtual void end() = 0;
    };

    class CliReporter : public Reporter {
    public:
        void begin(const std::string& stage, int total) override;
        void tick() override;
        void end() override;

    private:
        std::string stage_name;
        int total = 0;

        std::atomic<int> completed{0};
        std::atomic<int> last_percent{-1};

        std::mutex print_mtx;
    };

    class NullReporter : public Reporter {
    public:
        void begin(const std::string&, int) override {}
        void tick() override {}
        void end() override {}
    };
}
