// reporter.cpp

#include "progress/reporter.hpp"

#include <iostream>
#include <sstream>

namespace {
    std::string build_bar(int percent, int width = 30) {
        int filled = (width * percent) / 100;
        std::ostringstream ss;
        ss << "[";
        for (int i = 0; i < width; i++) {
            ss << (i < filled ? '#' : ' ');
        }
        ss << "]";
        return ss.str();
    }
}

namespace progress {
    void CliReporter::begin(const std::string& stage, int total_items) {
        stage_name = stage;
        total = total_items;
        completed.store(0);
        last_percent.store(-1);

        std::lock_guard<std::mutex> lock(print_mtx);
        std::cerr << stage_name << " (" << total << " items)\n";
    }

    void CliReporter::tick() {
        int done = ++completed;
        int percent = (total > 0) ? (done * 100) / total : 100;

        int expected = last_percent.load();
        while (percent > expected) {
            if (last_percent.compare_exchange_weak(expected, percent)) {
                std::lock_guard<std::mutex> lock(print_mtx);
                std::cerr << "\r" << build_bar(percent) << " " << percent
                          << "%  " << done << "/" << total << std::flush;
                break;
            }
        }
    }

    void CliReporter::end() {
        std::lock_guard<std::mutex> lock(print_mtx);
        std::cerr << "\r" << build_bar(100) << " 100%  " << total << "/" << total << "\n";
    }
}
