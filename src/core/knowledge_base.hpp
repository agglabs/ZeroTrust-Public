// knowledge_base.hpp

#pragma once

#include <map>
#include <mutex>
#include <optional>
#include <string>

namespace core {
    class KnowledgeBase {
    public:
        KnowledgeBase() = default;

        KnowledgeBase(const KnowledgeBase&) = delete;
        KnowledgeBase& operator=(const KnowledgeBase&) = delete;

        void set(const std::string& key, const std::string& value);
        std::optional<std::string> get(const std::string& key) const;
        bool has(const std::string& key) const;

        std::map<std::string, std::string> snapshot() const;

    private:
        mutable std::mutex mtx;
        std::map<std::string, std::string> data;
    };
}
