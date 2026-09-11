// knowledge_base.cpp

#include "core/knowledge_base.hpp"

namespace core {
    void KnowledgeBase::set(const std::string& key, const std::string& value) {
        std::lock_guard<std::mutex> lock(mtx);
        data[key] = value;
    }

    std::optional<std::string> KnowledgeBase::get(const std::string& key) const {
        std::lock_guard<std::mutex> lock(mtx);
        auto it = data.find(key);
        if (it == data.end()) return std::nullopt;
        return it->second;
    }

    bool KnowledgeBase::has(const std::string& key) const {
        std::lock_guard<std::mutex> lock(mtx);
        return data.find(key) != data.end();
    }

    std::map<std::string, std::string> KnowledgeBase::snapshot() const {
        std::lock_guard<std::mutex> lock(mtx);
        return data;
    }
}
