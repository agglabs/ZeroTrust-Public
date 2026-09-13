// knowledge_base.hpp

#pragma once

#include <map>
#include <mutex>
#include <optional>
#include <string>

namespace core {
    enum class KnowledgeScope {
        HOST,
        PORT
    };

    inline std::string scoped_key(KnowledgeScope scope, const std::string& key) {
        return std::string(scope == KnowledgeScope::HOST ? "host." : "port.") + key;
    }

    class KnowledgeBase {
    public:
        KnowledgeBase() = default;

        KnowledgeBase(const KnowledgeBase&) = delete;
        KnowledgeBase& operator=(const KnowledgeBase&) = delete;

        void set(const std::string& key, const std::string& value);
        std::optional<std::string> get(const std::string& key) const;
        bool has(const std::string& key) const;

        void set_scoped(KnowledgeScope scope, const std::string& key, const std::string& value);
        std::optional<std::string> get_scoped(KnowledgeScope scope, const std::string& key) const;
        bool has_scoped(KnowledgeScope scope, const std::string& key) const;

        std::map<std::string, std::string> snapshot() const;

    private:
        mutable std::mutex mtx;
        std::map<std::string, std::string> data;
    };
}
