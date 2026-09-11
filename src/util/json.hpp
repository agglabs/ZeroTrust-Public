// json.hpp

#pragma once

#include <map>
#include <memory>
#include <optional>
#include <string>
#include <variant>
#include <vector>

namespace util {
    struct JsonValue;
    using JsonArray  = std::vector<std::shared_ptr<JsonValue>>;
    using JsonObject = std::map<std::string, std::shared_ptr<JsonValue>>;

    struct JsonValue {
        std::variant<std::monostate, bool, double, std::string, JsonArray, JsonObject> v;

        bool is_null()   const { return std::holds_alternative<std::monostate>(v); }
        bool is_bool()   const { return std::holds_alternative<bool>(v); }
        bool is_number() const { return std::holds_alternative<double>(v); }
        bool is_string() const { return std::holds_alternative<std::string>(v); }
        bool is_array()  const { return std::holds_alternative<JsonArray>(v); }
        bool is_object() const { return std::holds_alternative<JsonObject>(v); }

        bool               as_bool()   const { return std::get<bool>(v); }
        double             as_number() const { return std::get<double>(v); }
        const std::string& as_string() const { return std::get<std::string>(v); }
        const JsonArray&   as_array()  const { return std::get<JsonArray>(v); }
        const JsonObject&  as_object() const { return std::get<JsonObject>(v); }
    };

    std::shared_ptr<JsonValue> parse_json(const std::string& text);

    std::optional<std::shared_ptr<JsonValue>> parse_json_file(const std::string& path);

    std::string obj_get_string(const JsonObject& o, const std::string& key);
    int         obj_get_int(const JsonObject& o, const std::string& key);
    bool        obj_get_bool(const JsonObject& o, const std::string& key);
}
