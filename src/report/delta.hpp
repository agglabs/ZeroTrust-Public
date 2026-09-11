// delta.hpp

#pragma once

#include "report/reader.hpp"

#include <string>

namespace report {
    void print_delta(const ScanReport& before, const ScanReport& after);
}
