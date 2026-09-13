cmake_minimum_required(VERSION 3.20)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

project(zerotrust
    VERSION 0.1.0
    LANGUAGES CXX
)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

add_executable(zerotrustd
    src/main.cpp

    src/processor/processor.cpp

    src/transport/tcp.cpp
    src/transport/udp.cpp
    src/transport/icmp.cpp

    src/logging/logging.cpp

    src/protocols/dns/resolver.cpp

    src/processor/thread_pool.cpp

    src/ztl/lexer.cpp
    src/ztl/parser.cpp
    src/ztl/interpreter.cpp
    src/ztl/runner.cpp

    src/scan/cve.cpp
    src/scan/cidr.cpp
    src/scan/reporter.cpp
    src/scan/tcp_range.cpp

    src/protocols/ssh/terrapin.cpp
    src/protocols/tls/checks.cpp

    src/transport/tls.cpp

    src/core/knowledge_base.cpp
    src/core/db.cpp

    src/webui/webui.cpp
)

find_package(Threads REQUIRED)

if(APPLE AND NOT DEFINED OPENSSL_ROOT_DIR)
    execute_process(
        COMMAND brew --prefix openssl@3
        OUTPUT_VARIABLE OPENSSL_ROOT_DIR
        OUTPUT_STRIP_TRAILING_WHITESPACE
    )
endif()

find_package(OpenSSL REQUIRED)
find_package(SQLite3 REQUIRED)

target_include_directories(zerotrustd
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src/include
        ${CMAKE_CURRENT_SOURCE_DIR}/src
)

target_compile_options(zerotrustd PRIVATE
    -Wall
    -Wextra
    -Wpedantic
)

target_link_libraries(zerotrustd PRIVATE Threads::Threads OpenSSL::SSL OpenSSL::Crypto SQLite3::SQLite3)

enable_testing()

add_executable(zerotrust_tests
    tests/core_tests.cpp
    src/core/db.cpp
    src/core/knowledge_base.cpp
    src/logging/logging.cpp
    src/scan/cve.cpp
    src/protocols/ssh/terrapin.cpp
    src/protocols/tls/checks.cpp
    src/transport/tcp.cpp
    src/transport/tls.cpp
    src/ztl/lexer.cpp
    src/ztl/parser.cpp
    src/ztl/interpreter.cpp
)

target_include_directories(zerotrust_tests
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src/include
        ${CMAKE_CURRENT_SOURCE_DIR}/src
)

target_compile_options(zerotrust_tests PRIVATE
    -Wall
    -Wextra
    -Wpedantic
)

target_link_libraries(zerotrust_tests PRIVATE
    Threads::Threads
    OpenSSL::SSL
    OpenSSL::Crypto
    SQLite3::SQLite3
)

add_test(NAME zerotrust_core_tests COMMAND zerotrust_tests)
set_tests_properties(zerotrust_core_tests PROPERTIES
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
)