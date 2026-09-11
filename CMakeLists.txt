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

    src/concurrency/thread_pool.cpp

    src/ztl/interpreter.cpp
    src/ztl/parser.cpp

    src/vuln/vuln.cpp
    src/vuln/terrapin.cpp
    src/vuln/tls_checks.cpp

    src/transport/tls.cpp

    src/core/knowledge_base.cpp

    src/util/cidr.cpp
    src/util/json.cpp

    src/import/nmap_probes.cpp
    src/import/nvd.cpp

    src/report/json_writer.cpp
    src/report/reader.cpp
    src/report/delta.cpp

    src/progress/reporter.cpp
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

target_link_libraries(zerotrustd PRIVATE Threads::Threads OpenSSL::SSL OpenSSL::Crypto)