cmake_minimum_required(VERSION 3.20)
project(GW_Network_Packet_Communication VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Enable strict warning flags
if(MSVC)
    add_compile_options(/W4 /WX)
else()
    add_compile_options(-Wall -Wextra -Werror -pedantic)
endif()

# AddressSanitizer option (P6.14)
option(SANITIZE_ADDRESS "Enable AddressSanitizer" OFF)
if(SANITIZE_ADDRESS)
    if(MSVC)
        add_compile_options(/fsanitize=address)
    else()
        add_compile_options(-fsanitize=address -fno-omit-frame-pointer)
        add_link_options(-fsanitize=address)
    endif()
endif()

# Include directories
include_directories(
    ${CMAKE_CURRENT_SOURCE_DIR}/include/common
    ${CMAKE_CURRENT_SOURCE_DIR}/include/server
    ${CMAKE_CURRENT_SOURCE_DIR}/include/client
)

# Common static library target: libgw_common
add_library(gw_common STATIC
    src/common/platform_socket.cpp
    src/common/socket_guard.cpp
    src/common/logger.cpp
    src/common/crc8_calculator.cpp
    src/common/xor_crypto_strategy.cpp
    src/common/nibble_swap_transform.cpp
    src/common/packet.cpp
    src/common/packet_parser.cpp
    src/common/stream_framer.cpp
    src/server/base_validator.cpp
    src/server/length_validator.cpp
    src/server/source_address_validator.cpp
    src/server/target_address_validator.cpp
    src/server/crc_validator.cpp
    src/server/response_factory.cpp
    src/client/request_builder.cpp
    src/client/response_parser.cpp
    src/server/tcp_server.cpp
    src/server/connection_handler.cpp
    src/server/server_metrics.cpp
    src/server/gateway_server.cpp
    src/client/tcp_client.cpp
)

target_include_directories(gw_common PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include/common
    ${CMAKE_CURRENT_SOURCE_DIR}/include/server
    ${CMAKE_CURRENT_SOURCE_DIR}/include/client
)

if(WIN32)
    target_link_libraries(gw_common PUBLIC ws2_32)
endif()

# Gateway Server executable: gw_server
add_executable(gw_server
    src/server/main.cpp
)
target_link_libraries(gw_server PRIVATE gw_common)

# Diagnostic Client executable: gw_client
add_executable(gw_client
    src/client/main.cpp
)
target_link_libraries(gw_client PRIVATE gw_common)

# Testing
enable_testing()

include(FetchContent)
FetchContent_Declare(
    googletest
    URL https://github.com/google/googletest/archive/refs/tags/v1.14.0.zip
    DOWNLOAD_EXTRACT_TIMESTAMP TRUE
)

# Set gtest options
set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
set(BUILD_GMOCK OFF CACHE BOOL "" FORCE)
set(INSTALL_GTEST OFF CACHE BOOL "" FORCE)

FetchContent_MakeAvailable(googletest)

if(TARGET gtest_main)
    include(GoogleTest)

    macro(add_gw_test test_name test_source)
        add_executable(${test_name} ${test_source})
        target_link_libraries(${test_name} PRIVATE gw_common gtest_main)
        if(WIN32)
            target_link_libraries(${test_name} PRIVATE ws2_32)
        endif()
        gtest_discover_tests(${test_name})
    endmacro()

    # Phase 1 Test
    add_gw_test(test_stub tests/common/test_stub.cpp)

    # Phase 2 Tests
    add_gw_test(test_crc8_calculator tests/common/test_crc8_calculator.cpp)
    add_gw_test(test_xor_crypto_strategy tests/common/test_xor_crypto_strategy.cpp)
    add_gw_test(test_nibble_swap_transform tests/common/test_nibble_swap_transform.cpp)
    add_gw_test(test_transformation_pipeline tests/common/test_transformation_pipeline.cpp)

    # Phase 3 Tests
    add_gw_test(test_packet tests/common/test_packet.cpp)
    add_gw_test(test_packet_parser tests/common/test_packet_parser.cpp)
    add_gw_test(test_stream_framer tests/common/test_stream_framer.cpp)
    add_gw_test(test_length_validator tests/server/test_length_validator.cpp)
    add_gw_test(test_source_address_validator tests/server/test_source_address_validator.cpp)
    add_gw_test(test_target_address_validator tests/server/test_target_address_validator.cpp)
    add_gw_test(test_crc_validator tests/server/test_crc_validator.cpp)
    add_gw_test(test_validation_chain tests/server/test_validation_chain.cpp)
    add_gw_test(test_response_factory tests/server/test_response_factory.cpp)
    add_gw_test(test_request_builder tests/client/test_request_builder.cpp)
    add_gw_test(test_response_parser tests/client/test_response_parser.cpp)

    # Phase 4 Tests
    add_gw_test(test_server_metrics tests/server/test_server_metrics.cpp)
    add_gw_test(test_rule_of_five_traits tests/server/test_rule_of_five_traits.cpp)
    add_gw_test(test_connection_handler tests/server/test_connection_handler.cpp)
    add_gw_test(test_tcp_client tests/client/test_tcp_client.cpp)
    add_gw_test(test_phase4_networking tests/integration/test_phase4_networking.cpp)

    # Phase 5 Tests
    add_gw_test(test_phase5_observability tests/integration/test_phase5_observability.cpp)

    # Phase 6 Tests
    add_gw_test(test_e2e_positive tests/integration/test_e2e_positive.cpp)
    add_gw_test(test_e2e_address_pairs tests/integration/test_e2e_address_pairs.cpp)
    add_gw_test(test_e2e_negative tests/integration/test_e2e_negative.cpp)
    add_gw_test(test_concurrent_clients tests/stress/test_concurrent_clients.cpp)
    add_gw_test(test_zero_drop tests/stress/test_zero_drop.cpp)
endif()
