cmake_minimum_required(VERSION 3.15)
set(CMAKE_CXX_STANDARD 20)

project(NetworkingSuite)

cmake_policy(SET CMP0091 NEW)

# Set global output directory for binaries
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

# Find required packages
find_package(Threads REQUIRED)
find_package(CURL REQUIRED)
find_package(nlohmann_json CONFIG REQUIRED)
find_package(asio CONFIG REQUIRED)
find_package(OpenSSL REQUIRED)  # Add OpenSSL package
# Print nlohmann JSON include directory for debugging
message(STATUS "nlohmann_json include dir: ${nlohmann_json_INCLUDE_DIRS}")
# Define ASIO_STANDALONE to avoid needing Boost
add_definitions(-DASIO_STANDALONE)

# Set Asio include directory


# Check if Asio directory exists
if(NOT EXISTS ${ASIO_INCLUDE_DIR})
    message(FATAL_ERROR "Asio include directory not found: ${ASIO_INCLUDE_DIR}")
endif()

# Add the include directory for Asio
include_directories(${ASIO_INCLUDE_DIR} ${OPENSSL_INCLUDE_DIR} ${nlohmann_json_INCLUDE_DIRS})

# Print Asio include path for debugging
message(STATUS "Asio include path: ${ASIO_INCLUDE_DIR}")

# Common compile options and link libraries
set(COMMON_COMPILE_OPTIONS
        -Wall
)

set(COMMON_LINK_LIBRARIES
        Threads::Threads
        ${CURL_LIBRARIES}
        nlohmann_json::nlohmann_json
        OpenSSL::SSL
        OpenSSL::Crypto
)

# Function to add common settings to targets
function(add_common_settings target)
    target_compile_options(${target} PRIVATE ${COMMON_COMPILE_OPTIONS})
    target_link_libraries(${target} PRIVATE ${COMMON_LINK_LIBRARIES})
    target_include_directories(${target} PRIVATE
            ${ASIO_INCLUDE_DIR}
            ${OPENSSL_INCLUDE_DIR}
            ${nlohmann_json_INCLUDE_DIR}
            ${CMAKE_SOURCE_DIR}/networking_suite/include
    )
    set_target_properties(${target} PROPERTIES
            RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
    )
endfunction()

add_subdirectory(examples/echo_server_example)
add_subdirectory(examples/http_server_example)
