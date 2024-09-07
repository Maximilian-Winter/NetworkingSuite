# entrance_server/CMakeLists.txt
cmake_minimum_required(VERSION 3.15)
project(networking_suite)
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_executable(echo_server src/server.cpp)


target_include_directories(echo_server PRIVATE
        ${CMAKE_SOURCE_DIR}/common/include
)

target_link_libraries(echo_server PRIVATE
        common
        ${COMMON_LINK_LIBRARIES}
)

target_compile_options(echo_server PRIVATE ${COMMON_COMPILE_OPTIONS})

set_target_properties(echo_server PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
)

add_executable(echo_client src/client.cpp)


target_include_directories(echo_client PRIVATE
        ${CMAKE_SOURCE_DIR}/common/include
)

target_link_libraries(echo_client PRIVATE
        common
        ${COMMON_LINK_LIBRARIES}
)

target_compile_options(echo_client PRIVATE ${COMMON_COMPILE_OPTIONS})

set_target_properties(echo_client PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
)