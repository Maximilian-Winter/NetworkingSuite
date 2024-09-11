# entrance_server/CMakeLists.txt
cmake_minimum_required(VERSION 3.15)
project(networking_suite)
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_executable(http_server src/server.cpp)


target_include_directories(http_server PRIVATE
        ${CMAKE_SOURCE_DIR}/networking_suite/include
)

target_link_libraries(http_server PRIVATE
        ${COMMON_LINK_LIBRARIES}
)

target_compile_options(http_server PRIVATE ${COMMON_COMPILE_OPTIONS})

set_target_properties(http_server PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
)

add_executable(http_client src/client.cpp)


target_include_directories(http_client PRIVATE
        ${CMAKE_SOURCE_DIR}/networking_suite/include
)

target_link_libraries(http_client PRIVATE
        ${COMMON_LINK_LIBRARIES}
)

target_compile_options(http_client PRIVATE ${COMMON_COMPILE_OPTIONS})

set_target_properties(http_client PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
)


