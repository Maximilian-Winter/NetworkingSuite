add_executable(http_server src/server.cpp)
add_executable(http_client src/client.cpp)

add_common_settings(http_server)
add_common_settings(http_client)

configure_file(${CMAKE_SOURCE_DIR}/examples/http_server_example/public/test.html ${CMAKE_BINARY_DIR}/bin/public/test.html COPYONLY)

