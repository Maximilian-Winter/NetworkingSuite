add_executable(http_server src/server.cpp)
add_executable(http_client src/client.cpp)

add_common_settings(http_server)
add_common_settings(http_client)

configure_file(${CMAKE_SOURCE_DIR}/examples/http_server_example/public/test.html ${CMAKE_BINARY_DIR}/bin/public/test.html COPYONLY)
configure_file(${CMAKE_SOURCE_DIR}/examples/http_server_example/http_server_config_test.json ${CMAKE_BINARY_DIR}/bin/http_server_config_test.json COPYONLY)
configure_file(${CMAKE_SOURCE_DIR}/examples/http_server_example/dh2048.pem ${CMAKE_BINARY_DIR}/bin/dh2048.pem COPYONLY)
configure_file(${CMAKE_SOURCE_DIR}/examples/http_server_example/server.crt ${CMAKE_BINARY_DIR}/bin/server.crt COPYONLY)
configure_file(${CMAKE_SOURCE_DIR}/examples/http_server_example/server.csr ${CMAKE_BINARY_DIR}/bin/server.csr COPYONLY)
configure_file(${CMAKE_SOURCE_DIR}/examples/http_server_example/server.key ${CMAKE_BINARY_DIR}/bin/server.key COPYONLY)