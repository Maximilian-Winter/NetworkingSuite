file(GLOB_RECURSE SOURCES "src/*.cpp")


add_library(networking_suite STATIC
        ${SOURCES}
)

target_include_directories(networking_suite PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/include
)

target_compile_options(networking_suite PRIVATE ${COMMON_COMPILE_OPTIONS})

target_link_libraries(networking_suite PUBLIC ${COMMON_LINK_LIBRARIES})
