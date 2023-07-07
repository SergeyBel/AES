cmake_minimum_required(VERSION 2.8)
project(AES CXX)
set(CMAKE_CXX_STANDARD 14)

set(MAIN_PROJECT OFF)
if (CMAKE_CURRENT_SOURCE_DIR STREQUAL CMAKE_SOURCE_DIR)
    set(MAIN_PROJECT ON)
endif()

include_directories(src)
add_subdirectory(src)

if (${MAIN_PROJECT})
    include(CTest)
    add_subdirectory(tests)

    add_test(AESTest tests/AESTest)
endif()