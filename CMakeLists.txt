cmake_minimum_required(VERSION 2.8)

project(AES CXX)

set(SOURCE_FILES src/AES.cpp src/AES.h)
add_library(${PROJECT_NAME} ${SOURCE_FILES})

target_include_directories(${PROJECT_NAME} PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})


