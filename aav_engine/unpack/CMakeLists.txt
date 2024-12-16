cmake_minimum_required(VERSION 2.6 FATAL_ERROR)

project (LIBUNPACK)

set (MY_TOP_PROJECT_SOURCE_DIR ${PROJECT_SOURCE_DIR}/..)
set (MY_LIB_NAME unpack)
message (STATUS "process ${MY_LIB_NAME}")

include (${MY_TOP_PROJECT_SOURCE_DIR}/cmake/user_config.cmake)

set (LIBUNPACK_SRC
    libunpack_export.cpp)

add_library (${MY_LIB_NAME} STATIC ${LIBUNPACK_SRC})    

