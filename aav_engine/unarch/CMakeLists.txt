cmake_minimum_required(VERSION 2.6 FATAL_ERROR)

project (LIBUNARCH)

set (MY_TOP_PROJECT_SOURCE_DIR ${PROJECT_SOURCE_DIR}/..)
set (MY_LIB_NAME unarch)
message (STATUS "process ${MY_LIB_NAME}")

include (${MY_TOP_PROJECT_SOURCE_DIR}/cmake/user_config.cmake)

set (LIBUNARCH_SRC
    libunarch_export.cpp)

add_library (${MY_LIB_NAME} STATIC ${LIBUNARCH_SRC})    

