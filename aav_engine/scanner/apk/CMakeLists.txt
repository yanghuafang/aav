cmake_minimum_required(VERSION 2.6 FATAL_ERROR)

project (LIBAPK)

set (MY_TOP_PROJECT_SOURCE_DIR ${PROJECT_SOURCE_DIR}/../..)
set (MY_LIB_NAME apk)
message (STATUS "process ${MY_LIB_NAME}")

include (${MY_TOP_PROJECT_SOURCE_DIR}/cmake/user_config.cmake)

set (LIBAPK_SRC
    libapk_export.cpp
    ApkScanner.cpp)

add_library (${MY_LIB_NAME} STATIC ${LIBAPK_SRC})    

