cmake_minimum_required(VERSION 2.6 FATAL_ERROR)

project (LIBUTIL)

set (MY_TOP_PROJECT_SOURCE_DIR ${PROJECT_SOURCE_DIR}/..)
set (MY_LIB_NAME util_)
message (STATUS "process ${MY_LIB_NAME}")

include (${MY_TOP_PROJECT_SOURCE_DIR}/cmake/user_config.cmake)

add_subdirectory (crc32)

set (LIBUTIL_SRC
    ${CRC32_SRC}
    libutil_export.cpp)

add_library (${MY_LIB_NAME} STATIC ${LIBUTIL_SRC})    

