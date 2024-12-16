cmake_minimum_required(VERSION 2.6 FATAL_ERROR)

project (LIBFILEID)

set (MY_TOP_PROJECT_SOURCE_DIR ${PROJECT_SOURCE_DIR}/..)
set (MY_LIB_NAME fileid)
message (STATUS "process ${MY_LIB_NAME}")

include (${MY_TOP_PROJECT_SOURCE_DIR}/cmake/user_config.cmake)

set (LIBFILEID_SRC
    libfileid_export.cpp
    FileID.cpp)

add_library (${MY_LIB_NAME} STATIC ${LIBFILEID_SRC})    

