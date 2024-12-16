cmake_minimum_required(VERSION 2.6 FATAL_ERROR)

project (LIBFRAMEWORK)

set (MY_TOP_PROJECT_SOURCE_DIR ${PROJECT_SOURCE_DIR}/..)
set (MY_LIB_NAME framework)
message (STATUS "process ${MY_LIB_NAME}")

include (${MY_TOP_PROJECT_SOURCE_DIR}/cmake/user_config.cmake)

set (LIBFRAMEWORK_SRC
    libframework_export.cpp)

add_library (${MY_LIB_NAME} STATIC ${LIBFRAMEWORK_SRC})    

