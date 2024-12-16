cmake_minimum_required(VERSION 2.6 FATAL_ERROR)

project (LIBPLATFORM)

set (MY_TOP_PROJECT_SOURCE_DIR ${PROJECT_SOURCE_DIR}/..)
set (MY_LIB_NAME platform)
message (STATUS "process ${MY_LIB_NAME}")

include (${MY_TOP_PROJECT_SOURCE_DIR}/cmake/user_config.cmake)

add_subdirectory (file)
add_subdirectory (module)
add_subdirectory (memory)

set (LIBPLATFORM_SRC
    ${FILE_SRC}
    ${MODULE_SRC}
    ${MEMORY_SRC}
    libplatform_export.cpp)

add_library (${MY_LIB_NAME} STATIC ${LIBPLATFORM_SRC})    

