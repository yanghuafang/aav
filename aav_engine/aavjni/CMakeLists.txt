cmake_minimum_required(VERSION 2.6 FATAL_ERROR)

project (LIBAAVJNI)

set (MY_TOP_PROJECT_SOURCE_DIR ${PROJECT_SOURCE_DIR}/..)
set (MY_LIB_NAME aavjni)
message (STATUS "process ${MY_LIB_NAME}")

include (${MY_TOP_PROJECT_SOURCE_DIR}/cmake/user_config.cmake)

find_library (LIBPLATFORM platform ${LIBRARY_OUTPUT_PATH})
find_library (LIBUTIL util_ ${LIBRARY_OUTPUT_PATH})
find_library (LIBZIP zip_ ${LIBRARY_OUTPUT_PATH})

set (AAVJNI_SRC
    aavjni.cpp
    jniUtil.cpp
    unzipapk.cpp
    )
add_library (${MY_LIB_NAME} SHARED ${AAVJNI_SRC})

set (CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -L${LIBRARY_OUTPUT_PATH}")
target_link_libraries (${MY_LIB_NAME}
    platform
    util_
    zip_
    z
    log
    )

