cmake_minimum_required(VERSION 2.6 FATAL_ERROR)

project (LIBAAVENG)

set (MY_TOP_PROJECT_SOURCE_DIR ${PROJECT_SOURCE_DIR}/..)
set (MY_LIB_NAME aaveng)
message (STATUS "process ${MY_LIB_NAME}")

include (${MY_TOP_PROJECT_SOURCE_DIR}/cmake/user_config.cmake)

find_library (LIBFRAMEWORK framework ${LIBRARY_OUTPUT_PATH})
find_library (LIBSIGMGR sigmgr ${LIBRARY_OUTPUT_PATH})
find_library (LIBFILEID fileid ${LIBRARY_OUTPUT_PATH})
find_library (LIBUNARCH unarch ${LIBRARY_OUTPUT_PATH})
find_library (LIBUNPACK unpack ${LIBRARY_OUTPUT_PATH})
find_library (LIBAPK apk ${LIBRARY_OUTPUT_PATH})
#find_library (LIBDEX dex ${LIBRARY_OUTPUT_PATH})
find_library (LIBPLATFORM platform ${LIBRARY_OUTPUT_PATH})
find_library (LIBUTIL util_ ${LIBRARY_OUTPUT_PATH})
find_library (LIBZIP zip_ ${LIBRARY_OUTPUT_PATH})

if (ANALYSISASSISTDEXINFO)
    find_library (LIBDEX dex_analysisassist ${LIBRARY_OUTPUT_PATH})
else (ANALYSISASSISTDEXINFO)
    find_library (LIBDEX dex ${LIBRARY_OUTPUT_PATH})
endif (ANALYSISASSISTDEXINFO)

add_library (${MY_LIB_NAME} SHARED aaveng.cpp)

if (LINUX_BUILD)
    target_link_libraries (${MY_LIB_NAME}
        ${LIBFRAMEWORK}
        ${LIBSIGMGR}
        ${LIBFILEID}
        ${LIBUNARCH}
        ${LIBUNPACK}
        ${LIBAPK}
        ${LIBDEX}
        ${LIBPLATFORM}
        ${LIBUTIL}
        ${LIBZIP}
        z
        )
elseif (ANDROID_BUILD)
    set (CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -L${LIBRARY_OUTPUT_PATH}")
    target_link_libraries (${MY_LIB_NAME}
        framework
        sigmgr
        fileid
        unarch
        unpack
        apk
        dex
        platform
        util_
        zip_
        z
        )
endif (LINUX_BUILD)
