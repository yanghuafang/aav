cmake_minimum_required(VERSION 2.6 FATAL_ERROR)

project (AAVSCAN)

set (MY_TOP_PROJECT_SOURCE_DIR ${PROJECT_SOURCE_DIR}/..)
set (MY_BIN_NAME aavscan)
message (STATUS "process ${MY_BIN_NAME}")

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
    add_definitions (-DANALYSISASSISTDEXINFO)
    find_library (LIBDEX dex_analysisassist ${LIBRARY_OUTPUT_PATH})
else (ANALYSISASSISTDEXINFO)
    find_library (LIBDEX dex ${LIBRARY_OUTPUT_PATH})
endif (ANALYSISASSISTDEXINFO)

set (AAVSCAN_SRC
    aavscan.cpp
    unzipapk.cpp
    )
add_executable (${MY_BIN_NAME} ${AAVSCAN_SRC})

if (LINUX_BUILD)
    target_link_libraries (${MY_BIN_NAME}
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
        dl
        z
        )
elseif (ANDROID_BUILD)
    set (CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -L${LIBRARY_OUTPUT_PATH}")
    target_link_libraries (${MY_BIN_NAME}
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

