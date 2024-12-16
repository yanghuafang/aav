cmake_minimum_required(VERSION 2.6 FATAL_ERROR)

project (LIBSIGMGR)

set (MY_TOP_PROJECT_SOURCE_DIR ${PROJECT_SOURCE_DIR}/..)
set (MY_LIB_NAME sigmgr)
message (STATUS "process ${MY_LIB_NAME}")

include (${MY_TOP_PROJECT_SOURCE_DIR}/cmake/user_config.cmake)

#add_subdirectory (crc32)

set (LIBSIGMGR_SRC
	FileUncompress.cpp
	BlowFish.cpp
	SigMgr.cpp	
    	libsigmgr_export.cpp)

add_library (${MY_LIB_NAME} STATIC ${LIBSIGMGR_SRC})

