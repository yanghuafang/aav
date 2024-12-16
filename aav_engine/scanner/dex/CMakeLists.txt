cmake_minimum_required(VERSION 2.6 FATAL_ERROR)

project (LIBDEX)

set (MY_TOP_PROJECT_SOURCE_DIR ${PROJECT_SOURCE_DIR}/../..)
set (MY_LIB_NAME dex)
message (STATUS "process ${MY_LIB_NAME}")

include (${MY_TOP_PROJECT_SOURCE_DIR}/cmake/user_config.cmake)

set (LIBDEX_SRC
    libdex_export.cpp
    mutf8.cpp
    leb128.cpp
    DexSigMgr.cpp
    DexPathSigMgr.cpp
    DexCodeSigMgr.cpp
    DexPathScanResult.cpp
    DexPathScanResultMgr.cpp
    DexCodeScanResult.cpp
    DexCodeScanResultMgr.cpp
    DexParser.cpp
    DexFile.cpp
    DexCode.cpp
    DexScanner.cpp
    ACMatcher.cpp
    )

if (DEBUG_BUILD)
    add_definitions (-DDEBUG_BUILD)
endif (DEBUG_BUILD)

if (ANALYSISASSISTDEXINFO)
    add_definitions (-DANALYSISASSISTDEXINFO)
    set (LIBDEX_SRC
        ${LIBDEX_SRC}
        AnalysisAssistDexInfo.cpp
        )
    add_library (dex_analysisassist STATIC ${LIBDEX_SRC})
else (ANALYSISASSISTDEXINFO)
    add_library (${MY_LIB_NAME} STATIC ${LIBDEX_SRC})
endif (ANALYSISASSISTDEXINFO)

