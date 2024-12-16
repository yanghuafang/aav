include_directories (${MY_TOP_PROJECT_SOURCE_DIR}/inc
    ${MY_TOP_PROJECT_SOURCE_DIR}/framework/inc
    ${MY_TOP_PROJECT_SOURCE_DIR}/sigmgr/inc
    ${MY_TOP_PROJECT_SOURCE_DIR}/fileid/inc
    ${MY_TOP_PROJECT_SOURCE_DIR}/unarch/inc
    ${MY_TOP_PROJECT_SOURCE_DIR}/unpack/inc
    ${MY_TOP_PROJECT_SOURCE_DIR}/scanner/inc
    ${MY_TOP_PROJECT_SOURCE_DIR}/scanner/apk/inc
    ${MY_TOP_PROJECT_SOURCE_DIR}/scanner/dex/inc
    ${MY_TOP_PROJECT_SOURCE_DIR}/platform/inc
    ${MY_TOP_PROJECT_SOURCE_DIR}/platform/file/inc
    ${MY_TOP_PROJECT_SOURCE_DIR}/platform/module/inc
    ${MY_TOP_PROJECT_SOURCE_DIR}/platform/memory/inc
    ${MY_TOP_PROJECT_SOURCE_DIR}/util/inc
    ${MY_TOP_PROJECT_SOURCE_DIR}/util/crc32/inc
    ${MY_TOP_PROJECT_SOURCE_DIR}/thirdparty/libzip_0.10.1
    )

set (EXECUTABLE_OUTPUT_PATH ${MY_TOP_PROJECT_SOURCE_DIR}/bin)
set (LIBRARY_OUTPUT_PATH ${MY_TOP_PROJECT_SOURCE_DIR}/lib)

if (DEBUG_BUILD)
    if (LINUX_BUILD)
        if (X86_BUILD)
            set (EXECUTABLE_OUTPUT_PATH ${MY_TOP_PROJECT_SOURCE_DIR}/bin/debug/linux/x86)
            set (LIBRARY_OUTPUT_PATH ${MY_TOP_PROJECT_SOURCE_DIR}/lib/debug/linux/x86)
        endif (X86_BUILD)
    elseif (ANDROID_BUILD)
        if (ARM_BUILD)
            if (ARMEABI)
                set (EXECUTABLE_OUTPUT_PATH ${MY_TOP_PROJECT_SOURCE_DIR}/bin/debug/android/arm/armeabi)
                set (LIBRARY_OUTPUT_PATH ${MY_TOP_PROJECT_SOURCE_DIR}/lib/debug/android/arm/armeabi)
            elseif (ARMEABI_V7A)
                set (EXECUTABLE_OUTPUT_PATH ${MY_TOP_PROJECT_SOURCE_DIR}/bin/debug/android/arm/armeabi-v7a)
                set (LIBRARY_OUTPUT_PATH ${MY_TOP_PROJECT_SOURCE_DIR}/lib/debug/android/arm/armeabi-v7a)
            else (ARMEABI)
                message (FATAL_ERROR "error: unknown ANDROID_ABI.")
            endif (ARMEABI)
        elseif (X86_BUILD)
            set (EXECUTABLE_OUTPUT_PATH ${MY_TOP_PROJECT_SOURCE_DIR}/bin/debug/android/x86)
            set (LIBRARY_OUTPUT_PATH ${MY_TOP_PROJECT_SOURCE_DIR}/lib/debug/android/x86)
        elseif (MIPS_BUILD)
            set (EXECUTABLE_OUTPUT_PATH ${MY_TOP_PROJECT_SOURCE_DIR}/bin/debug/android/mips)
            set (LIBRARY_OUTPUT_PATH ${MY_TOP_PROJECT_SOURCE_DIR}/lib/debug/android/mips)
        endif (ARM_BUILD)
    endif (LINUX_BUILD)
elseif (RELEASE_BUILD)
    if (LINUX_BUILD)
        if (X86_BUILD)
            set (EXECUTABLE_OUTPUT_PATH ${MY_TOP_PROJECT_SOURCE_DIR}/bin/release/linux/x86)
            set (LIBRARY_OUTPUT_PATH ${MY_TOP_PROJECT_SOURCE_DIR}/lib/release/linux/x86)
        endif (X86_BUILD)
    elseif (ANDROID_BUILD)
        if (ARM_BUILD)
            if (ARMEABI)
                set (EXECUTABLE_OUTPUT_PATH ${MY_TOP_PROJECT_SOURCE_DIR}/bin/release/android/arm/armeabi)
                set (LIBRARY_OUTPUT_PATH ${MY_TOP_PROJECT_SOURCE_DIR}/lib/release/android/arm/armeabi)
            elseif (ARMEABI_V7A)
                set (EXECUTABLE_OUTPUT_PATH ${MY_TOP_PROJECT_SOURCE_DIR}/bin/release/android/arm/armeabi-v7a)
                set (LIBRARY_OUTPUT_PATH ${MY_TOP_PROJECT_SOURCE_DIR}/lib/release/android/arm/armeabi-v7a)
            else (ARMEABI)
                message (FATAL_ERROR "error: unknown ANDROID_ABI.")
            endif (ARMEABI)
        elseif (X86_BUILD)
            set (EXECUTABLE_OUTPUT_PATH ${MY_TOP_PROJECT_SOURCE_DIR}/bin/release/android/x86)
            set (LIBRARY_OUTPUT_PATH ${MY_TOP_PROJECT_SOURCE_DIR}/lib/release/android/x86)
        elseif (MIPS_BUILD)
            set (EXECUTABLE_OUTPUT_PATH ${MY_TOP_PROJECT_SOURCE_DIR}/bin/release/android/mips)
            set (LIBRARY_OUTPUT_PATH ${MY_TOP_PROJECT_SOURCE_DIR}/lib/release/android/mips)
        endif (ARM_BUILD)
    endif (LINUX_BUILD)
endif (DEBUG_BUILD)

if (LINUX_BUILD)
    message (STATUS "build Linux.")
    if (CLANG_BUILD)
        message (STATUS "build with clang.")
        if (EXISTS /usr/local/llvm/share/llvm/cmake)
            set (CMAKE_C_COMPILER "/usr/local/llvm/bin/clang")
            set (CMAKE_CXX_COMPILER "/usr/local/llvm/bin/clang++")
            set (LLVM_DIR "/usr/local/llvm/share/llvm/cmake")
            find_package (LLVM REQUIRED CONFIG)
            message (STATUS "found LLVM ${LLVM_PACKAGE_VERSION}")
            message (STATUS "use LLVMConfig.cmake in: ${LLVM_DIR}")
            include_directories (${LLVM_INCLUDE_DIRS})
            message (STATUS "LLVM_INCLUDE_DIRS: ${LLVM_INCLUDE_DIRS}")
            add_definitions (${LLVM_DEFINITIONS})
            message (STATUS "LLVM_DEFINITIONS: ${LLVM_DEFINITIONS}")
            #llvm_map_components_to_libnames (llvm_libs support core irreader)
            #target_link_libraries(${MY_LIB_NAME} ${llvm_libs})
        endif (EXISTS /usr/local/llvm/share/llvm/cmake)
    elseif (GCC_BUILD)
        message (STATUS "build with gcc.")
    else (CLANG_BUILD)
        message (FATAL_ERROR "error: build with clang or gcc?")
    endif (CLANG_BUILD)
elseif (ANDROID_BUILD)
    set (CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -llog")
    set (CMAKE_TOOLCHAIN_FILE "${MY_TOP_PROJECT_SOURCE_DIR}/cmake/android.toolchain.cmake")
    message (STATUS "build Android.")
    set (ANDROID_NDK "~/android_ndk_r9d")
    set (ANDROID_NATIVE_API_LEVEL "android-9")
    set (ANDROID_STL "gnustl_static") 
    set (ANDROID_STL_FORCE_FEATURES ON)
    if (ARM_BUILD)
        message (STATUS "build ARM.")
        if (ARMEABI)
            set (ANDROID_ABI "armeabi")
            message (STATUS "build armeabi")
        elseif (ARMEABI_V7A)
            set (ANDROID_ABI "armeabi-v7a")
            message (STATUS "build armeabi-v7a")
        else (ARMEABI)
            message (FATAL_ERROR "error: unknown ANDROID_ABI.")
        endif (ARMEABI)
        if (CLANG_BUILD)
            message (STATUS "build with clang.")
            set (ANDROID_TOOLCHAIN_NAME "arm-linux-androideabi-clang3.4")
        elseif (GCC_BUILD)
            message (STATUS "build with gcc.")
            set (ANDROID_TOOLCHAIN_NAME "arm-linux-androideabi-4.8")
        else (CLANG_BUILD)
            message (FATAL_ERROR "error: build with clang or gcc?")
        endif (CLANG_BUILD)
    elseif (X86_BUILD)
        message (STATUS "build x86.")
        set (ANDROID_ABI "x86")
        if (CLANG_BUILD)
            message (STATUS "build with clang.")
            set (ANDROID_TOOLCHAIN_NAME "x86-clang3.4")
        elseif (GCC_BUILD)
            message (STATUS "build with gcc.")
            set (ANDROID_TOOLCHAIN_NAME "x86-4.8")
        else (CLANG_BUILD)
            message (FATAL_ERROR "error: build with clang or gcc?")
        endif (CLANG_BUILD)
    elseif (MIPS_BUILD)
        message (STATUS "build MIPS.")
        set (ANDROID_ABI "mips")
        if (CLANG_BUILD)
            message (STATUS "build with clang.")
            set (ANDROID_TOOLCHAIN_NAME "mipsel-linux-android-clang3.4")
        elseif (GCC_BUILD)
            message (STATUS "build with gcc.")
            set (ANDROID_TOOLCHAIN_NAME "mipsel-linux-android-4.8")
        else (CLANG_BUILD)
            message (FATAL_ERROR "error: build with clang or gcc?")
        endif (CLANG_BUILD)
    else (ARM_BUILD)
        message (FATAL_ERROR "error: build ARM or x86 or MIPS?")
    endif (ARM_BUILD)
else (LINUX_BUILD)
    message (FATAL_ERROR "error: build for Linux or Android?")
endif (LINUX_BUILD)

if (RELEASE_BUILD)
    message (STATUS "build Release.")
    set (CMAKE_BUILD_TYPE "Release")
elseif (RELEASE_WITH_DEBUG_INFO_BUILD)
    message (STATUS "build RelWithDebInfo.")
    set (CMAKE_BUILD_TYPE "RelWithDebInfo")
elseif (DEBUG_BUILD)
    message (STATUS "build Debug.")
    set (CMAKE_BUILD_TYPE "Debug")
else (RELEASE_BUILD)
    message (FATAL_ERROR "error: unknown build type!")
endif (RELEASE_BUILD)

#set (CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11")
set (CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++0x")
set (CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fPIC")

set (CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fvisibility=hidden") 
set (CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fvisibility=hidden") 

if (DEBUG_BUILD)
    add_definitions (-DDEBUG_BUILD)
endif (DEBUG_BUILD)

if (ANDROID_BUILD)
    add_definitions (-DANDROID_BUILD)
endif (ANDROID_BUILD)

