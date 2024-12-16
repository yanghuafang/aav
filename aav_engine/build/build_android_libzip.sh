#!/usr/bin/env sh

#build android

export ANDROID_NDK=~/android-ndk-r9d


##build armeabi

rm -rf lib_build/android/armeabi
mkdir -p lib_build/android/armeabi
cd lib_build/android/armeabi
cmake ../../../../thirdparty/libzip_0.10.1 -DANDROID_BUILD=ON -DARM_BUILD=ON -DARMEABI=ON -DCLANG_BUILD=ON -DRELEASE_BUILD=ON -DANDROID_ABI="armeabi" -DCMAKE_TOOLCHAIN_FILE=../../../../cmake/android.toolchain.cmake
make
cd ../../../


##build armeabi-v7a

rm -rf lib_build/android/armeabi-v7a
mkdir -p lib_build/android/armeabi-v7a
cd lib_build/android/armeabi-v7a
cmake ../../../../thirdparty/libzip_0.10.1 -DANDROID_BUILD=ON -DARM_BUILD=ON -DARMEABI_V7A=ON -DCLANG_BUILD=ON -DRELEASE_BUILD=ON -DANDROID_ABI="armeabi-v7a" -DCMAKE_TOOLCHAIN_FILE=../../../../cmake/android.toolchain.cmake
make
cd ../../../


#build x86

rm -rf lib_build/android/x86
mkdir -p lib_build/android/x86
cd lib_build/android/x86
cmake ../../../../thirdparty/libzip_0.10.1 -DANDROID_BUILD=ON -DX86_BUILD=ON -DCLANG_BUILD=ON -DRELEASE_BUILD=ON -DANDROID_ABI="x86" -DCMAKE_TOOLCHAIN_FILE=../../../../cmake/android.toolchain.cmake
make
cd ../../../


#build mips

rm -rf lib_build/android/mips
mkdir -p lib_build/android/mips
cd lib_build/android/mips
cmake ../../../../thirdparty/libzip_0.10.1 -DANDROID_BUILD=ON -DMIPS_BUILD=ON -DCLANG_BUILD=ON -DRELEASE_BUILD=ON -DANDROID_ABI="mips" -DCMAKE_TOOLCHAIN_FILE=../../../../cmake/android.toolchain.cmake
make
cd ../../../
