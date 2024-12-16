#!/usr/bin/env sh

#build android

export ANDROID_NDK=~/android-ndk-r9d


##build armeabi

rm -rf module_build/android/armeabi
mkdir -p module_build/android/armeabi
cd module_build/android/armeabi
cmake ../../../../ -DANDROID_BUILD=ON -DARM_BUILD=ON -DARMEABI=ON -DCLANG_BUILD=ON -DRELEASE_BUILD=ON -DANDROID_ABI="armeabi" -DCMAKE_TOOLCHAIN_FILE=../../../../cmake/android.toolchain.cmake -DMODULE_BUILD=ON
make
cd ../../../

rm -rf lib_build/android/armeabi
mkdir -p lib_build/android/armeabi
cd lib_build/android/armeabi
cmake ../../../../ -DANDROID_BUILD=ON -DARM_BUILD=ON -DARMEABI=ON -DCLANG_BUILD=ON -DRELEASE_BUILD=ON -DANDROID_ABI="armeabi" -DCMAKE_TOOLCHAIN_FILE=../../../../cmake/android.toolchain.cmake
make
cd ../../../

$ANDROID_NDK/toolchains/arm-linux-androideabi-4.8/prebuilt/linux-x86_64/arm-linux-androideabi/bin/strip --strip-unneeded ../lib/release/android/arm/armeabi/libaavjni.so
$ANDROID_NDK/toolchains/arm-linux-androideabi-4.8/prebuilt/linux-x86_64/arm-linux-androideabi/bin/strip --strip-unneeded ../lib/release/android/arm/armeabi/libaaveng.so


##build armeabi-v7a

rm -rf module_build/android/armeabi-v7a
mkdir -p module_build/android/armeabi-v7a
cd module_build/android/armeabi-v7a
cmake ../../../../ -DANDROID_BUILD=ON -DARM_BUILD=ON -DARMEABI_V7A=ON -DCLANG_BUILD=ON -DRELEASE_BUILD=ON -DANDROID_ABI="armeabi-v7a" -DCMAKE_TOOLCHAIN_FILE=../../../../cmake/android.toolchain.cmake -DMODULE_BUILD=ON
make
cd ../../../

rm -rf lib_build/android/armeabi-v7a
mkdir -p lib_build/android/armeabi-v7a
cd lib_build/android/armeabi-v7a
cmake ../../../../ -DANDROID_BUILD=ON -DARM_BUILD=ON -DARMEABI_V7A=ON -DCLANG_BUILD=ON -DRELEASE_BUILD=ON -DANDROID_ABI="armeabi-v7a" -DCMAKE_TOOLCHAIN_FILE=../../../../cmake/android.toolchain.cmake
make
cd ../../../

$ANDROID_NDK/toolchains/arm-linux-androideabi-4.8/prebuilt/linux-x86_64/arm-linux-androideabi/bin/strip --strip-unneeded ../lib/release/android/arm/armeabi-v7a/libaavjni.so
$ANDROID_NDK/toolchains/arm-linux-androideabi-4.8/prebuilt/linux-x86_64/arm-linux-androideabi/bin/strip --strip-unneeded ../lib/release/android/arm/armeabi-v7a/libaaveng.so


#build x86

rm -rf module_build/android/x86
mkdir -p module_build/android/x86
cd module_build/android/x86
cmake ../../../../ -DANDROID_BUILD=ON -DX86_BUILD=ON -DCLANG_BUILD=ON -DRELEASE_BUILD=ON -DANDROID_ABI="x86" -DCMAKE_TOOLCHAIN_FILE=../../../../cmake/android.toolchain.cmake -DMODULE_BUILD=ON
make
cd ../../../

rm -rf lib_build/android/x86
mkdir -p lib_build/android/x86
cd lib_build/android/x86
cmake ../../../../ -DANDROID_BUILD=ON -DX86_BUILD=ON -DCLANG_BUILD=ON -DRELEASE_BUILD=ON -DANDROID_ABI="x86" -DCMAKE_TOOLCHAIN_FILE=../../../../cmake/android.toolchain.cmake
make
cd ../../../

$ANDROID_NDK/toolchains/x86-4.8/prebuilt/linux-x86_64/i686-linux-android/bin/strip --strip-unneeded ../lib/release/android/x86/libaavjni.so
$ANDROID_NDK/toolchains/x86-4.8/prebuilt/linux-x86_64/i686-linux-android/bin/strip --strip-unneeded ../lib/release/android/x86/libaaveng.so


#build mips

rm -rf module_build/android/mips
mkdir -p module_build/android/mips
cd module_build/android/mips
cmake ../../../../ -DANDROID_BUILD=ON -DMIPS_BUILD=ON -DCLANG_BUILD=ON -DRELEASE_BUILD=ON -DANDROID_ABI="mips" -DCMAKE_TOOLCHAIN_FILE=../../../../cmake/android.toolchain.cmake -DMODULE_BUILD=ON
make
cd ../../../

rm -rf lib_build/android/mips
mkdir -p lib_build/android/mips
cd lib_build/android/mips
cmake ../../../../ -DANDROID_BUILD=ON -DMIPS_BUILD=ON -DCLANG_BUILD=ON -DRELEASE_BUILD=ON -DANDROID_ABI="mips" -DCMAKE_TOOLCHAIN_FILE=../../../../cmake/android.toolchain.cmake
make
cd ../../../

$ANDROID_NDK/toolchains/mipsel-linux-android-4.8/prebuilt/linux-x86_64/mipsel-linux-android/bin/strip --strip-unneeded ../lib/release/android/mips/libaavjni.so
$ANDROID_NDK/toolchains/mipsel-linux-android-4.8/prebuilt/linux-x86_64/mipsel-linux-android/bin/strip --strip-unneeded ../lib/release/android/mips/libaaveng.so

