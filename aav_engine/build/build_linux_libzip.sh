#!/usr/bin/env sh

#export CC=/usr/local/llvm/bin/clang
#export CXX=/usr/local/llvm/bin/clang++


#Debug build for Linux

rm -rf lib_build/linux/x86
mkdir -p lib_build/linux/x86
cd lib_build/linux/x86
cmake ../../../../thirdparty/libzip_0.10.1 -DLINUX_BUILD=ON -DX86_BUILD=ON -DCLANG_BUILD=ON -DDEBUG_BUILD=ON
make
cd ../../../


#Release build for Linux

rm -rf lib_build/linux/x86
mkdir -p lib_build/linux/x86
cd lib_build/linux/x86
cmake ../../../../thirdparty/libzip_0.10.1 -DLINUX_BUILD=ON -DX86_BUILD=ON -DCLANG_BUILD=ON -DRELEASE_BUILD=ON
make
cd ../../../
