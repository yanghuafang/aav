#!/usr/bin/env sh

#export CC=/usr/local/llvm/bin/clang
#export CXX=/usr/local/llvm/bin/clang++


#build linux

rm -rf module_build/linux
mkdir -p module_build/linux
cd module_build/linux
cmake ../../../ -DLINUX_BUILD=ON -DX86_BUILD=ON -DCLANG_BUILD=ON -DDEBUG_BUILD=ON -DANALYSISASSISTDEXINFO=ON -DMODULE_BUILD=ON
make
cd ../../

rm -rf lib_build/linux
mkdir -p lib_build/linux
cd lib_build/linux
cmake ../../../ -DLINUX_BUILD=ON -DX86_BUILD=ON -DCLANG_BUILD=ON -DDEBUG_BUILD=ON -DANALYSISASSISTDEXINFO=ON
make
cd ../../

