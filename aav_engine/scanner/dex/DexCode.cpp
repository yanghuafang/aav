#include "DexCode.h"

#include <assert.h>
#include <stdio.h>

#include <algorithm>
#include <iostream>
#include <new>

#include "DexCodeSigMgr.h"
#include "DexFile.h"
#include "IMemCRC32.h"
#include "libutil_export.h"
using namespace std;

#ifdef ANALYSISASSISTDEXINFO
const DexInstruction instructionFirstTable[] = {
    {0x00, 2, "nop"},
    {0x01, 2, "move vA, vB"},
    {0x02, 4, "move/from16 vAA, vBBBB"},
    {0x03, 6, "move/16 vAAAA, vBBBB"},
    {0x04, 2, "move-wide vA, vB"},
    {0x05, 4, "move-wide/from16 vAA, vBBBB"},
    {0x06, 6, "move-wide/16 vAAAA, vBBBB"},
    {0x07, 2, "move-object vA, vB "},
    {0x08, 4, "move-object/from16 vAA, vBBBB"},
    {0x09, 6, "move-object/16 vAAAA, vBBBB"},
    {0x0a, 2, "move-result vAA"},
    {0x0b, 2, "move-result-wide vAA"},
    {0x0c, 2, "move-result-object vAA"},
    {0x0d, 2, "move-exception vAA"},
    {0x0e, 2, "return-void"},
    {0x0f, 2, "return vAA"},
    {0x10, 2, "return-wide vAA"},
    {0x11, 2, "return-object vAA"},
    {0x12, 2, "const/4 vA, #+B"},
    {0x13, 4, "const/16 vAA, #+BBBB"},
    {0x14, 6, "const vAA, #+BBBBBBBB"},
    {0x15, 4, "const/high16 vAA, #+BBBB0000"},
    {0x16, 4, "const-wide/16 vAA, #+BBBB"},
    {0x17, 6, "const-wide/32 vAA, #+BBBBBBBB"},
    {0x18, 10, "const-wide vAA, #+BBBBBBBBBBBBBBBB"},
    {0x19, 4, "const-wide/high16 vAA, #+BBBB000000000000"},
    {0x1a, 4, "const-string vAA, string@BBBB"},
    {0x1b, 6, "const-string/jumbo vAA, string@BBBBBBBB"},
    {0x1c, 4, "const-class vAA, type@BBBB"},
    {0x1d, 2, "monitor-enter vAA"},
    {0x1e, 2, "monitor-exit vAA"},
    {0x1f, 4, " check-cast vAA, type@BBBB "},
    {0x20, 4, "instance-of vA, vB, type@CCCC"},
    {0x21, 2, "array-length vA, vB"},
    {0x22, 4, "new-instance vAA, type@BBBB"},
    {0x23, 4, "new-array vA, vB, type@CCCC"},
    {0x24, 6, "filled-new-array {vC, vD, vE, vF, vG}, type@BBBB"},
    {0x25, 6, "filled-new-array/range {vCCCC .. vNNNN}, type@BBBB"},
    {0x26, 6, "fill-array-data vAA, +BBBBBBBB"},
    {0x27, 2, "throw vAA"},
    {0x28, 2, "goto +AA"},
    {0x29, 4, "goto/16 +AAAA"},
    {0x2a, 6, "goto/32 +AAAAAAAA"},
    {0x2b, 6, "packed-switch vAA, +BBBBBBBB"},
    {0x2c, 6, "sparse-switch vAA, +BBBBBBBB"},

    // 2d..31    //23x    //cmpkind vAA, vBB, vCC
    {0x2d, 4, "cmpl-float"},
    {0x2e, 4, "cmpg-float"},
    {0x2f, 4, "cmpl-double"},
    {0x30, 4, "cmpg-double"},
    {0x31, 4, "cmp-long"},

    // 32..37    //22t    //if-test vA, vB, +CCCC
    {0x32, 4, "if-eq"},
    {0x33, 4, "if-ne"},
    {0x34, 4, "if-lt"},
    {0x35, 4, "if-ge"},
    {0x36, 4, "if-gt"},
    {0x37, 4, "if-le"},

    // 38..3d    //21t    //if-testz vAA, +BBBB
    {0x38, 4, "if-eqz"},
    {0x39, 4, "if-nez"},
    {0x3a, 4, "if-ltz"},
    {0x3b, 4, "if-gez"},
    {0x3c, 4, "if-gtz"},
    {0x3d, 4, "if-lez"},

    // 3e..43    //10x    //unused
    {0x3e, 2, "unused"},
    {0x3f, 2, "unused"},
    {0x40, 2, "unused"},
    {0x41, 2, "unused"},
    {0x42, 2, "unused"},
    {0x43, 2, "unused"},

    // 44..51    //23x    //arrayop vAA, vBB, vCC
    {0x44, 4, "aget"},
    {0x45, 4, "aget-wide"},
    {0x46, 4, "aget-object"},
    {0x47, 4, "aget-boolean"},
    {0x48, 4, "aget-byte"},
    {0x49, 4, "aget-char"},
    {0x4a, 4, "aget-short"},
    {0x4b, 4, "aput"},
    {0x4c, 4, "aput-wide"},
    {0x4d, 4, "aput-object"},
    {0x4e, 4, "aput-boolean"},
    {0x4f, 4, "aput-byte"},
    {0x50, 4, "aput-char"},
    {0x51, 4, "aput-short"},

    // 52..5f    //22c    //iinstanceop vA, vB, field@CCCC
    {0x52, 4, "iget"},
    {0x53, 4, "iget-wide"},
    {0x54, 4, "iget-object"},
    {0x55, 4, "iget-boolean"},
    {0x56, 4, "iget-byte"},
    {0x57, 4, "iget-char"},
    {0x58, 4, "iget-short"},
    {0x59, 4, "iput"},
    {0x5a, 4, "iput-wide"},
    {0x5b, 4, "iput-object"},
    {0x5c, 4, "iput-boolean"},
    {0x5d, 4, "iput-byte"},
    {0x5e, 4, "iput-char"},
    {0x5f, 4, "iput-short"},

    // 60..6d    //21c    //sstaticop vAA, field@BBBB
    {0x60, 4, "sget"},
    {0x61, 4, "sget-wide"},
    {0x62, 4, "sget-object"},
    {0x63, 4, "sget-boolean"},
    {0x64, 4, "sget-byte"},
    {0x65, 4, "sget-char"},
    {0x66, 4, "sget-short"},
    {0x67, 4, "sput"},
    {0x68, 4, "sput-wide"},
    {0x69, 4, "sput-object"},
    {0x6a, 4, "sput-boolean"},
    {0x6b, 4, "sput-byte"},
    {0x6c, 4, "sput-char"},
    {0x6d, 4, "sput-short"},

    // 6e..72    //35c    //invoke-kind {vC, vD, vE, vF, vG}, meth@BBBB
    {0x6e, 6, "invoke-virtual"},
    {0x6f, 6, "invoke-super"},
    {0x70, 6, "invoke-direct"},
    {0x71, 6, "invoke-static"},
    {0x72, 6, "invoke-interface"},

    {0x73, 2, "unused    //10x"},

    // 74..78    //3rc    //invoke-kind/range {vCCCC .. vNNNN}, meth@BBBB
    {0x74, 6, "invoke-virtual/range"},
    {0x75, 6, "invoke-super/range"},
    {0x76, 6, "invoke-direct/range"},
    {0x77, 6, "invoke-static/range"},
    {0x78, 6, "invoke-interface/range"},

    // 79..7a    //10x    //unused
    {0x79, 2, "unused"},
    {0x7a, 2, "unused"},

    // 7b..8f    //12x    //unop vA, vB
    {0x7b, 2, "neg-int"},
    {0x7c, 2, "not-int"},
    {0x7d, 2, "neg-long"},
    {0x7e, 2, "not-long"},
    {0x7f, 2, "neg-float"},
    {0x80, 2, "net-double"},
    {0x81, 2, "int-to-long"},
    {0x82, 2, "int-to-float"},
    {0x83, 2, "int-to-double"},
    {0x84, 2, "long-to-int"},
    {0x85, 2, "long-to-float"},
    {0x86, 2, "long-to-double"},
    {0x87, 2, "float-to-int"},
    {0x88, 2, "float-to-long"},
    {0x89, 2, "float-to-double"},
    {0x8a, 2, "double-to-int"},
    {0x8b, 2, "double-to-long"},
    {0x8c, 2, "double-to-float"},
    {0x8d, 2, "int-to-byte"},
    {0x8e, 2, "int-to-char"},
    {0x8f, 2, "int-to-short"},

    // 90..af    //23x    //binop vAA, vBB, vCC
    {0x90, 4, "add-int"},
    {0x91, 4, "sub-int"},
    {0x92, 4, "mul-int"},
    {0x93, 4, "div-int"},
    {0x94, 4, "rem-int"},
    {0x95, 4, "and-int"},
    {0x96, 4, "or-int"},
    {0x97, 4, "xor-int"},
    {0x98, 4, "shl-int"},
    {0x99, 4, "shr-int"},
    {0x9a, 4, "ushr-int"},
    {0x9b, 4, "add-long"},
    {0x9c, 4, "sub-long"},
    {0x9d, 4, "mul-long"},
    {0x9e, 4, "div-long"},
    {0x9f, 4, "rem-long"},
    {0xa0, 4, "and-long"},
    {0xa1, 4, "or-long"},
    {0xa2, 4, "xor-long"},
    {0xa3, 4, "shl-long"},
    {0xa4, 4, "shr-long"},
    {0xa5, 4, "ushr-long"},
    {0xa6, 4, "add-float"},
    {0xa7, 4, "sub-float"},
    {0xa8, 4, "mul-float"},
    {0xa9, 4, "div-float"},
    {0xaa, 4, "rem-float"},
    {0xab, 4, "add-double"},
    {0xac, 4, "sub-double"},
    {0xad, 4, "mul-double"},
    {0xae, 4, "div-double"},
    {0xaf, 4, "rem-double"},

    // b0..cf    //12x    //binop/2addr vA, vB
    {0xb0, 2, "add-int/2addr"},
    {0xb1, 2, "sub-int/2addr"},
    {0xb2, 2, "mul-int/2addr"},
    {0xb3, 2, "div-int/2addr"},
    {0xb4, 2, "rem-int/2addr"},
    {0xb5, 2, "and-int/2addr"},
    {0xb6, 2, "or-int/2addr"},
    {0xb7, 2, "xor-int/2addr"},
    {0xb8, 2, "shl-int/2addr"},
    {0xb9, 2, "shr-int/2addr"},
    {0xba, 2, "ushr-int/2addr"},
    {0xbb, 2, "add-long/2addr"},
    {0xbc, 2, "sub-long/2addr"},
    {0xbd, 2, "mul-long/2addr"},
    {0xbe, 2, "div-long/2addr"},
    {0xbf, 2, "rem-long/2addr"},
    {0xc0, 2, "and-long/2addr"},
    {0xc1, 2, "or-long/2addr"},
    {0xc2, 2, "xor-long/2addr"},
    {0xc3, 2, "shl-long/2addr"},
    {0xc4, 2, "shr-long/2addr"},
    {0xc5, 2, "ushr-long/2addr"},
    {0xc6, 2, "add-float/2addr"},
    {0xc7, 2, "sub-float/2addr"},
    {0xc8, 2, "mul-float/2addr"},
    {0xc9, 2, "div-float/2addr"},
    {0xca, 2, "rem-float/2addr"},
    {0xcb, 2, "add-double/2addr"},
    {0xcc, 2, "sub-double/2addr"},
    {0xcd, 2, "mul-double/2addr"},
    {0xce, 2, "div-double/2addr"},
    {0xcf, 2, "rem-double/2addr"},

    // d0..d7    //22a    //binop/lit16 vA, vB, #+CCCC
    {0xd0, 4, "add-int/lit16"},
    {0xd1, 4, "rsub-int"},
    {0xd2, 4, "mul-int/lit16"},
    {0xd3, 4, "div-int/lit16"},
    {0xd4, 4, "rem-int/lit16"},
    {0xd5, 4, "and-int/lit16"},
    {0xd6, 4, "or-int/lit16"},
    {0xd7, 4, "xor-int/lit16"},

    // d8..e2    //22b    //binop/lit8 vAA, vBB, #+CC
    {0xd8, 4, "add-int/lit8"},
    {0xd9, 4, "rsub-int/lit8"},
    {0xda, 4, "mul-int/lit8"},
    {0xdb, 4, "div-int/lit8"},
    {0xdc, 4, "rem-int/lit8"},
    {0xdd, 4, "and-int/lit8"},
    {0xde, 4, "or-int/lit8"},
    {0xdf, 4, "xor-int/lit8"},
    {0xe0, 4, "shl-int/lit8"},
    {0xe1, 4, "shr-int/lit8"},
    {0xe2, 4, "ushr-int/lit8"},

    // e3..fe    //10x    //unused
    {0xe3, 2, "unused"},
    {0xe4, 2, "unused"},
    {0xe5, 2, "unused"},
    {0xe6, 2, "unused"},
    {0xe7, 2, "unused"},
    {0xe8, 2, "unused"},
    {0xe9, 2, "unused"},
    {0xea, 2, "unused"},
    {0xeb, 2, "unused"},
    {0xec, 2, "unused"},
    {0xed, 2, "unused"},
    {0xee, 2, "unused"},
    {0xef, 2, "unused"},
    {0xf0, 2, "unused"},
    {0xf1, 2, "unused"},
    {0xf2, 2, "unused"},
    {0xf3, 2, "unused"},
    {0xf4, 2, "unused"},
    {0xf5, 2, "unused"},
    {0xf6, 2, "unused"},
    {0xf7, 2, "unused"},
    {0xf8, 2, "unused"},
    {0xf9, 2, "unused"},
    {0xfa, 2, "unused"},
    {0xfb, 2, "unused"},
    {0xfc, 2, "unused"},
    {0xfd, 2, "unused"},
    {0xfe, 2, "unused"},
};

const DexInstruction instructionSecondTable[] = {
    // 0xff    //(expanded opcode)
    {0x00ff, 8, "const-class/jumbo vAAAA, type@BBBBBBBB"},
    {0x01ff, 8, "check-cast/jumbo vAAAA, type@BBBBBBBB"},
    {0x02ff, 10, "instance-of/jumbo vAAAA, vBBBB, type@CCCCCCCC"},
    {0x03ff, 8, "new-instance/jumbo vAAAA, type@BBBBBBBB"},
    {0x04ff, 10, "new-array/jumbo vAAAA, vBBBB, type@CCCCCCCC"},
    {0x05ff, 10, "filled-new-array/jumbo {vCCCC .. vNNNN}, type@BBBBBBBB"},

    // 06ff..13ff    //52c    //iinstanceop/jumbo vAAAA, vBBBB, field@CCCCCCCC
    {0x06ff, 10, "iget/jumbo"},
    {0x07ff, 10, "iget-wide/jumbo"},
    {0x08ff, 10, "iget-object/jumbo"},
    {0x09ff, 10, "iget-boolean/jumbo"},
    {0x0aff, 10, "iget-byte/jumbo"},
    {0x0bff, 10, "iget-char/jumbo"},
    {0x0cff, 10, "iget-short/jumbo"},
    {0x0dff, 10, "iput/jumbo"},
    {0x0eff, 10, "iput-wide/jumbo"},
    {0x0fff, 10, "iput-object/jumbo"},
    {0x10ff, 10, "iput-boolean/jumbo"},
    {0x11ff, 10, "iput-byte/jumbo"},
    {0x12ff, 10, "iput-char/jumbo"},
    {0x13ff, 10, "iput-short/jumbo"},

    // 14ff..21ff    //41c    //sstaticop/jumbo vAAAA, field@BBBBBBBB
    {0x14ff, 8, "sget/jumbo"},
    {0x15ff, 8, "sget-wide/jumbo"},
    {0x16ff, 8, "sget-object/jumbo"},
    {0x17ff, 8, "sget-boolean/jumbo"},
    {0x18ff, 8, "sget-byte/jumbo"},
    {0x19ff, 8, "sget-char/jumbo"},
    {0x1aff, 8, "sget-short/jumbo"},
    {0x1bff, 8, "sput/jumbo"},
    {0x1cff, 8, "sput-wide/jumbo"},
    {0x1dff, 8, "sput-object/jumbo"},
    {0x1eff, 8, "sput-boolean/jumbo"},
    {0x1fff, 8, "sput-byte/jumbo"},
    {0x20ff, 8, "sput-char/jumbo"},
    {0x21ff, 8, "sput-short/jumbo"},

    // 22ff..26ff    //5rc    //invoke-kind/jumbo {vCCCC .. vNNNN},
    // meth@BBBBBBBB
    {0x22ff, 10, "invoke-virtual/jumbo"},
    {0x23ff, 10, "invoke-super/jumbo"},
    {0x24ff, 10, "invoke-direct/jumbo"},
    {0x25ff, 10, "invoke-static/jumbo"},
    {0x26ff, 10, "invoke-interface/jumbo"},
};

#else

const DexInstruction instructionFirstTable[] = {
    {0x00, 2},   // nop    //10x
    {0x01, 2},   // move vA, vB    //12x
    {0x02, 4},   // move/from16 vAA, vBBBB    //22x
    {0x03, 6},   // move/16 vAAAA, vBBBB    //32x
    {0x04, 2},   // move-wide vA, vB    //12x
    {0x05, 4},   // move-wide/from16 vAA, vBBBB    //22x
    {0x06, 6},   // move-wide/16 vAAAA, vBBBB    //32x
    {0x07, 2},   // move-object vA, vB     //12x
    {0x08, 4},   // move-object/from16 vAA, vBBBB    //22x
    {0x09, 6},   // move-object/16 vAAAA, vBBBB    //32x
    {0x0a, 2},   // move-result vAA    //11x
    {0x0b, 2},   // move-result-wide vAA    //11x
    {0x0c, 2},   // move-result-object vAA    //11x
    {0x0d, 2},   // move-exception vAA    //11x
    {0x0e, 2},   // return-void    //10x
    {0x0f, 2},   // return vAA    //11x
    {0x10, 2},   // return-wide vAA    //11x
    {0x11, 2},   // return-object vAA    //11x
    {0x12, 2},   // const/4 vA, #+B    //11n
    {0x13, 4},   // const/16 vAA, #+BBBB    //21s
    {0x14, 6},   // const vAA, #+BBBBBBBB    //31i
    {0x15, 4},   // const/high16 vAA, #+BBBB0000    //21h
    {0x16, 4},   // const-wide/16 vAA, #+BBBB    //21s
    {0x17, 6},   // const-wide/32 vAA, #+BBBBBBBB    //31i
    {0x18, 10},  // const-wide vAA, #+BBBBBBBBBBBBBBBB    //51l
    {0x19, 4},   // const-wide/high16 vAA, #+BBBB000000000000    //21h
    {0x1a, 4},   // const-string vAA, string@BBBB    //21c
    {0x1b, 6},   // const-string/jumbo vAA, string@BBBBBBBB    //31c
    {0x1c, 4},   // const-class vAA, type@BBBB    //21c
    {0x1d, 2},   // monitor-enter vAA    //11x
    {0x1e, 2},   // monitor-exit vAA    //11x
    {0x1f, 4},   // check-cast vAA, type@BBBB     //21c
    {0x20, 4},   // instance-of vA, vB, type@CCCC    //22c
    {0x21, 2},   // array-length vA, vB    //12x
    {0x22, 4},   // new-instance vAA, type@BBBB    //21c
    {0x23, 4},   // new-array vA, vB, type@CCCC    //22c
    {0x24, 6},   // filled-new-array {vC, vD, vE, vF, vG}, type@BBBB    //35c
    {0x25, 6},   // filled-new-array/range {vCCCC .. vNNNN}, type@BBBB    //3rc
    {0x26, 6},   // fill-array-data vAA, +BBBBBBBB (with supplemental data as
                // specified below in "fill-array-data-payload Format")    //31t
    {0x27, 2},  // throw vAA    //11x
    {0x28, 2},  // goto +AA    //10t
    {0x29, 4},  // goto/16 +AAAA    //20t
    {0x2a, 6},  // goto/32 +AAAAAAAA    //30t
    {0x2b, 6},  // packed-switch vAA, +BBBBBBBB (with supplemental data as
                // specified below in "packed-switch-payload Format")    //31t
    {0x2c, 6},  // sparse-switch vAA, +BBBBBBBB (with supplemental data as
                // specified below in "sparse-switch-payload Format")    //31t

    // 2d..31    //23x    //cmpkind vAA, vBB, vCC
    {0x2d, 4},  // cmpl-float
    {0x2e, 4},  // cmpg-float
    {0x2f, 4},  // cmpl-double
    {0x30, 4},  // cmpg-double
    {0x31, 4},  // cmp-long

    // 32..37    //22t    //if-test vA, vB, +CCCC
    {0x32, 4},  // if-eq
    {0x33, 4},  // if-ne
    {0x34, 4},  // if-lt
    {0x35, 4},  // if-ge
    {0x36, 4},  // if-gt
    {0x37, 4},  // if-le

    // 38..3d    //21t    //if-testz vAA, +BBBB
    {0x38, 4},  // if-eqz
    {0x39, 4},  // if-nez
    {0x3a, 4},  // if-ltz
    {0x3b, 4},  // if-gez
    {0x3c, 4},  // if-gtz
    {0x3d, 4},  // if-lez

    // 3e..43    //10x    //unused
    {0x3e, 2},
    {0x3f, 2},
    {0x40, 2},
    {0x41, 2},
    {0x42, 2},
    {0x43, 2},

    // 44..51    //23x    //arrayop vAA, vBB, vCC
    {0x44, 4},  // aget
    {0x45, 4},  // aget-wide
    {0x46, 4},  // aget-object
    {0x47, 4},  // aget-boolean
    {0x48, 4},  // aget-byte
    {0x49, 4},  // aget-char
    {0x4a, 4},  // aget-short
    {0x4b, 4},  // aput
    {0x4c, 4},  // aput-wide
    {0x4d, 4},  // aput-object
    {0x4e, 4},  // aput-boolean
    {0x4f, 4},  // aput-byte
    {0x50, 4},  // aput-char
    {0x51, 4},  // aput-short

    // 52..5f    //22c    //iinstanceop vA, vB, field@CCCC
    {0x52, 4},  // iget
    {0x53, 4},  // iget-wide
    {0x54, 4},  // iget-object
    {0x55, 4},  // iget-boolean
    {0x56, 4},  // iget-byte
    {0x57, 4},  // iget-char
    {0x58, 4},  // iget-short
    {0x59, 4},  // iput
    {0x5a, 4},  // iput-wide
    {0x5b, 4},  // iput-object
    {0x5c, 4},  // iput-boolean
    {0x5d, 4},  // iput-byte
    {0x5e, 4},  // iput-char
    {0x5f, 4},  // iput-short

    // 60..6d    //21c    //sstaticop vAA, field@BBBB
    {0x60, 4},  // sget
    {0x61, 4},  // sget-wide
    {0x62, 4},  // sget-object
    {0x63, 4},  // sget-boolean
    {0x64, 4},  // sget-byte
    {0x65, 4},  // sget-char
    {0x66, 4},  // sget-short
    {0x67, 4},  // sput
    {0x68, 4},  // sput-wide
    {0x69, 4},  // sput-object
    {0x6a, 4},  // sput-boolean
    {0x6b, 4},  // sput-byte
    {0x6c, 4},  // sput-char
    {0x6d, 4},  // sput-short

    // 6e..72    //35c    //invoke-kind {vC, vD, vE, vF, vG}, meth@BBBB
    {0x6e, 6},  // invoke-virtual
    {0x6f, 6},  // invoke-super
    {0x70, 6},  // invoke-direct
    {0x71, 6},  // invoke-static
    {0x72, 6},  // invoke-interface

    {0x73, 2},  // unused    //10x

    // 74..78    //3rc    //invoke-kind/range {vCCCC .. vNNNN}, meth@BBBB
    {0x74, 6},  // invoke-virtual/range
    {0x75, 6},  // invoke-super/range
    {0x76, 6},  // invoke-direct/range
    {0x77, 6},  // invoke-static/range
    {0x78, 6},  // invoke-interface/range

    // 79..7a    //10x    //unused
    {0x79, 2},
    {0x7a, 2},

    // 7b..8f    //12x    //unop vA, vB
    {0x7b, 2},  // neg-int
    {0x7c, 2},  // not-int
    {0x7d, 2},  // neg-long
    {0x7e, 2},  // not-long
    {0x7f, 2},  // neg-float
    {0x80, 2},  // net-double
    {0x81, 2},  // int-to-long
    {0x82, 2},  // int-to-float
    {0x83, 2},  // int-to-double
    {0x84, 2},  // long-to-int
    {0x85, 2},  // long-to-float
    {0x86, 2},  // long-to-double
    {0x87, 2},  // float-to-int
    {0x88, 2},  // float-to-long
    {0x89, 2},  // float-to-double
    {0x8a, 2},  // double-to-int
    {0x8b, 2},  // double-to-long
    {0x8c, 2},  // double-to-float
    {0x8d, 2},  // int-to-byte
    {0x8e, 2},  // int-to-char
    {0x8f, 2},  // int-to-short

    // 90..af    //23x    //binop vAA, vBB, vCC
    {0x90, 4},  // add-int
    {0x91, 4},  // sub-int
    {0x92, 4},  // mul-int
    {0x93, 4},  // div-int
    {0x94, 4},  // rem-int
    {0x95, 4},  // and-int
    {0x96, 4},  // or-int
    {0x97, 4},  // xor-int
    {0x98, 4},  // shl-int
    {0x99, 4},  // shr-int
    {0x9a, 4},  // ushr-int
    {0x9b, 4},  // add-long
    {0x9c, 4},  // sub-long
    {0x9d, 4},  // mul-long
    {0x9e, 4},  // div-long
    {0x9f, 4},  // rem-long
    {0xa0, 4},  // and-long
    {0xa1, 4},  // or-long
    {0xa2, 4},  // xor-long
    {0xa3, 4},  // shl-long
    {0xa4, 4},  // shr-long
    {0xa5, 4},  // ushr-long
    {0xa6, 4},  // add-float
    {0xa7, 4},  // sub-float
    {0xa8, 4},  // mul-float
    {0xa9, 4},  // div-float
    {0xaa, 4},  // rem-float
    {0xab, 4},  // add-double
    {0xac, 4},  // sub-double
    {0xad, 4},  // mul-double
    {0xae, 4},  // div-double
    {0xaf, 4},  // rem-double

    // b0..cf    //12x    //binop/2addr vA, vB
    {0xb0, 2},  // add-int/2addr
    {0xb1, 2},  // sub-int/2addr
    {0xb2, 2},  // mul-int/2addr
    {0xb3, 2},  // div-int/2addr
    {0xb4, 2},  // rem-int/2addr
    {0xb5, 2},  // and-int/2addr
    {0xb6, 2},  // or-int/2addr
    {0xb7, 2},  // xor-int/2addr
    {0xb8, 2},  // shl-int/2addr
    {0xb9, 2},  // shr-int/2addr
    {0xba, 2},  // ushr-int/2addr
    {0xbb, 2},  // add-long/2addr
    {0xbc, 2},  // sub-long/2addr
    {0xbd, 2},  // mul-long/2addr
    {0xbe, 2},  // div-long/2addr
    {0xbf, 2},  // rem-long/2addr
    {0xc0, 2},  // and-long/2addr
    {0xc1, 2},  // or-long/2addr
    {0xc2, 2},  // xor-long/2addr
    {0xc3, 2},  // shl-long/2addr
    {0xc4, 2},  // shr-long/2addr
    {0xc5, 2},  // ushr-long/2addr
    {0xc6, 2},  // add-float/2addr
    {0xc7, 2},  // sub-float/2addr
    {0xc8, 2},  // mul-float/2addr
    {0xc9, 2},  // div-float/2addr
    {0xca, 2},  // rem-float/2addr
    {0xcb, 2},  // add-double/2addr
    {0xcc, 2},  // sub-double/2addr
    {0xcd, 2},  // mul-double/2addr
    {0xce, 2},  // div-double/2addr
    {0xcf, 2},  // rem-double/2addr

    // d0..d7    //22a    //binop/lit16 vA, vB, #+CCCC
    {0xd0, 4},  // add-int/lit16
    {0xd1, 4},  // rsub-int (reverse subtract)
    {0xd2, 4},  // mul-int/lit16
    {0xd3, 4},  // div-int/lit16
    {0xd4, 4},  // rem-int/lit16
    {0xd5, 4},  // and-int/lit16
    {0xd6, 4},  // or-int/lit16
    {0xd7, 4},  // xor-int/lit16

    // d8..e2    //22b    //binop/lit8 vAA, vBB, #+CC
    {0xd8, 4},  // add-int/lit8
    {0xd9, 4},  // rsub-int/lit8
    {0xda, 4},  // mul-int/lit8
    {0xdb, 4},  // div-int/lit8
    {0xdc, 4},  // rem-int/lit8
    {0xdd, 4},  // and-int/lit8
    {0xde, 4},  // or-int/lit8
    {0xdf, 4},  // xor-int/lit8
    {0xe0, 4},  // shl-int/lit8
    {0xe1, 4},  // shr-int/lit8
    {0xe2, 4},  // ushr-int/lit8

    // e3..fe    //10x    //unused
    {0xe3, 2},
    {0xe4, 2},
    {0xe5, 2},
    {0xe6, 2},
    {0xe7, 2},
    {0xe8, 2},
    {0xe9, 2},
    {0xea, 2},
    {0xeb, 2},
    {0xec, 2},
    {0xed, 2},
    {0xee, 2},
    {0xef, 2},
    {0xf0, 2},
    {0xf1, 2},
    {0xf2, 2},
    {0xf3, 2},
    {0xf4, 2},
    {0xf5, 2},
    {0xf6, 2},
    {0xf7, 2},
    {0xf8, 2},
    {0xf9, 2},
    {0xfa, 2},
    {0xfb, 2},
    {0xfc, 2},
    {0xfd, 2},
    {0xfe, 2},
};

const DexInstruction instructionSecondTable[] = {
    // 0xff    //(expanded opcode)
    {0x00ff, 8},   // const-class/jumbo vAAAA, type@BBBBBBBB    //41c
    {0x01ff, 8},   // check-cast/jumbo vAAAA, type@BBBBBBBB    //41c
    {0x02ff, 10},  // instance-of/jumbo vAAAA, vBBBB, type@CCCCCCCC    //52c
    {0x03ff, 8},   // new-instance/jumbo vAAAA, type@BBBBBBBB    //41c
    {0x04ff, 10},  // new-array/jumbo vAAAA, vBBBB, type@CCCCCCCC    //52c
    {0x05ff,
     10},  // filled-new-array/jumbo {vCCCC .. vNNNN}, type@BBBBBBBB    //5rc

    // 06ff..13ff    //52c    //iinstanceop/jumbo vAAAA, vBBBB, field@CCCCCCCC
    {0x06ff, 10},  // iget/jumbo
    {0x07ff, 10},  // iget-wide/jumbo
    {0x08ff, 10},  // iget-object/jumbo
    {0x09ff, 10},  // iget-boolean/jumbo
    {0x0aff, 10},  // iget-byte/jumbo
    {0x0bff, 10},  // iget-char/jumbo
    {0x0cff, 10},  // iget-short/jumbo
    {0x0dff, 10},  // iput/jumbo
    {0x0eff, 10},  // iput-wide/jumbo
    {0x0fff, 10},  // iput-object/jumbo
    {0x10ff, 10},  // iput-boolean/jumbo
    {0x11ff, 10},  // iput-byte/jumbo
    {0x12ff, 10},  // iput-char/jumbo
    {0x13ff, 10},  // iput-short/jumbo

    // 14ff..21ff    //41c    //sstaticop/jumbo vAAAA, field@BBBBBBBB
    {0x14ff, 8},  // sget/jumbo
    {0x15ff, 8},  // sget-wide/jumbo
    {0x16ff, 8},  // sget-object/jumbo
    {0x17ff, 8},  // sget-boolean/jumbo
    {0x18ff, 8},  // sget-byte/jumbo
    {0x19ff, 8},  // sget-char/jumbo
    {0x1aff, 8},  // sget-short/jumbo
    {0x1bff, 8},  // sput/jumbo
    {0x1cff, 8},  // sput-wide/jumbo
    {0x1dff, 8},  // sput-object/jumbo
    {0x1eff, 8},  // sput-boolean/jumbo
    {0x1fff, 8},  // sput-byte/jumbo
    {0x20ff, 8},  // sput-char/jumbo
    {0x21ff, 8},  // sput-short/jumbo

    // 22ff..26ff    //5rc    //invoke-kind/jumbo {vCCCC .. vNNNN},
    // meth@BBBBBBBB
    {0x22ff, 10},  // invoke-virtual/jumbo
    {0x23ff, 10},  // invoke-super/jumbo
    {0x24ff, 10},  // invoke-direct/jumbo
    {0x25ff, 10},  // invoke-static/jumbo
    {0x26ff, 10},  // invoke-interface/jumbo
};
#endif

DexCode::DexCode() {
  dexFile_ = NULL;
  funcStart_ = NULL;
  funcEnd_ = NULL;
  codeEnd_ = NULL;
  assert(0xfe == instructionFirstTable[0xfe].opcode);
  assert(0x26ff == instructionSecondTable[0x26ff >> 8].opcode);
}

DexCode::~DexCode() { uninit(); }

int DexCode::init(DexFile* dexFile, void* funcStart, void* funcEnd) {
  if (NULL == dexFile || NULL == funcStart || NULL == funcEnd) return -1;
  if (funcStart > funcEnd) return -1;

  dexFile_ = dexFile;
  funcStart_ = funcStart;
  funcEnd_ = funcEnd;
  codeEnd_ = funcEnd_;
  return 0;
}

int DexCode::uninit() {
  dexFile_ = NULL;
  funcStart_ = NULL;
  funcEnd_ = NULL;
  codeEnd_ = NULL;

  opcodeBuf_.clear();
  operandStrBuf_.clear();
  return 0;
}

int DexCode::parseCode() {
  int realCount = 0;
  uint8_t* cur = (uint8_t*)funcStart_;
  try {
    opcodeBuf_.reserve(((char*)codeEnd_ - (char*)funcStart_) / 2);
    while (cur < codeEnd_) {
      uint8_t opcode = *cur;
#ifdef DEBUG_BUILD
      // cout << "opcode: " << hex << (int)opcode << dec << endl;
#endif
      if (opcode != 0xff) {
        assert(instructionFirstTable[opcode].opcode == opcode);
        opcodeBuf_.push_back(opcode);

        if (0x1a == opcode || 0x1b == opcode) {
          int index = 0;
          if (0x1a == opcode)  // const-string vAA, string@BBBB
            index = *(uint16_t*)(cur + sizeof(uint16_t));
          else if (0x1b == opcode)  // const-string/jumbo vAA, string@BBBBBBBB
            index = *(uint32_t*)(cur + sizeof(uint16_t));

          string constStr;
          int result = dexFile_->getStringString(index, constStr);
          if (0 != result) return result;
#ifdef DEBUG_BUILD
          cout << "constStr: " << constStr << endl;
#endif
          pushOperandStr(constStr);
        }

        if (0x2b == opcode || 0x2c == opcode || 0x26 == opcode) {
          int32_t payloadOffset = *(int32_t*)(cur + sizeof(uint16_t));
          uint8_t* payloadStart = cur + sizeof(uint16_t) * payloadOffset;
          // assert(payloadStart < funcEnd_);
          if (payloadStart < funcEnd_) {
            if (payloadStart < codeEnd_) codeEnd_ = payloadStart;
          } else
            return -2;

          if (0x2b == opcode) {  // packed-switch-payload
            ;
          } else if (0x2c == opcode) {  // sparse-switch-payload
            ;
          } else if (0x26 == opcode) {  // fill-array-data-payload
            ;
          }
        }

        cur += instructionFirstTable[opcode].size;
        realCount++;
      } else {
        uint16_t opcode2 = *(uint16_t*)cur;
#ifdef DEBUG_BUILD
        // cout << "opcode2: " << hex << (int)opcode << dec << endl;
#endif
        if (opcode2 > 0x26ff) return -2;
        assert(instructionSecondTable[opcode2 >> 8].opcode == opcode2);
        opcodeBuf_.push_back(0xff);
        opcodeBuf_.push_back(opcode);
        cur += instructionSecondTable[opcode2 >> 8].size;
        realCount++;
      }
    }
  } catch (bad_alloc& e) {
    cerr << "DexCode::init bad_alloc caught: " << e.what() << endl;
    return -1;
  }
  return 0;
}

#ifdef ANALYSISASSISTDEXINFO

// #define STAT_OPCODE_MAP
#ifdef STAT_OPCODE_MAP

#include <math.h>
#include <string.h>

#pragma pack(push, 1)

struct FastOpcodes6 {
  uint16_t opcode01;
  uint16_t opcode23;
  uint16_t opcode45;

  bool operator<(const FastOpcodes6& opcodes) const {
    if (opcode01 > opcodes.opcode01)
      return false;
    else if (opcode23 > opcodes.opcode23)
      return false;
    else if (opcode45 > opcodes.opcode45)
      return false;
    if (opcode01 == opcodes.opcode01 && opcode23 == opcodes.opcode23 &&
        opcode45 == opcodes.opcode45)
      return false;
    return true;
  }

  bool operator==(const FastOpcodes6& opcodes) const {
    return (opcode01 == opcodes.opcode01 && opcode23 == opcodes.opcode23 &&
            opcode45 == opcodes.opcode45);
  }
};

struct Fast6 {
  FastOpcodes6 opcodes;
  int count;

  bool operator<(const Fast6& fast) const {
    // return opcodes < fast.opcodes;
    return count < fast.count;
  }

  bool operator==(const Fast6& fast) const { return opcodes == fast.opcodes; }
};

struct FastOpcodes8 {
  uint16_t opcode01;
  uint16_t opcode23;
  uint16_t opcode45;
  uint16_t opcode67;

  bool operator<(const FastOpcodes8& opcodes) const {
    if (opcode01 > opcodes.opcode01)
      return false;
    else if (opcode23 > opcodes.opcode23)
      return false;
    else if (opcode45 > opcodes.opcode45)
      return false;
    else if (opcode67 > opcodes.opcode67)
      return false;
    if (opcode01 == opcodes.opcode01 && opcode23 == opcodes.opcode23 &&
        opcode45 == opcodes.opcode45 && opcode67 == opcodes.opcode67)
      return false;
    return true;
  }

  bool operator==(const FastOpcodes8& opcodes) const {
    return (opcode01 == opcodes.opcode01 && opcode23 == opcodes.opcode23 &&
            opcode45 == opcodes.opcode45 && opcode67 == opcodes.opcode67);
  }
};

struct Fast8 {
  FastOpcodes8 opcodes;
  int count;

  bool operator<(const Fast8& fast) const {
    // return opcodes < fast.opcodes;
    return count < fast.count;
  }

  bool operator==(const Fast8& fast) const { return opcodes == fast.opcodes; }
};

struct FastOpcodes10 {
  uint16_t opcode01;
  uint16_t opcode23;
  uint16_t opcode45;
  uint16_t opcode67;
  uint16_t opcode89;

  bool operator<(const FastOpcodes10& opcodes) const {
    if (opcode01 > opcodes.opcode01)
      return false;
    else if (opcode23 > opcodes.opcode23)
      return false;
    else if (opcode45 > opcodes.opcode45)
      return false;
    else if (opcode67 > opcodes.opcode67)
      return false;
    else if (opcode89 > opcodes.opcode89)
      return false;
    if (opcode01 == opcodes.opcode01 && opcode23 == opcodes.opcode23 &&
        opcode45 == opcodes.opcode45 && opcode67 == opcodes.opcode67 &&
        opcode89 == opcodes.opcode89)
      return false;
    return true;
  }

  bool operator==(const FastOpcodes10& opcodes) const {
    return (opcode01 == opcodes.opcode01 && opcode23 == opcodes.opcode23 &&
            opcode45 == opcodes.opcode45 && opcode67 == opcodes.opcode67 &&
            opcode89 == opcodes.opcode89);
  }
};

struct Fast10 {
  FastOpcodes10 opcodes;
  int count;

  bool operator<(const Fast10& fast) const {
    // return opcodes < fast.opcodes;
    return count < fast.count;
  }

  bool operator==(const Fast10& fast) const { return opcodes == fast.opcodes; }
};

#pragma pack(pop)

list<Fast6> fast6_;
list<Fast8> fast8_;
list<Fast10> fast10_;
int fastCount_ = 0;

void StatOpcodeMap(const FastOpcodes& fastOpcodes) {
  FastOpcodes6 opcodes6;
  memcpy(&opcodes6, &fastOpcodes, sizeof(FastOpcodes6));
  FastOpcodes8 opcodes8;
  memcpy(&opcodes8, &fastOpcodes, sizeof(FastOpcodes8));
  FastOpcodes10 opcodes10;
  memcpy(&opcodes10, &fastOpcodes, sizeof(FastOpcodes10));

  try {
    bool found = false;
    for (list<Fast6>::iterator i = fast6_.begin(); i != fast6_.end(); ++i) {
      if (opcodes6 == i->opcodes) {
        i->count++;
        found = true;
        break;
      }
    }
    if (!found) {
      Fast6 fast6;
      fast6.opcodes = opcodes6;
      fast6.count = 1;
      fast6_.push_back(fast6);
    }

    found = false;
    for (list<Fast8>::iterator i = fast8_.begin(); i != fast8_.end(); ++i) {
      if (opcodes8 == i->opcodes) {
        i->count++;
        found = true;
        break;
      }
    }
    if (!found) {
      Fast8 fast8;
      fast8.opcodes = opcodes8;
      fast8.count = 1;
      fast8_.push_back(fast8);
    }

    found = false;
    for (list<Fast10>::iterator i = fast10_.begin(); i != fast10_.end(); ++i) {
      if (opcodes10 == i->opcodes) {
        i->count++;
        found = true;
        break;
      }
    }
    if (!found) {
      Fast10 fast10;
      fast10.opcodes = opcodes10;
      fast10.count = 1;
      fast10_.push_back(fast10);
    }
  } catch (bad_alloc& e) {
    cerr << "StatOpcodeMap bad_alloc caught: " << e.what() << endl;
    return;
  }

  if (0 == ++fastCount_ % 100000) {
    cout << "STAT_OPCODE_MAP *** fastCount_: " << fastCount_ << endl;
    float s2 = 0;
    float s = 0;
    int n = 0;
    int sum = 0;

    // fast6_.sort();
    cout << "STAT_OPCODE_MAP fast6_ size: " << fast6_.size() << endl;
    n = fast6_.size();
    for (list<Fast6>::iterator i = fast6_.begin(); i != fast6_.end(); ++i) {
      if (1 == i->count) continue;
      sum += pow(i->count - 1, 2);
      // cout << "STAT_OPCODE_MAP opcode6 count: " << i->count;
      // cout << hex;
      // cout << " opcodes: ";
      // cout << "0x" << i->opcodes.opcode01 << " ";
      // cout << "0x" << i->opcodes.opcode23 << " ";
      // cout << "0x" << i->opcodes.opcode45 << endl;
      // cout << dec;
    }
    cout << dec;
    s2 = sum / n;
    s = sqrt(s2);
    cout << "STAT_OPCODE_MAP fast6_ s2: " << s2 << " s: " << s << endl;

    s2 = 0;
    s = 0;
    n = 0;
    sum = 0;

    // fast8_.sort();
    cout << "STAT_OPCODE_MAP fast8_ size: " << fast8_.size() << endl;
    n = fast8_.size();
    for (list<Fast8>::iterator i = fast8_.begin(); i != fast8_.end(); ++i) {
      if (1 == i->count) continue;
      sum += pow(i->count - 1, 2);
      // cout << "STAT_OPCODE_MAP opcode8 count: " << i->count;
      // cout << hex;
      // cout << " opcodes: ";
      // cout << "0x" << i->opcodes.opcode01 << " ";
      // cout << "0x" << i->opcodes.opcode23 << " ";
      // cout << "0x" << i->opcodes.opcode45 << " ";
      // cout << "0x" << i->opcodes.opcode67 << endl;
      // cout << dec;
    }
    cout << dec;
    s2 = sum / n;
    s = sqrt(s2);
    cout << "STAT_OPCODE_MAP fast8_ s2: " << s2 << " s: " << s << endl;

    s2 = 0;
    s = 0;
    n = 0;
    sum = 0;

    // fast10_.sort();
    cout << "STAT_OPCODE_MAP fast10_ size: " << fast10_.size() << endl;
    n = fast10_.size();
    for (list<Fast10>::iterator i = fast10_.begin(); i != fast10_.end(); ++i) {
      if (1 == i->count) continue;
      sum += pow(i->count - 1, 2);
      // cout << "STAT_OPCODE_MAP opcode10 count: " << i->count;
      // cout << hex;
      // cout << " opcodes: ";
      // cout << "0x" << i->opcodes.opcode01 << " ";
      // cout << "0x" << i->opcodes.opcode23 << " ";
      // cout << "0x" << i->opcodes.opcode45 << " ";
      // cout << "0x" << i->opcodes.opcode67 << " ";
      // cout << "0x" << i->opcodes.opcode89 << endl;
      // cout << dec;
    }
    cout << dec;
    s2 = sum / n;
    s = sqrt(s2);
    cout << "STAT_OPCODE_MAP fast10_ s2: " << s2 << " s: " << s << endl;
  }
}
#endif

int DexCode::getFastOpcodes(FastOpcodes& fastOpcodes) {
  int realCount = 0;
  uint8_t opcodes[MAX_FAST_OPCODES_COUNT] = {0};
  uint8_t* cur = (uint8_t*)funcStart_;
  while (cur < codeEnd_) {
    uint8_t opcode = *cur;
    if (opcode != 0xff) {
      assert(instructionFirstTable[opcode].opcode == opcode);
      if (0x2b == opcode || 0x2c == opcode || 0x26 == opcode) {
        int32_t payloadOffset = *(int32_t*)(cur + sizeof(uint16_t));
        uint8_t* payloadStart = cur + sizeof(uint16_t) * payloadOffset;
        // assert(payloadStart < funcEnd_);
        if (payloadStart < funcEnd_) {
          if (payloadStart < codeEnd_) codeEnd_ = payloadStart;
        } else
          return -2;
      }

      cur += instructionFirstTable[opcode].size;
      opcodes[realCount] = opcode;
      realCount++;
    } else {
      uint16_t opcode2 = *(uint16_t*)cur;
      if (opcode2 > 0x26ff) return -2;
      assert(instructionSecondTable[opcode2 >> 8].opcode == opcode2);
      cur += instructionSecondTable[opcode2 >> 8].size;
      opcodes[realCount] = opcode;
      realCount++;
    }

    if (MAX_FAST_OPCODES_COUNT == realCount) break;
  }

  if (realCount < MAX_FAST_OPCODES_COUNT) return -1;
  assert(MAX_FAST_OPCODES_COUNT == realCount);
  fastOpcodes.opcode01 = *(uint16_t*)(&opcodes[0]);
  fastOpcodes.opcode23 = *(uint16_t*)(&opcodes[2]);
  fastOpcodes.opcode45 = *(uint16_t*)(&opcodes[4]);
  fastOpcodes.opcode67 = *(uint16_t*)(&opcodes[6]);
  fastOpcodes.opcode89 = *(uint16_t*)(&opcodes[8]);

#ifdef STAT_OPCODE_MAP
  StatOpcodeMap(fastOpcodes);
#endif
  return 0;
}

#else

int DexCode::getFastOpcodes(FastOpcodes& fastOpcodes) {
  int realCount = 0;
  uint8_t opcodes[FAST_OPCODES_COUNT] = {0};
  uint8_t* cur = (uint8_t*)funcStart_;
  while (cur < codeEnd_) {
    uint8_t opcode = *cur;
    if (opcode != 0xff) {
      assert(instructionFirstTable[opcode].opcode == opcode);
      if (0x2b == opcode || 0x2c == opcode || 0x26 == opcode) {
        int32_t payloadOffset = *(int32_t*)(cur + sizeof(uint16_t));
        uint8_t* payloadStart = cur + sizeof(uint16_t) * payloadOffset;
        // assert(payloadStart < funcEnd_);
        if (payloadStart < funcEnd_) {
          if (payloadStart < codeEnd_) codeEnd_ = payloadStart;
        } else
          return -2;
      }

      cur += instructionFirstTable[opcode].size;
      opcodes[realCount] = opcode;
      realCount++;
    } else {
      uint16_t opcode2 = *(uint16_t*)cur;
      if (opcode2 > 0x26ff) return -2;
      assert(instructionSecondTable[opcode2 >> 8].opcode == opcode2);
      cur += instructionSecondTable[opcode2 >> 8].size;
      opcodes[realCount] = opcode;
      realCount++;
    }

    if (FAST_OPCODES_COUNT == realCount) break;
  }

  if (realCount < FAST_OPCODES_COUNT) return -1;
  assert(FAST_OPCODES_COUNT == realCount);
  fastOpcodes.opcode01 = *(uint16_t*)(&opcodes[0]);
  fastOpcodes.opcode23 = *(uint16_t*)(&opcodes[2]);
  fastOpcodes.opcode45 = *(uint16_t*)(&opcodes[4]);
  fastOpcodes.opcode67 = *(uint16_t*)(&opcodes[6]);
  return 0;
}
#endif

int DexCode::getOpcodeCRC32(uint32_t& crc) {
  IObject* crc32 = NULL;
  int ret = -1;
  do {
    if (0 != libutil_createInstance(UTIL_ID_MEMCRC32, &crc32)) break;
    if (0 != ((IMemCRC32*)crc32)->init(opcodeBuf_.data(), opcodeBuf_.size()))
      break;
    if (0 != ((IMemCRC32*)crc32)->getCRC32(&crc)) break;
    ret = 0;
  } while (false);

  if (NULL != crc32) crc32->release();
  return ret;
}

int DexCode::getOperandStrCRC32(uint32_t& crc) {
  IObject* crc32 = NULL;
  int ret = -1;
  do {
    if (0 != libutil_createInstance(UTIL_ID_MEMCRC32, &crc32)) break;
    if (0 !=
        ((IMemCRC32*)crc32)->init(operandStrBuf_.data(), operandStrBuf_.size()))
      break;
    if (0 != ((IMemCRC32*)crc32)->getCRC32(&crc)) break;
    ret = 0;
  } while (false);

  if (NULL != crc32) crc32->release();
  return ret;
}

int DexCode::pushOperandStr(string& constStr) {
  transform(constStr.begin(), constStr.end(), constStr.begin(), ::tolower);
  int l = 0;
  int r = constStr.size() - 1;
  while (l <= r) {
    char lchar = constStr[l];
    bool lcharValid = true;
    char rchar = constStr[r];
    bool rcharValid = true;
    if (' ' == lchar || '\t' == lchar || '\x0d' == lchar || '\x0a' == lchar) {
      lcharValid = false;
      l++;
    }
    if (' ' == rchar || '\t' == rchar || '\x0d' == rchar || '\x0a' == rchar) {
      rcharValid = false;
      r++;
    }
    if (lcharValid && rcharValid) break;
  }
  if (l > r) return 0;

  try {
    constStr = constStr.substr(l, r - l + 1);
    for (int i = 0; i < constStr.size(); i++) {
      operandStrBuf_.push_back(constStr[i]);
    }
    operandStrBuf_.push_back(0);
#ifdef DEBUG_BUILD
    cout << "regular constStr: " << constStr << endl;
#endif
  } catch (bad_alloc& e) {
    cerr << "DexCode::pushOperandStr bad_alloc caught: " << e.what() << endl;
    return -1;
  }
  return 0;
}

#ifdef ANALYSISASSISTDEXINFO
int DexCode::parseCode(list<OpcodeInfo>& opcodeBuf, list<string>& stringBuf) {
  int realCount = 0;
  uint8_t* cur = (uint8_t*)funcStart_;
  try {
    opcodeBuf_.reserve(((char*)codeEnd_ - (char*)funcStart_) / 2);
    while (cur < codeEnd_) {
      uint8_t opcode = *cur;
#ifdef DEBUG_BUILD
      // cout << "opcode: " << hex << (int)opcode << dec << endl;
#endif
      if (opcode != 0xff) {
        assert(instructionFirstTable[opcode].opcode == opcode);
        opcodeBuf_.push_back(opcode);

        if (0x1a == opcode || 0x1b == opcode) {
          int index = 0;
          if (0x1a == opcode)  // const-string vAA, string@BBBB
            index = *(uint16_t*)(cur + sizeof(uint16_t));
          else if (0x1b == opcode)  // const-string/jumbo vAA, string@BBBBBBBB
            index = *(uint32_t*)(cur + sizeof(uint16_t));

          string constStr;
          int result = dexFile_->getStringString(index, constStr);
          if (0 != result) return result;
#ifdef DEBUG_BUILD
          cout << "constStr: " << constStr << endl;
#endif
          pushOperandStr(stringBuf, constStr);
        }

        if (0x2b == opcode || 0x2c == opcode || 0x26 == opcode) {
          int32_t payloadOffset = *(int32_t*)(cur + sizeof(uint16_t));
          uint8_t* payloadStart = cur + sizeof(uint16_t) * payloadOffset;
          // assert(payloadStart < funcEnd_);
          if (payloadStart < funcEnd_) {
            if (payloadStart < codeEnd_) codeEnd_ = payloadStart;
          } else
            return -2;

          if (0x2b == opcode) {  // packed-switch-payload
            ;
          } else if (0x2c == opcode) {  // sparse-switch-payload
            ;
          } else if (0x26 == opcode) {  // fill-array-data-payload
            ;
          }
        }

        cur += instructionFirstTable[opcode].size;
        realCount++;

        OpcodeInfo opcodeInfo;
        opcodeInfo.opcode = opcode;
        opcodeInfo.instruction = instructionFirstTable[opcode].instructionStr;
        opcodeBuf.push_back(opcodeInfo);
      } else {
        uint16_t opcode2 = *(uint16_t*)cur;
#ifdef DEBUG_BUILD
        // cout << "opcode2: " << hex << (int)opcode << dec << endl;
#endif
        if (opcode2 > 0x26ff) return -2;
        assert(instructionSecondTable[opcode2 >> 8].opcode == opcode2);
        opcodeBuf_.push_back(0xff);
        opcodeBuf_.push_back(opcode);
        cur += instructionSecondTable[opcode2 >> 8].size;
        realCount++;

        OpcodeInfo opcodeInfo;
        opcodeInfo.opcode = opcode2;
        opcodeInfo.instruction =
            instructionSecondTable[opcode2 >> 8].instructionStr;
        opcodeBuf.push_back(opcodeInfo);
      }
    }
  } catch (bad_alloc& e) {
    cerr << "DexCode::init bad_alloc caught: " << e.what() << endl;
    return -1;
  }
  return 0;
}

int DexCode::pushOperandStr(list<string>& stringBuf, string& constStr) {
  transform(constStr.begin(), constStr.end(), constStr.begin(), ::tolower);
  int l = 0;
  int r = constStr.size() - 1;
  while (l <= r) {
    char lchar = constStr[l];
    bool lcharValid = true;
    char rchar = constStr[r];
    bool rcharValid = true;
    if (' ' == lchar || '\t' == lchar || '\x0d' == lchar || '\x0a' == lchar) {
      lcharValid = false;
      l++;
    }
    if (' ' == rchar || '\t' == rchar || '\x0d' == rchar || '\x0a' == rchar) {
      rcharValid = false;
      r++;
    }
    if (lcharValid && rcharValid) break;
  }
  if (l > r) return 0;

  try {
    constStr = constStr.substr(l, r - l + 1);
    for (int i = 0; i < constStr.size(); i++) {
      operandStrBuf_.push_back(constStr[i]);
    }
    operandStrBuf_.push_back(0);
    stringBuf.push_back(constStr);
#ifdef DEBUG_BUILD
    cout << "regular constStr: " << constStr << endl;
#endif
  } catch (bad_alloc& e) {
    cerr << "DexCode::pushOperandStr bad_alloc caught: " << e.what() << endl;
    return -1;
  }
  return 0;
}
#endif
