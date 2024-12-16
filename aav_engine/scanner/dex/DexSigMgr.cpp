#include "DexSigMgr.h"

#include "DexCodeSigMgr.h"
#include "DexPathSigMgr.h"

#if defined(ANDROID_BUILD) && defined(DEBUG_BUILD)
#include <android/log.h>
#include <jni.h>

#endif

#include <iostream>
#include <new>

using namespace std;

DexSigMgr::DexSigMgr() {
  pathSigMgr_ = NULL;
  codeSigMgr_ = NULL;
}

DexSigMgr::~DexSigMgr() { uninit(); }

int DexSigMgr::init(ISigMgr* sigMgr) {
  if (NULL == sigMgr) return -1;

  int ret = -1;
  do {
    pathSigMgr_ = new (nothrow) DexPathSigMgr;
    if (NULL == pathSigMgr_) break;
    if (0 != pathSigMgr_->init(sigMgr)) {
#if defined(ANDROID_BUILD) && defined(DEBUG_BUILD)
      __android_log_print(ANDROID_LOG_ERROR, "aaveng",
                          "failed to init pathSigMgr_");
#endif
      break;
    }

    codeSigMgr_ = new (nothrow) DexCodeSigMgr;
    if (NULL == codeSigMgr_) break;
    if (0 != codeSigMgr_->init(sigMgr)) {
#if defined(ANDROID_BUILD) && defined(DEBUG_BUILD)
      __android_log_print(ANDROID_LOG_ERROR, "aaveng",
                          "failed to init codeSigMgr_");
#endif
      break;
    }

    ret = 0;
  } while (false);

  if (0 != ret) uninit();
  return ret;
}

int DexSigMgr::uninit() {
  delete pathSigMgr_;
  pathSigMgr_ = NULL;

  delete codeSigMgr_;
  codeSigMgr_ = NULL;
  return 0;
}

int DexSigMgr::searchClassPath(const char* classPath, DexPathSig** pathSig) {
  int ret = pathSigMgr_->searchClassPath(classPath, pathSig);
#if defined(DEBUG_BUILD) && defined(DEX_DEBUG)
  uint32_t hitSigID = 293;
  if (ret == 0 && (*pathSig)->sigID == hitSigID) {
    cout << "^^^ " << hitSigID << " hit! " << classPath << endl;
  }
#endif
  return ret;
}

int DexSigMgr::searchOpcodeMap(const FastOpcodes* opcodes) {
  int ret = codeSigMgr_->searchOpcodeMap(opcodes);
#if defined(DEBUG_BUILD) && defined(DEX_DEBUG)
  if (opcodes->opcode01 == 0x1a12 && opcodes->opcode23 == 0x7022 &&
      opcodes->opcode45 == 0x6e1a && opcodes->opcode67 == 0x620c) {
    cout << "^^^ opcodemap hit " << hex << "0x" << opcodes->opcode01 << ":0x"
         << opcodes->opcode23 << ":0x" << opcodes->opcode45 << ":0x"
         << opcodes->opcode67 << dec << endl;
  }
  if (opcodes->opcode01 == 0x0c71 && opcodes->opcode23 == 0x0c6e &&
      opcodes->opcode45 == 0x6e38 && opcodes->opcode67 == 0x3d0a) {
    cout << "^^^ opcodemap hit " << hex << "0x" << opcodes->opcode01 << ":0x"
         << opcodes->opcode23 << ":0x" << opcodes->opcode45 << ":0x"
         << opcodes->opcode67 << dec << endl;
  }
#endif
  return ret;
}

int DexSigMgr::searchOpcodeCrc(uint32_t crc, DexCodeCrcSig** opcodeSig) {
  int ret = codeSigMgr_->searchOpcodeCrc(crc, opcodeSig);
#if defined(DEBUG_BUILD) && defined(DEX_DEBUG)
  if (crc == 0xb07f2cf7) {
    cout << "^^^ opcode crc hit 0x" << hex << crc << dec << endl;
    if (ret == 0) {
      cout << "    sigID: [";
      for (vector<uint32_t>::iterator i = (*opcodeSig)->sigIDs.begin();
           i != (*opcodeSig)->sigIDs.end(); ++i)
        cout << *i << " ";
      cout << "]" << endl;
    }
  }
  if (crc == 0x7b35eb0c) {
    cout << "^^^ opcode crc hit 0x" << hex << crc << dec << endl;
    if (ret == 0) {
      cout << "    sigID: [";
      for (vector<uint32_t>::iterator i = (*opcodeSig)->sigIDs.begin();
           i != (*opcodeSig)->sigIDs.end(); ++i)
        cout << *i << " ";
      cout << "]" << endl;
    }
  }
#endif
  return ret;
}

int DexSigMgr::searchOperandCrc(uint32_t crc, DexCodeCrcSig** operandSig) {
  int ret = codeSigMgr_->searchOperandCrc(crc, operandSig);
#if defined(DEBUG_BUILD) && defined(DEX_DEBUG)
  if (crc == 0xa259a580) {
    cout << "^^^ operand crc hit 0x" << hex << crc << dec << endl;
    if (ret == 0) cout << "    sigID: [";
    for (vector<uint32_t>::iterator i = (*operandSig)->sigIDs.begin();
         i != (*operandSig)->sigIDs.end(); ++i)
      cout << *i << " ";
    cout << "]" << endl;
  }
  if (crc == 0x9a68e30e) {
    cout << "^^^ operand crc hit 0x" << hex << crc << dec << endl;
    if (ret == 0) cout << "    sigID: [";
    for (vector<uint32_t>::iterator i = (*operandSig)->sigIDs.begin();
         i != (*operandSig)->sigIDs.end(); ++i)
      cout << *i << " ";
    cout << "]" << endl;
  }
#endif
  return ret;
}

int DexSigMgr::searchCodeLogic(uint32_t sigID, DexCodeLogicSig** logicSig) {
  return codeSigMgr_->searchCodeLogic(sigID, logicSig);
}
