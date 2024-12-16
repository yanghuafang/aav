#include "DexParser.h"

#include "DexCode.h"
#include "DexCodeScanResultMgr.h"
#include "DexCodeSigMgr.h"
#include "DexFile.h"
#include "DexPathScanResultMgr.h"
#include "DexPathSigMgr.h"
#include "DexSigMgr.h"
#ifdef ANALYSISASSISTDEXINFO
#include "AnalysisAssistDexInfo.h"
#endif

#include <stdio.h>

#include "ITarget.h"
#ifdef ANALYSISASSISTDEXINFO
#include <string.h>
#endif

#include <algorithm>
#include <iostream>
#include <new>
using namespace std;

DexParser::DexParser() {
  dexSigMgr_ = NULL;
  dexFile_ = NULL;
}

DexParser::~DexParser() { uninit(); }

int DexParser::init(DexSigMgr* sigMgr, ITarget* target) {
  if (NULL == sigMgr || NULL == target) return -1;

  dexSigMgr_ = sigMgr;
  int ret = -1;
  do {
    dexFile_ = new (nothrow) DexFile;
    if (NULL == dexFile_) break;
    if (0 != dexFile_->init(target)) break;
    ret = 0;
  } while (false);

  if (0 != ret) uninit();
  return ret;
}

int DexParser::uninit() {
  delete dexFile_;
  dexFile_ = NULL;
  dexSigMgr_ = NULL;
  return 0;
}

#ifdef ANALYSISASSISTDEXINFO
void PrintDexInfo(AnalysisAssistDexInfo* dexInfo) {
  if (NULL == dexInfo) {
    cout << "dexInfo is NULL." << endl;
    return;
  }

  for (list<AnalysisAssistClassInfo>::iterator i =
           dexInfo->classInfoList.begin();
       i != dexInfo->classInfoList.end(); ++i) {
    cout << "classPath: " << i->classPath << endl;
    cout << "known: " << i->known << endl;
    for (list<AnalysisAssistMethodInfo>::iterator j = i->methodInfoList.begin();
         j != i->methodInfoList.end(); ++j) {
      cout << "    methodName: " << j->methodName << endl;
      cout << "    protoName: " << j->protoName << endl;
      cout << "    known: " << j->known << endl;
      cout << "    fastOpcodes: [0x" << hex << (int)j->fastOpcodes.opcode01
           << " 0x" << (int)j->fastOpcodes.opcode23 << " 0x"
           << (int)j->fastOpcodes.opcode45 << " 0x"
           << (int)j->fastOpcodes.opcode67 << " 0x"
           << (int)j->fastOpcodes.opcode89 << "]" << dec << endl;
      cout << "    opcodeCRC32: " << hex << j->opcodeCRC32 << dec << endl;
      cout << "    stringCRC32: " << hex << j->stringCRC32 << dec << endl;
    }
  }
}

int DexParser::scan(OUT vector<uint32_t>& sigIDArray) {
  string className;
  DexPathScanResultMgr pathResultMgr;
  DexCodeScanResultMgr codeResultMgr;

  delete analysisAssistDexInfo;
  analysisAssistDexInfo = new (nothrow) AnalysisAssistDexInfo;
  if (NULL == analysisAssistDexInfo) return -1;

  int ret = 0;
  try {
    int result = 0;
    while (-1 != (result = dexFile_->getClass(className))) {
#ifdef DEBUG_BUILD
      cout << "className: " << className << endl;
#endif
      if (-2 == result) continue;

      string className2 = className;
      if (0 == className2.size()) continue;
      if ('L' == className2[0]) className2.erase(0, 1);
      if (0 == className2.size()) continue;
      if (';' == className2[className2.size() - 1])
        className2.erase(className2.size() - 1, 1);
      if (0 == className2.size()) continue;
      for (int i = 0; i < className2.size(); i++) {
        if ('/' == className2[i]) className2[i] = '.';
      }
#ifdef DEBUG_BUILD
      cout << "className2: " << className2 << endl;
#ifdef DEX_DEBUG
      const char* targetClass = "com.renren.sdk.AderSDKView";
      if (className2.substr(0, strlen(targetClass)) == targetClass) {
        cout << "check " << className2 << endl;
      }
#endif
#endif
      if (0 != regularizeClassName(className)) continue;
#ifdef DEBUG_BUILD
      cout << "regular className: " << className << endl;
#endif

      AnalysisAssistClassInfo classInfo;
      classInfo.classPath = className2;

      DexPathSig* pathSig;
      if (0 == dexSigMgr_->searchClassPath(className.c_str(), &pathSig)) {
        classInfo.known = true;
        if (0 != pathResultMgr.addSigHit(pathSig)) {
          ret = -1;
          break;
        }
        // continue;
      }

      string methodName;
      string protoName;
      DexCode dexCode;
      bool success = true;
      uint32_t key = 0;
      while (-1 != (result = dexFile_->getDirectMethod(methodName, protoName,
                                                       dexCode, key))) {
#ifdef DEBUG_BUILD
        cout << "direct methodName: " << className2 << "::" << methodName
             << " protoName: " << protoName << endl;
#ifdef DEX_DEBUG
        const char* targetMethod = "startService";
        if (methodName.substr(0, strlen(targetMethod)) == targetMethod) {
          cout << "check " << methodName << endl;
        }
#endif
#endif
        if (-2 == result) continue;
        // if ("<clinit>" == methodName)
        //     continue;

        AnalysisAssistMethodInfo methodInfo;
        methodInfo.methodName = methodName;
        methodInfo.protoName = protoName;
        if (0 != dexCode.getFastOpcodes(methodInfo.fastOpcodes)) continue;
#ifdef DEBUG_BUILD
        cout << "    fastOpcodes: [0x" << hex
             << (int)methodInfo.fastOpcodes.opcode01 << " 0x"
             << (int)methodInfo.fastOpcodes.opcode23 << " 0x"
             << (int)methodInfo.fastOpcodes.opcode45 << " 0x"
             << (int)methodInfo.fastOpcodes.opcode67 << " 0x"
             << (int)methodInfo.fastOpcodes.opcode89 << "]" << dec << endl;
#endif
        if (0 !=
            dexCode.parseCode(methodInfo.opcodeBuf, methodInfo.stringBuf)) {
          // success = false;
          // break;
          continue;
        }
        DexCodeCRC codeCRC;
        getCodeCRC(dexCode, codeCRC);

        if (codeCRC.hasOpcode) {
          char crcBuf[9] = {0};
          snprintf(crcBuf, sizeof(crcBuf), "%8x", codeCRC.opcodeCRC);
          methodInfo.opcodeCRC32 = crcBuf;

          DexCodeCrcSig* opcodeSig = NULL;
          if (0 == dexSigMgr_->searchOpcodeCrc(codeCRC.opcodeCRC, &opcodeSig)) {
            methodInfo.known = true;
            if (0 != codeResultMgr.addSigHit(opcodeSig)) {
              success = false;
              break;
            }
          }
        }

        if (codeCRC.hasOperandStr) {
          char crcBuf[9] = {0};
          snprintf(crcBuf, sizeof(crcBuf), "%8x", codeCRC.operandStrCRC);
          methodInfo.stringCRC32 = crcBuf;

          DexCodeCrcSig* operandSig = NULL;
          if (0 == dexSigMgr_->searchOperandCrc(codeCRC.operandStrCRC,
                                                &operandSig)) {
            methodInfo.known = true;
            if (0 != codeResultMgr.addSigHit(operandSig)) {
              success = false;
              break;
            }
          }
        }

        classInfo.methodInfoList.push_back(methodInfo);
      }
      if (!success) {
        ret = -1;
        break;
      }

      key = 0;
      while (-1 != (result = dexFile_->getVirtualMethod(methodName, protoName,
                                                        dexCode, key))) {
#ifdef DEBUG_BUILD
        cout << "virtual methodName: " << className2 << "::" << methodName
             << " protoName: " << protoName << endl;
#ifdef DEX_DEBUG
        const char* targetMethod = "startService";
        if (methodName.substr(0, strlen(targetMethod)) == targetMethod) {
          cout << "check " << methodName << endl;
        }
#endif
#endif
        if (-2 == result) continue;
        // if ("<clinit>" == methodName)
        //     continue;

        AnalysisAssistMethodInfo methodInfo;
        methodInfo.methodName = methodName;
        methodInfo.protoName = protoName;
        if (0 != dexCode.getFastOpcodes(methodInfo.fastOpcodes)) continue;
#ifdef DEBUG_BUILD
        cout << "    fastOpcodes: [0x" << hex
             << (int)methodInfo.fastOpcodes.opcode01 << " 0x"
             << (int)methodInfo.fastOpcodes.opcode23 << " 0x"
             << (int)methodInfo.fastOpcodes.opcode45 << " 0x"
             << (int)methodInfo.fastOpcodes.opcode67 << " 0x"
             << (int)methodInfo.fastOpcodes.opcode89 << "]" << dec << endl;
#endif
        if (0 !=
            dexCode.parseCode(methodInfo.opcodeBuf, methodInfo.stringBuf)) {
          // success = false;
          // break;
          continue;
        }
        DexCodeCRC codeCRC;
        getCodeCRC(dexCode, codeCRC);

        if (codeCRC.hasOpcode) {
          char crcBuf[9] = {0};
          snprintf(crcBuf, sizeof(crcBuf), "%8x", codeCRC.opcodeCRC);
          methodInfo.opcodeCRC32 = crcBuf;

          DexCodeCrcSig* opcodeSig = NULL;
          if (0 == dexSigMgr_->searchOpcodeCrc(codeCRC.opcodeCRC, &opcodeSig)) {
            methodInfo.known = true;
            if (0 != codeResultMgr.addSigHit(opcodeSig)) {
              success = false;
              break;
            }
          }
        }

        if (codeCRC.hasOperandStr) {
          char crcBuf[9] = {0};
          snprintf(crcBuf, sizeof(crcBuf), "%8x", codeCRC.operandStrCRC);
          methodInfo.stringCRC32 = crcBuf;

          DexCodeCrcSig* operandSig = NULL;
          if (0 == dexSigMgr_->searchOperandCrc(codeCRC.operandStrCRC,
                                                &operandSig)) {
            methodInfo.known = true;
            if (0 != codeResultMgr.addSigHit(operandSig)) {
              success = false;
              break;
            }
          }
        }

        classInfo.methodInfoList.push_back(methodInfo);
      }
      if (!success) {
        ret = -1;
        break;
      }

      analysisAssistDexInfo->classInfoList.push_back(classInfo);
    }
  } catch (bad_alloc& e) {
    return -1;
  }

  if (0 != ret) return -1;
  ret = mergeScanResult(pathResultMgr, codeResultMgr, sigIDArray);
  PrintDexInfo(analysisAssistDexInfo);
  return ret;
}

#else

int DexParser::scan(OUT vector<uint32_t>& sigIDArray) {
  string className;
  DexPathScanResultMgr pathResultMgr;
  DexCodeScanResultMgr codeResultMgr;
  int ret = 0;
  int result = 0;
  while (-1 != (result = dexFile_->getClass(className))) {
    if (-2 == result) continue;
    if (0 != regularizeClassName(className)) continue;

    DexPathSig* pathSig;
    if (0 == dexSigMgr_->searchClassPath(className.c_str(), &pathSig)) {
      if (0 != pathResultMgr.addSigHit(pathSig)) {
        ret = -1;
        break;
      }
      continue;
    }

    string methodName;
    string protoName;
    DexCode dexCode;
    bool success = true;
    uint32_t key = 0;
    while (-1 != (result = dexFile_->getDirectMethod(methodName, protoName,
                                                     dexCode, key))) {
      // if ("<clinit>" == methodName)
      //     continue;
      if (-2 == result) continue;

#ifdef DEX_DEBUG
      cout << "^^^ className: " << className
           << " direct methodName: " << methodName
           << " protoName: " << protoName << endl;
      if (className == "com.energysource.szj.embeded.admanager" &&
          methodName == "initAd") {
        cout << "^^^ className: " << className << " methodName: " << methodName
             << " protoName: " << protoName << endl;
      }
      if (className == "com.energysource.szj.embeded.admanager" &&
          methodName == "requestAdvById") {
        cout << "^^^ className: " << className << " methodName: " << methodName
             << " protoName: " << protoName << endl;
      }
#endif

      FastOpcodes fastOpcodes;
      if (0 != dexCode.getFastOpcodes(fastOpcodes)) continue;
      if (0 != dexSigMgr_->searchOpcodeMap(&fastOpcodes)) continue;

      if (0 != scanCode(dexCode, codeResultMgr)) {
        // success = false;
        // break;
        continue;
      }
    }
    if (!success) {
      ret = -1;
      break;
    }

    key = 0;
    while (-1 != (result = dexFile_->getVirtualMethod(methodName, protoName,
                                                      dexCode, key))) {
      // if ("<clinit>" == methodName)
      //     continue;
      if (-2 == result) continue;

#ifdef DEX_DEBUG
      cout << "^^^ className: " << className
           << " virtual methodName: " << methodName
           << " protoName: " << protoName << endl;
      if (className == "com.energysource.szj.embeded.admanager" &&
          methodName == "initAd") {
        cout << "^^^ className: " << className << " methodName: " << methodName
             << " protoName: " << protoName << endl;
      }
      if (className == "com.energysource.szj.embeded.admanager" &&
          methodName == "requestAdvById") {
        cout << "^^^ className: " << className << " methodName: " << methodName
             << " protoName: " << protoName << endl;
      }
#endif

      FastOpcodes fastOpcodes;
      if (0 != dexCode.getFastOpcodes(fastOpcodes)) continue;
      if (0 != dexSigMgr_->searchOpcodeMap(&fastOpcodes)) continue;

      if (0 != scanCode(dexCode, codeResultMgr)) {
        // success = false;
        // break;
        continue;
      }
    }
    if (!success) {
      ret = -1;
      break;
    }
  }

  if (0 != ret) return -1;
  ret = mergeScanResult(pathResultMgr, codeResultMgr, sigIDArray);
  return ret;
}
#endif

int DexParser::regularizeClassName(string& className) {
  if (0 == className.size()) return -1;

  if ('L' == className[0]) className.erase(0, 1);
  if (0 == className.size()) return -1;
  if (';' == className[className.size() - 1])
    className.erase(className.size() - 1, 1);
  if (0 == className.size()) return -1;

  for (int i = 0; i < className.size(); i++) {
    if (className[i] >= 0x41 && className[i] <= 0x5a)
      className[i] += 0x20;
    else if ('/' == className[i])
      className[i] = '.';
  }
  transform(className.begin(), className.end(), className.begin(), ::tolower);

  return 0;
}

int DexParser::scanCode(DexCode& dexCode, DexCodeScanResultMgr& codeResultMgr) {
  int result = dexCode.parseCode();
  if (0 != result) return result;

  DexCodeCRC codeCRC;
  getCodeCRC(dexCode, codeCRC);

  if (codeCRC.hasOpcode) {
    DexCodeCrcSig* opcodeSig = NULL;
    if (0 == dexSigMgr_->searchOpcodeCrc(codeCRC.opcodeCRC, &opcodeSig)) {
      if (0 != codeResultMgr.addSigHit(opcodeSig)) return -1;
    }
  }

  if (codeCRC.hasOperandStr) {
    DexCodeCrcSig* operandSig = NULL;
    if (0 == dexSigMgr_->searchOperandCrc(codeCRC.operandStrCRC, &operandSig)) {
      if (0 != codeResultMgr.addSigHit(operandSig)) return -1;
    }
  }
  return 0;
}

int DexParser::getCodeCRC(DexCode& dexCode, DexCodeCRC& codeCRC) {
  if (0 != dexCode.getOpcodeCRC32(codeCRC.opcodeCRC))
    codeCRC.hasOpcode = false;
  else
    codeCRC.hasOpcode = true;

  if (0 != dexCode.getOperandStrCRC32(codeCRC.operandStrCRC))
    codeCRC.hasOperandStr = false;
  else
    codeCRC.hasOperandStr = true;
  return 0;
}

int DexParser::mergeScanResult(DexPathScanResultMgr& pathResultMgr,
                               DexCodeScanResultMgr& codeResultMgr,
                               vector<uint32_t>& sigIDArray) {
  int ret = -1;
  do {
    vector<uint32_t> pathSigIDArray;
    if (0 != pathResultMgr.getMalwareSigIDs(pathSigIDArray)) break;
    vector<uint32_t> codeSigIDArray;
    if (0 != codeResultMgr.getMalwareSigIDs(dexSigMgr_, codeSigIDArray)) break;

    try {
      if (codeSigIDArray.empty() && !pathSigIDArray.empty())
        sigIDArray = pathSigIDArray;
      if (pathSigIDArray.empty() && !codeSigIDArray.empty())
        sigIDArray = codeSigIDArray;
      if (!pathSigIDArray.empty() && !codeSigIDArray.empty()) {
        sigIDArray = codeSigIDArray;
        for (vector<uint32_t>::iterator i = pathSigIDArray.begin();
             i != pathSigIDArray.end(); ++i) {
          bool found = false;
          for (vector<uint32_t>::iterator j = codeSigIDArray.begin();
               j != codeSigIDArray.end(); ++j) {
            if (*j == *i) {
              found = true;
              break;
            }
          }
          if (!found) sigIDArray.push_back(*i);
        }
      }
    } catch (bad_alloc& e) {
      cerr << "DexParser::mergeScanResult bad_alloc caught: " << e.what()
           << endl;
      break;
    }

    ret = 0;
  } while (false);
  return ret;
}
