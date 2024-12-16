#ifndef _DEXPARSER_H_
#define _DEXPARSER_H_

#include <stdint.h>

#include <string>
#include <vector>

#include "TypeDefine.h"
using namespace std;

class ITarget;
class DexSigMgr;
class DexFile;
class DexCode;
class DexPathScanResultMgr;
class DexCodeScanResultMgr;

struct DexCodeCRC {
  bool hasOpcode;
  uint32_t opcodeCRC;
  bool hasOperandStr;
  uint32_t operandStrCRC;
};

class DexParser {
 public:
  DexParser();
  ~DexParser();

  int init(DexSigMgr* sigMgr, ITarget* target);
  int uninit();
  int scan(OUT vector<uint32_t>& sigIDArray);

 private:
  int regularizeClassName(string& className);
  int scanCode(DexCode& dexCode, DexCodeScanResultMgr& codeResultMgr);
  int getCodeCRC(DexCode& dexCode, DexCodeCRC& codeCRC);
  int mergeScanResult(DexPathScanResultMgr& pathResultMgr,
                      DexCodeScanResultMgr& codeResultMgr,
                      OUT vector<uint32_t>& sigIDArray);

 private:
  DexSigMgr* dexSigMgr_;
  DexFile* dexFile_;
};

#endif
