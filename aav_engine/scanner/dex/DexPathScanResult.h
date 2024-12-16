#ifndef _DEXPATHSCANRESULT_H_
#define _DEXPATHSCANRESULT_H_

#include <stdint.h>

#include "DexSig.h"

class DexPathScanResult {
 public:
  DexPathScanResult();
  ~DexPathScanResult();

  uint32_t sigID();
  int setSigID(uint32_t sigID);
  int addLogicMatchType(LOGIC_MATCH_TYPE logicMatchType);
  bool isMalware();

 private:
  uint32_t sigID_;
  int andMatchCount_;
  int orMatchCount_;
  int xorMatchCount_;
  int notMatchCount_;
};

#endif
