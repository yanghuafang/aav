#ifndef _DEXCODESCANRESULT_H_
#define _DEXCODESCANRESULT_H_

#include <stdint.h>

#include <set>

#include "DexSig.h"
using namespace std;

class DexCodeScanResult {
 public:
  DexCodeScanResult();
  ~DexCodeScanResult();

  uint32_t sigID();
  int setSigID(uint32_t sigID);
  int addCrc(uint32_t crc);
  bool hasCrc(uint32_t crc);

 private:
  uint32_t sigID_;
  set<uint32_t> crcSet_;
};

#endif
