#ifndef _DEXPATHSCANRESULTMGR_H_
#define _DEXPATHSCANRESULTMGR_H_

#include <stdint.h>

#include <list>
#include <vector>

#include "DexSig.h"
using namespace std;

struct DexPathSig;

class DexPathScanResult;

class DexPathScanResultMgr {
 public:
  DexPathScanResultMgr();
  ~DexPathScanResultMgr();

  int addSigHit(const DexPathSig* pathSig);
  int getMalwareSigIDs(vector<uint32_t>& sigIDArray);

 private:
  list<DexPathScanResult> scanResultList_;
};

#endif
