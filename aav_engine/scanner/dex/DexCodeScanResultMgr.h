#ifndef _DEXCODESCANRESULTMGR_H_
#define _DEXCODESCANRESULTMGR_H_

#include <stdint.h>

#include <list>
#include <vector>
using namespace std;

struct DexCodeCrcSig;
struct DexCodeLogicSig;

class DexCodeScanResult;
class DexSigMgr;

class DexCodeScanResultMgr {
 public:
  DexCodeScanResultMgr();
  ~DexCodeScanResultMgr();

  int addSigHit(DexCodeCrcSig* codeSig);
  int getMalwareSigIDs(DexSigMgr* codeSigMgr, vector<uint32_t>& sigIDArray);

 private:
  bool matchNotLogic(DexCodeLogicSig& logicSig, DexCodeScanResult& scanResult);
  bool matchXorLogic(DexCodeLogicSig& logicSig, DexCodeScanResult& scanResult);
  bool matchAndLogic(DexCodeLogicSig& logicSig, DexCodeScanResult& scanResult);
  bool matchOrLogic(DexCodeLogicSig& logicSig, DexCodeScanResult& scanResult);

 private:
  list<DexCodeScanResult> scanResultList_;
};

#endif
