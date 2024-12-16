#include "DexCodeScanResultMgr.h"

#include <assert.h>
#include <stdio.h>

#include <iostream>
#include <new>

#include "DexCodeScanResult.h"
#include "DexCodeSigMgr.h"
#include "DexSigMgr.h"
using namespace std;

DexCodeScanResultMgr::DexCodeScanResultMgr() {}

DexCodeScanResultMgr::~DexCodeScanResultMgr() { scanResultList_.clear(); }

int DexCodeScanResultMgr::addSigHit(DexCodeCrcSig* codeSig) {
  if (NULL == codeSig) return -1;

  for (vector<uint32_t>::iterator i = codeSig->sigIDs.begin();
       i != codeSig->sigIDs.end(); ++i) {
    bool found = false;
    for (list<DexCodeScanResult>::iterator j = scanResultList_.begin();
         j != scanResultList_.end(); ++j) {
      if (j->sigID() == *i) {
        if (0 != j->addCrc(codeSig->crc)) return -1;
        found = true;
        break;
      }
    }

    if (!found) {
      DexCodeScanResult result;
      result.setSigID(*i);
      result.addCrc(codeSig->crc);
      try {
        scanResultList_.push_back(result);
      } catch (bad_alloc& e) {
        cerr << "DexCodeScanResultMgr::addSigHit bad_alloc caught: " << e.what()
             << endl;
        return -1;
      }
    }
  }
  return 0;
}

int DexCodeScanResultMgr::getMalwareSigIDs(DexSigMgr* dexSigMgr,
                                           vector<uint32_t>& sigIDArray) {
  if (NULL == dexSigMgr) return -1;

  try {
    for (list<DexCodeScanResult>::iterator i = scanResultList_.begin();
         i != scanResultList_.end(); ++i) {
      DexCodeLogicSig* logicSig = NULL;
      if (0 != dexSigMgr->searchCodeLogic(i->sigID(), &logicSig)) return -1;
      assert(i->sigID() == logicSig->sigID);

      if (!logicSig->notCrcs.empty()) {
        if (matchNotLogic(*logicSig, *i)) continue;
      }
      if (!logicSig->xorCrcs.empty()) {
        if (matchXorLogic(*logicSig, *i)) continue;
      }

      bool foundMalware = false;
      if (!foundMalware && !logicSig->andCrcs.empty()) {
        if (matchAndLogic(*logicSig, *i)) foundMalware = true;
      }
      if (!foundMalware && !logicSig->orCrcs.empty()) {
        if (matchOrLogic(*logicSig, *i)) foundMalware = true;
      }
      if (foundMalware) sigIDArray.push_back(i->sigID());
    }
  } catch (bad_alloc& e) {
    cerr << "DexCodeScanResultMgr::getMalwareSigIDs bad_alloc caught: "
         << e.what() << endl;
    return -1;
  }
  return 0;
}

bool DexCodeScanResultMgr::matchNotLogic(DexCodeLogicSig& logicSig,
                                         DexCodeScanResult& scanResult) {
  for (vector<uint32_t>::iterator i = logicSig.notCrcs.begin();
       i != logicSig.notCrcs.end(); ++i) {
    if (scanResult.hasCrc(*i)) return true;
  }
  return false;
}

bool DexCodeScanResultMgr::matchXorLogic(DexCodeLogicSig& logicSig,
                                         DexCodeScanResult& scanResult) {
  int count = 0;
  for (vector<uint32_t>::iterator i = logicSig.xorCrcs.begin();
       i != logicSig.xorCrcs.end(); ++i) {
    if (scanResult.hasCrc(*i))
      count++;
    else
      break;
  }
  if (logicSig.xorCrcs.size() == count) return true;
  return false;
}

bool DexCodeScanResultMgr::matchAndLogic(DexCodeLogicSig& logicSig,
                                         DexCodeScanResult& scanResult) {
  int count = 0;
  for (vector<uint32_t>::iterator i = logicSig.andCrcs.begin();
       i != logicSig.andCrcs.end(); ++i) {
    if (scanResult.hasCrc(*i))
      count++;
    else
      break;
  }
  if (logicSig.andCrcs.size() == count) return true;
  return false;
}

bool DexCodeScanResultMgr::matchOrLogic(DexCodeLogicSig& logicSig,
                                        DexCodeScanResult& scanResult) {
  for (vector<uint32_t>::iterator i = logicSig.orCrcs.begin();
       i != logicSig.orCrcs.end(); ++i) {
    if (scanResult.hasCrc(*i)) return true;
  }
  return false;
}
