#include "DexPathScanResultMgr.h"

#include <stdio.h>

#include <iostream>
#include <new>

#include "DexPathScanResult.h"
#include "DexPathSigMgr.h"
using namespace std;

DexPathScanResultMgr::DexPathScanResultMgr() {}

DexPathScanResultMgr::~DexPathScanResultMgr() { scanResultList_.clear(); }

int DexPathScanResultMgr::addSigHit(const DexPathSig* pathSig) {
  if (NULL == pathSig) return -1;

  bool found = false;
  for (list<DexPathScanResult>::iterator i = scanResultList_.begin();
       i != scanResultList_.end(); ++i) {
    if (pathSig->sigID == i->sigID()) {
      i->addLogicMatchType(pathSig->logicMatchType);
      found = true;
      break;
    }
  }

  if (!found) {
    DexPathScanResult result;
    result.setSigID(pathSig->sigID);
    result.addLogicMatchType(pathSig->logicMatchType);
    try {
      scanResultList_.push_back(result);
    } catch (bad_alloc& e) {
      cerr << "DexPathScanResultMgr::addSigHit bad_alloc caught: " << e.what()
           << endl;
      return -1;
    }
  }
  return 0;
}

int DexPathScanResultMgr::getMalwareSigIDs(vector<uint32_t>& sigIDArray) {
  try {
    for (list<DexPathScanResult>::iterator i = scanResultList_.begin();
         i != scanResultList_.end(); ++i) {
      if (i->isMalware()) sigIDArray.push_back(i->sigID());
    }
  } catch (bad_alloc& e) {
    cerr << "DexPathScanResultMgr::getMalwareSigIDs bad_alloc caught: "
         << e.what() << endl;
    return -1;
  }
  return 0;
}
