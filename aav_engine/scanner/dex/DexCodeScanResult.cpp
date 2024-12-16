#include "DexCodeScanResult.h"

#include <assert.h>

#include <iostream>
#include <new>
using namespace std;

DexCodeScanResult::DexCodeScanResult() { sigID_ = 0; }

DexCodeScanResult::~DexCodeScanResult() {
  sigID_ = 0;
  crcSet_.clear();
}

uint32_t DexCodeScanResult::sigID() { return sigID_; }

int DexCodeScanResult::setSigID(uint32_t sigID) {
  assert(sigID != 0);
  sigID_ = sigID;
  return 0;
}

int DexCodeScanResult::addCrc(uint32_t crc) {
  try {
    crcSet_.insert(crc);
  } catch (bad_alloc& e) {
    cerr << "DexCodeSigMgr::addCrc bad_alloc caught: " << e.what() << endl;
    return -1;
  }
  return 0;
}

bool DexCodeScanResult::hasCrc(uint32_t crc) {
  set<uint32_t>::iterator it = crcSet_.find(crc);
  if (it != crcSet_.end()) return true;
  return false;
}
