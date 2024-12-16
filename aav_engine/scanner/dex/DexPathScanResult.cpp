#include "DexPathScanResult.h"

#include <assert.h>

DexPathScanResult::DexPathScanResult() {
  sigID_ = 0;
  andMatchCount_ = 0;
  orMatchCount_ = 0;
  xorMatchCount_ = 0;
  notMatchCount_ = 0;
}

DexPathScanResult::~DexPathScanResult() {}

uint32_t DexPathScanResult::sigID() { return sigID_; }

int DexPathScanResult::setSigID(uint32_t sigID) {
  assert(sigID != 0);
  sigID_ = sigID;
  return 0;
}

int DexPathScanResult::addLogicMatchType(LOGIC_MATCH_TYPE logicMatchType) {
  int ret = 0;

  switch (logicMatchType) {
    case LOGIC_MATCH_TYPE_AND:
      andMatchCount_++;
      break;
    case LOGIC_MATCH_TYPE_OR:
      orMatchCount_++;
      break;
    case LOGIC_MATCH_TYPE_XOR:
      xorMatchCount_++;
      break;
    case LOGIC_MATCH_TYPE_NOT:
      notMatchCount_++;
      break;
    default:
      assert(false);
      ret = -1;
      break;
  }

  return ret;
}

bool DexPathScanResult::isMalware() {
  if (notMatchCount_ > 0) return false;
  if (xorMatchCount_ > 1) return false;

  if (orMatchCount_ > 0) return true;
  if (andMatchCount_ > 1) return true;
  if (1 == xorMatchCount_) return true;

  return false;
}
