#include "DexScanner.h"

#include <stdio.h>
#include <stdlib.h>

#include <new>
#include <vector>

#include "DexParser.h"
#include "DexSigMgr.h"
#include "IScanner.h"
#include "ISigMgr.h"
#include "MalwareName.h"
#include "ScanOption.h"
#include "ScanResult.h"
#include "TypeDefine.h"
using namespace std;

DexScanner::DexScanner() {
  ref_ = 1;
  dexSigMgr_ = NULL;
}

DexScanner::~DexScanner() { uninit(); }

int DexScanner::retain() {
  mutex_.lock();
  int ref = ++ref_;
  mutex_.unlock();
  return ref;
}

int DexScanner::release() {
  int ref = 0;
  bool kill = false;

  mutex_.lock();
  if (ref_ > 0) {
    ref = --ref_;
    if (0 == ref) kill = true;
  }
  mutex_.unlock();

  if (kill) delete this;
  return ref;
}

int DexScanner::init(void* context) {
  if (NULL == context) return -1;

  int ret = -1;
  do {
    ISigMgr* sigMgr = (ISigMgr*)context;
    dexSigMgr_ = new (nothrow) DexSigMgr;
    if (NULL == dexSigMgr_) break;
    if (0 != dexSigMgr_->init(sigMgr)) break;
    ret = 0;
  } while (false);

  if (0 != ret) uninit();
  return ret;
}

int DexScanner::uninit() {
  delete dexSigMgr_;
  dexSigMgr_ = NULL;
  return 0;
}

int DexScanner::scanStream(IStream* stream, const SCAN_OPTION* option,
                           SCAN_RESULT** result) {
  return -1;
}

int DexScanner::scanTarget(ITarget* target, const SCAN_OPTION* option,
                           SCAN_RESULT** result) {
  if (NULL == target || NULL == option || NULL == result) return -1;
  if (!option->config.dex) return -1;

  DexParser* dexParser = NULL;
  vector<uint32_t> sigIDArray;
  *result = NULL;
  int ret = -1;

  do {
    dexParser = new (nothrow) DexParser;
    if (NULL == dexParser) break;
    if (0 != dexParser->init(dexSigMgr_, target)) break;
    if (0 != dexParser->scan(sigIDArray)) break;

    if (!sigIDArray.empty()) {
      int size =
          sizeof(SCAN_RESULT) + (sigIDArray.size() - 1) * sizeof(uint32_t);
      SCAN_RESULT* scanResult = (SCAN_RESULT*)malloc(size);
      if (NULL == scanResult) break;
      scanResult->isWhite = 0;
      scanResult->isMalware = 1;
      scanResult->scannerID = (uint16_t)SCANNER_ID_DEX;
      scanResult->fileType = (uint16_t)MALWARE_FILE_FORMAT_DEX;
      scanResult->sigCount = sigIDArray.size();
      for (int i = 0; i < scanResult->sigCount; i++)
        scanResult->sigID[i] = sigIDArray[i];
      *result = scanResult;
    } else {
      SCAN_RESULT* scanResult = (SCAN_RESULT*)malloc(sizeof(SCAN_RESULT));
      if (NULL == scanResult) break;
      scanResult->isWhite = 0;
      scanResult->isMalware = 0;
      scanResult->scannerID = (uint16_t)SCANNER_ID_DEX;
      scanResult->fileType = (uint16_t)MALWARE_FILE_FORMAT_DEX;
      scanResult->sigCount = 0;
      scanResult->sigID[0] = 0;
      *result = scanResult;
    }

    ret = 0;
  } while (false);

  delete dexParser;
  dexParser = NULL;
  if (0 != ret) {
    free(*result);
    *result = NULL;
  }

  return ret;
}

int DexScanner::getScannerID(SCANNER_ID* id) {
  if (NULL == id) return -1;

  *id = SCANNER_ID_DEX;
  return 0;
}
