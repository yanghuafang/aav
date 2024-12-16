#ifndef _DEXSCANNER_H_
#define _DEXSCANNER_H_

#include "IScanner.h"
#include "TypeDefine.h"

// #include <atomic>
#include <mutex>
using namespace std;

class DexSigMgr;

class DexScanner : public IScanner {
 public:
  DexScanner();

  int retain();
  int release();

  int init(void* context);
  int uninit();
  int scanStream(IStream* stream, const SCAN_OPTION* option,
                 SCAN_RESULT** result);
  int scanTarget(ITarget* target, const SCAN_OPTION* option,
                 SCAN_RESULT** result);
  int getScannerID(SCANNER_ID* id);

 private:
  virtual ~DexScanner();

 private:
  // atomic_int ref_;
  int ref_;
  recursive_mutex mutex_;
  DexSigMgr* dexSigMgr_;
};

#endif
