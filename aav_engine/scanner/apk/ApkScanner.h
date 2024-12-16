#ifndef _FILEID_H_
#define _FILEID_H_

#include "IScanner.h"

// #include <atomic>
#include <mutex>
using namespace std;

class ApkScanner : public IScanner {
 public:
  ApkScanner();

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
  virtual ~ApkScanner();

 private:
  // atomic_int ref_;
  int ref_;
  recursive_mutex mutex_;
};

#endif
