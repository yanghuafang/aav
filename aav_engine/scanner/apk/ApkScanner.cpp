#include "ApkScanner.h"

#include <assert.h>
#include <stdio.h>

#include <iostream>
#include <new>
using namespace std;

ApkScanner::ApkScanner() { ref_ = 1; }

ApkScanner::~ApkScanner() { uninit(); }

int ApkScanner::retain() {
  mutex_.lock();
  int ref = ++ref_;
  mutex_.unlock();
  return ref;
}

int ApkScanner::release() {
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

int ApkScanner::init(void* context) { return 0; }

int ApkScanner::uninit() { return 0; }

int ApkScanner::scanStream(IStream* stream, const SCAN_OPTION* option,
                           SCAN_RESULT** result) {
  if (NULL == stream || NULL == option || NULL == result) return -1;
  return 0;
}

int ApkScanner::scanTarget(ITarget* target, const SCAN_OPTION* option,
                           SCAN_RESULT** result) {
  if (NULL == target || NULL == option || NULL == result) return -1;
  return 0;
}

int ApkScanner::getScannerID(SCANNER_ID* id) {
  if (NULL == id) return -1;
  *id = SCANNER_ID_APK;
  return 0;
}
