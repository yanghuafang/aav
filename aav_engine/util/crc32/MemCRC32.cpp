#include "MemCRC32.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "crc32.h"

MemCRC32::MemCRC32() {
  ref_ = 1;
  buf_ = NULL;
  bufSize_ = 0;
}

MemCRC32::~MemCRC32() { uninit(); }

int MemCRC32::retain() {
  mutex_.lock();
  int ref = ++ref_;
  mutex_.unlock();
  return ref;
}

int MemCRC32::release() {
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

int MemCRC32::init(const void* buf, int bufSize) {
  if (NULL == buf || bufSize < 0) return -1;

  buf_ = buf;
  bufSize_ = bufSize;
  return 0;
}

int MemCRC32::uninit() {
  buf_ = NULL;
  bufSize_ = 0;
  return 0;
}

int MemCRC32::getCRC32(uint32_t* crc) {
  if (NULL == crc) return -1;

  *crc = crc32(0, buf_, bufSize_);
  return 0;
}

int MemCRC32::getCRC32Str(char* crcBuf, int crcBufSize) {
  if (NULL == crcBuf || crcBufSize < 8) return -1;

  uint32_t crc = crc32(0, buf_, bufSize_);
  memset(crcBuf, 0, crcBufSize);
  snprintf(crcBuf, crcBufSize, "%8x", crc);
  return 0;
}
