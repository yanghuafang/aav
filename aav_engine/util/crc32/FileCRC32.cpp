#include "FileCRC32.h"

#include <stdlib.h>
#include <string.h>

#include "crc32.h"

FileCRC32::FileCRC32() {
  ref_ = 1;
  file_ = NULL;
}

FileCRC32::~FileCRC32() { uninit(); }

int FileCRC32::retain() {
  mutex_.lock();
  int ref = ++ref_;
  mutex_.unlock();
  return ref;
}

int FileCRC32::release() {
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

int FileCRC32::init(BSL_CHAR* path) {
  if (NULL == path) return -1;

  file_ = fopen((char*)path, "r");
  if (NULL == file_) return -1;
  return 0;
}

int FileCRC32::uninit() {
  fclose(file_);
  file_ = NULL;
  return 0;
}

int FileCRC32::getCRC32(uint32_t* crc) {
  int bufSize = 64 * 1024;
  uint8_t* buf = (uint8_t*)malloc(bufSize);
  if (NULL == buf) return -1;

  uint32_t oldcrc = 0;
  do {
    int bytesRead = fread(buf, 1, bufSize, file_);
    if (0 == bytesRead) break;
    oldcrc = crc32(oldcrc, buf, bytesRead);
    if (bytesRead < bufSize) break;
  } while (true);

  *crc = oldcrc;
  return 0;
}

int FileCRC32::getCRC32Str(char* crcBuf, int crcBufSize) {
  if (NULL == crcBuf || crcBufSize < 8) return -1;

  uint32_t crc = 0;
  getCRC32(&crc);
  memset(crcBuf, 0, crcBufSize);
  snprintf(crcBuf, crcBufSize, "%8x", crc);
  return 0;
}
