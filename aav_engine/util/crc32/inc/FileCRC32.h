#ifndef _FILECRC32_H_
#define _FILECRC32_H_

#include <stdio.h>

#include <mutex>

#include "IFileCRC32.h"
using namespace std;

class FileCRC32 : public IFileCRC32 {
 public:
  FileCRC32();
  ~FileCRC32();

  int retain();
  int release();

  int getCRC32(uint32_t* crc);
  int getCRC32Str(char* crcBuf, int crcBufSize);

  int init(BSL_CHAR* path);
  int uninit();

 private:
  int ref_;
  recursive_mutex mutex_;
  FILE* file_;
};

#endif
