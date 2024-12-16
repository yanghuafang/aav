#ifndef _MEMCRC32_H_
#define _MEMCRC32_H_

#include <mutex>

#include "IMemCRC32.h"
using namespace std;

class MemCRC32 : public IMemCRC32 {
 public:
  MemCRC32();
  ~MemCRC32();

  int retain();
  int release();

  int getCRC32(uint32_t* crc);
  int getCRC32Str(char* crcBuf, int crcBufSize);

  int init(const void* buf, int bufSize);
  int uninit();

 private:
  int ref_;
  recursive_mutex mutex_;
  const void* buf_;
  int bufSize_;
};

#endif
