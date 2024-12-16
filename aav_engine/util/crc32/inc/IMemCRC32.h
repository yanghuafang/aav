#ifndef _IMEMCRC32_H_
#define _IMEMCRC32_H_

#include "ICRC32.h"

class IMemCRC32 : public ICRC32 {
 public:
  virtual int init(const void* buf, int bufSize) = 0;
  virtual int uninit() = 0;
};

#endif
