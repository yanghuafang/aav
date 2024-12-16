#ifndef _ICRC32_H_
#define _ICRC32_H_

#include <stdint.h>

#include "IObject.h"
#include "TypeDefine.h"

class ICRC32 : public IObject {
 public:
  virtual int getCRC32(uint32_t* crc) = 0;
  virtual int getCRC32Str(char* crcBuf, int crcBufSize) = 0;
};

#endif
