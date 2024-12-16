#ifndef _IFILECRC32_H_
#define _IFILECRC32_H_

#include "ICRC32.h"

class IFileCRC32 : public ICRC32 {
 public:
  virtual int init(BSL_CHAR* path) = 0;
  virtual int uninit() = 0;
};

#endif
