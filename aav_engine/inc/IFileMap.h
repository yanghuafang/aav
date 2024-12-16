#ifndef _IFILEMAP_H_
#define _IFILEMAP_H_

#include "IObject.h"
#include "TypeDefine.h"

class IFileMap : public IObject {
 public:
  virtual int open(const BSL_CHAR* path,
                   int mode) = 0;  // mode 0: O_RDONLY 1: O_WRONLY 2: O_RDWR
  virtual int close() = 0;
  virtual int getPtr(void** ptr) = 0;
  virtual int getSize(int* size) = 0;
};

#endif
