#ifndef _IUNARCH_H_
#define _IUNARCH_H_

#include "IObject.h"
#include "TypeDefine.h"

class IStream;

class IUnarch : public IObject {
 public:
  virtual int init(void* context) = 0;
  virtual int uninit() = 0;
  virtual int open(IN IStream* stream, OUT void** handle) = 0;
  virtual int getItem(IN void* handle, OUT IStream** itemStream) = 0;
  virtual int close(void* handle) = 0;
};

#endif
