#ifndef _IUNPACK_H_
#define _IUNPACK_H_

#include "IObject.h"
#include "TypeDefine.h"

class ITarget;

class IUnpack : public IObject {
 public:
  virtual int init(void* context) = 0;
  virtual int uninit() = 0;
  virtual int open(IN ITarget* target, OUT void** handle) = 0;
  virtual int getItem(IN void* handle, OUT ITarget** itemTarget) = 0;
  virtual int close(void* handle) = 0;
};

#endif
