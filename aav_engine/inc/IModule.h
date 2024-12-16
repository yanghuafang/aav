#ifndef _IMODULE_H_
#define _IMODULE_H_

#include "IObject.h"
#include "TypeDefine.h"

class IModule : public IObject {
 public:
  virtual int load(const BSL_CHAR* path) = 0;
  virtual int getFuncAddress(const char* funcName, void** funcAddress) = 0;
  virtual int unload() = 0;
};

#endif
