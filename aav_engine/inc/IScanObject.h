#ifndef _ISCANOBJECT_H_
#define _ISCANOBJECT_H_

#include <stdint.h>

#include "IObject.h"
#include "TypeDefine.h"

struct SCAN_OBJECT_PROPERTY;

class IScanObject : public IObject {
 public:
  virtual int getSize(int64_t* size) = 0;
  virtual int getName(BSL_CHAR* nameBuf, int nameBufSize) = 0;
  virtual int getFullPath(BSL_CHAR* pathBuf, int pathBufSize) = 0;
  virtual int getProperty(SCAN_OBJECT_PROPERTY* property) = 0;
};

#endif
