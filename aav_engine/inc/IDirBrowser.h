#ifndef _IDIRBROWSER_H_
#define _IDIRBROWSER_H_

#include "IObject.h"
#include "TypeDefine.h"

class IDirBrowser : public IObject {
 public:
  virtual int open(const BSL_CHAR* path) = 0;
  virtual int getItem(BSL_CHAR* pathBuf, int pathBufSize) = 0;
  virtual bool isFile(const BSL_CHAR* path) = 0;
  virtual bool isDir(const BSL_CHAR* path) = 0;
  virtual int close() = 0;
};

#endif
