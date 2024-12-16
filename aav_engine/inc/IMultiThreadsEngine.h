#ifndef _IMULTITHREADSENGINE_H_
#define _IMULTITHREADSENGINE_H_

#include "IObject.h"
#include "TypeDefine.h"

class ICallback;

struct SCAN_OPTION;

class IMultiThreadsEngine : public IObject {
 public:
  virtual int init(int threadCount) = 0;
  virtual int uninit() = 0;
  virtual int setCallback(ICallback* callback) = 0;
  virtual int setScanOptions(const SCAN_OPTION* option) = 0;
  virtual int addFile(const BSL_CHAR* path) = 0;
  virtual int addDir(const BSL_CHAR* path) = 0;
  virtual int start() = 0;
  virtual int pause() = 0;
  virtual int resume() = 0;
  virtual int cancel() = 0;
  virtual int stop() = 0;
};

#endif
