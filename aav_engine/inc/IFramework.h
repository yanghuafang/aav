#ifndef _IFRAMEWORK_H_
#define _IFRAMEWORK_H_

#include "IObject.h"
#include "TypeDefine.h"

class IEngine;
class IMultiThreadsEngine;

struct LOAD_MODULE_CONFIG;
struct LOAD_FORMAT_CONFIG;

class IFramework : public IObject {
 public:
  virtual int init() = 0;
  virtual int uninit() = 0;
  virtual int loadModules(const LOAD_MODULE_CONFIG* config) = 0;
  virtual int loadBases(const BSL_CHAR* path,
                        const LOAD_FORMAT_CONFIG* config) = 0;
  virtual int unloadBases() = 0;
  virtual int updateBases(const BSL_CHAR* dir) = 0;
  virtual int engineVersion() = 0;
  virtual int baseVersion() = 0;
  virtual int createEngine(IEngine* engine) = 0;
  virtual int createMultiThreadsEngine(IMultiThreadsEngine* engine) = 0;
};

#endif
