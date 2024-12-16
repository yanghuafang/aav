#ifndef _IENGINE_H_
#define _IENGINE_H_

#include "IObject.h"

class ICallback;
class IStream;
class ITarget;

struct SCAN_OPTION;
struct SCAN_RESULT;

class IEngine : public IObject {
 public:
  virtual int init(void* context) = 0;
  virtual int uninit() = 0;
  virtual int setCallback(ICallback* callback) = 0;
  virtual int scanStream(IStream* stream, const SCAN_OPTION* option) = 0;
  virtual int scanTarget(ITarget* target, const SCAN_OPTION* option) = 0;
  virtual int pause() = 0;
  virtual int resume() = 0;
  virtual int stop() = 0;
};

#endif