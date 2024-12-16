#ifndef _ICALLBACK_H_
#define _ICALLBACK_H_

#include "IObject.h"
#include "TypeDefine.h"

class ITarget;

struct SCAN_RESULT;

class ICallback : public IObject {
 public:
  virtual int scanFilter(const BSL_CHAR* path) = 0;  // filter file name
  virtual int preScan(ITarget* target) = 0;
  virtual int postScan(ITarget* target,
                       SCAN_RESULT* result) = 0;  // post one sigID once
  virtual int enterLayer(ITarget* target) = 0;
  virtual int leaveLayer(ITarget* target) = 0;
};

#endif