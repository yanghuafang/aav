#ifndef _ITARGET_H_
#define _ITARGET_H_

#include "IScanObject.h"

class ITarget : public IScanObject {
 public:
  virtual int getBuf(void** buf) = 0;
};

#endif
