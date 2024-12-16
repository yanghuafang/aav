#ifndef _IMEMTARGET_H_
#define _IMEMTARGET_H_

#include "ITarget.h"

struct MemSource;

class IMemTarget : public ITarget {
 public:
  virtual int init(MemSource* source) = 0;
  virtual int uninit() = 0;
};

#endif
