#ifndef _IFILETARGET_H_
#define _IFILETARGET_H_

#include "ITarget.h"

struct FileSource;

class IFileTarget : public ITarget {
 public:
  virtual int init(FileSource* source) = 0;
  virtual int uninit() = 0;
};

#endif
