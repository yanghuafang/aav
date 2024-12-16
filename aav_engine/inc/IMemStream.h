#ifndef _IMEMSTREAM_H_
#define _IMEMSTREAM_H_

#include "IStream.h"

struct MemSource;

class IMemStream : public IStream {
 public:
  virtual int init(MemSource* source) = 0;
  virtual int uninit() = 0;
};

#endif
