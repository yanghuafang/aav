#ifndef _IFILESTREAM_H_
#define _IFILESTREAM_H_

#include "IStream.h"

struct FileSource;

class IFileStream : public IStream {
 public:
  virtual int init(FileSource* source) = 0;
  virtual int uninit() = 0;
};

#endif
