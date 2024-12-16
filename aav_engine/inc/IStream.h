#ifndef _ISTREAM_H_
#define _ISTREAM_H_

#include <stdint.h>

#include "IScanObject.h"

class IStream : public IScanObject {
 public:
  virtual int read(void* buf, int bytesToRead, int* bytesRead) = 0;
  virtual int write(void* buf, int bytesToWrite, int* bytesWritten) = 0;
  virtual int setSize(int64_t size) = 0;
  virtual int flush() = 0;
  virtual int seek(
      int64_t offset,
      int method) = 0;  // method 0: SEEK_SET 1: SEEK_CUR 2: SEEK_END
  virtual int tell(int64_t* pos) = 0;
};

#endif
