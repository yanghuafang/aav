#ifndef _MEMSTREAM_H_
#define _MEMSTREAM_H_

#include <mutex>
#include <string>

#include "IMemStream.h"
using namespace std;

struct MemSource;

class MemStream : public IMemStream {
 public:
  MemStream();

  int retain();
  int release();

  int getSize(int64_t* size);
  int getName(BSL_CHAR* nameBuf, int nameBufSize);
  int getFullPath(BSL_CHAR* pathBuf, int pathBufSize);
  int getProperty(SCAN_OBJECT_PROPERTY* property);

  int read(void* buf, int bytesToRead, int* bytesRead);
  int write(void* buf, int bytesToWrite, int* bytesWritten);
  int setSize(int64_t size);
  int flush();
  int seek(int64_t offset, int method);
  int tell(int64_t* pos);

  int init(MemSource* source);
  int uninit();

 private:
  ~MemStream();

 private:
  int ref_;
  recursive_mutex mutex_;
  int32_t mode_;
  string name_;
  void* buf_;
  int bufSize_;
  uint8_t* cur_;
};

#endif
