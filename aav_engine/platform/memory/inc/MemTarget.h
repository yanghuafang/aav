#ifndef _MEMTARGET_H_
#define _MEMTARGET_H_

#include <mutex>
#include <string>

#include "IMemTarget.h"
using namespace std;

struct MemSource;

class MemTarget : public IMemTarget {
 public:
  MemTarget();

  int retain();
  int release();

  int getSize(int64_t* size);
  int getName(BSL_CHAR* nameBuf, int nameBufSize);
  int getFullPath(BSL_CHAR* pathBuf, int pathBufSize);
  int getProperty(SCAN_OBJECT_PROPERTY* property);

  int getBuf(void** buf);

  int init(MemSource* source);
  int uninit();

 private:
  ~MemTarget();

 private:
  int ref_;
  recursive_mutex mutex_;
  int32_t mode_;
  string name_;
  void* buf_;
  int bufSize_;
};

#endif
