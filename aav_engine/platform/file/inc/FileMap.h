#ifndef _FILEMAP_H_
#define _FILEMAP_H_

#include <mutex>

#include "IFileMap.h"
using namespace std;

class FileMap : public IFileMap {
 public:
  FileMap();

  int retain();
  int release();

  int open(const BSL_CHAR* path, int mode);
  int close();
  int getPtr(void** ptr);
  int getSize(int* size);

 private:
  ~FileMap();

 private:
  int ref_;
  recursive_mutex mutex_;
  void* ptr_;
  int size_;
};

#endif
