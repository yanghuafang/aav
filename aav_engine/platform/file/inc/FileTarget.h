#ifndef _FILETARGET_H_
#define _FILETARGET_H_

#include <mutex>
#include <string>

#include "IFileTarget.h"
using namespace std;

struct FileSource;

class FileMap;

class FileTarget : public IFileTarget {
 public:
  FileTarget();

  int retain();
  int release();

  int getSize(int64_t* size);
  int getName(BSL_CHAR* nameBuf, int nameBufSize);
  int getFullPath(BSL_CHAR* pathBuf, int pathBufSize);
  int getProperty(SCAN_OBJECT_PROPERTY* property);

  int getBuf(void** buf);

  int init(FileSource* source);
  int uninit();

 private:
  ~FileTarget();

 private:
  int ref_;
  recursive_mutex mutex_;
  int32_t mode_;
  string name_;
  string path_;
  FileMap* fileMap_;
};

#endif
