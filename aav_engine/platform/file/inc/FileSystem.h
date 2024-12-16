#ifndef _FILESYSTEM_H_
#define _FILESYSTEM_H_

#include <mutex>

#include "IFileSystem.h"
using namespace std;

class FileSystem : public IFileSystem {
 public:
  FileSystem();

  int retain();
  int release();

  int createFile(const BSL_CHAR* path);
  int removeFile(const BSL_CHAR* path);
  int copyFile(const BSL_CHAR* src, const BSL_CHAR* dst);
  int moveFile(const BSL_CHAR* src, const BSL_CHAR* dst);
  bool fileExists(const BSL_CHAR* path);
  int getFileSize(const BSL_CHAR* path, int64_t* fileSize);
  int createTempFile(BSL_CHAR* pathBuf, int pathBufSize);

  int makeDir(const BSL_CHAR* path);
  int removeDir(const BSL_CHAR* path);
  bool dirExists(const BSL_CHAR* path);
  int getCurrentDir(BSL_CHAR* pathBuf, int pathBufSize);
  int setCurrentDir(const BSL_CHAR* path);

 private:
  ~FileSystem();

 private:
  int ref_;
  recursive_mutex mutex_;
};

#endif
