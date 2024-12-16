#ifndef _IFILESYSTEM_H_
#define _IFILESYSTEM_H_

#include <stdint.h>

#include "IObject.h"
#include "TypeDefine.h"

class IStream;
class ITarget;

class IFileSystem : public IObject {
 public:
  virtual int createFile(const BSL_CHAR* path) = 0;
  virtual int removeFile(const BSL_CHAR* path) = 0;
  virtual int copyFile(const BSL_CHAR* src, const BSL_CHAR* dst) = 0;
  virtual int moveFile(const BSL_CHAR* src, const BSL_CHAR* dst) = 0;
  virtual bool fileExists(const BSL_CHAR* path) = 0;
  virtual int getFileSize(const BSL_CHAR* path, int64_t* fileSize) = 0;
  virtual int createTempFile(BSL_CHAR* pathBuf, int pathBufSize) = 0;

  virtual int makeDir(const BSL_CHAR* path) = 0;
  virtual int removeDir(const BSL_CHAR* path) = 0;
  virtual bool dirExists(const BSL_CHAR* path) = 0;
  virtual int getCurrentDir(BSL_CHAR* pathBuf, int pathBufSize) = 0;
  virtual int setCurrentDir(const BSL_CHAR* path) = 0;
};

#endif
