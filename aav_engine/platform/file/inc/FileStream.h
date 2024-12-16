#ifndef _FILESTREAM_H_
#define _FILESTREAM_H_

#include <stdio.h>

#include <mutex>
#include <string>

#include "IFileStream.h"
using namespace std;

struct FileSource;

class FileStream : public IFileStream {
 public:
  FileStream();

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

  int init(FileSource* source);
  int uninit();

 private:
  ~FileStream();

 private:
  int ref_;
  recursive_mutex mutex_;
  int32_t mode_;
  string name_;
  string path_;
  FILE* file_;
};

#endif
