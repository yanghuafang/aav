#include "FileStream.h"

#include <fcntl.h>
#include <stdlib.h>
#include <string.h>

#include <iostream>
#include <new>

#include "FileSource.h"
#include "ScanObjectProperty.h"
using namespace std;

FileStream::FileStream() {
  ref_ = 1;
  mode_ = 0;
  file_ = NULL;
}

FileStream::~FileStream() { uninit(); }

int FileStream::retain() {
  mutex_.lock();
  int ref = ++ref_;
  mutex_.unlock();
  return ref;
}

int FileStream::release() {
  int ref = 0;
  bool kill = false;

  mutex_.lock();
  if (ref_ > 0) {
    ref = --ref_;
    if (0 == ref) kill = true;
  }
  mutex_.unlock();

  if (kill) delete this;
  return ref;
}

int FileStream::init(FileSource* source) {
  if (NULL == source) return -1;

  try {
    mode_ = source->mode;
    if (O_RDONLY != mode_ && O_WRONLY != mode_ && O_RDWR != mode_) return -1;

    if (NULL != source->name) name_ = (char*)source->name;

    if (NULL == source->path) return -1;
    path_ = (char*)source->path;
  } catch (bad_alloc& e) {
    return -1;
  }

  switch (mode_) {
    case O_RDONLY:
      file_ = fopen(path_.c_str(), "r");
      break;
    case O_WRONLY:
      file_ = fopen(path_.c_str(), "w");
      break;
    case O_RDWR:
      file_ = fopen(path_.c_str(), "r+");
      break;
    default:
      break;
  }

  if (NULL == file_) return -1;
  return 0;
}

int FileStream::uninit() {
  mode_ = 0;

  if (NULL != file_) {
    fclose(file_);
    file_ = NULL;
  }
  return 0;
}

int FileStream::getSize(int64_t* size) {
  int64_t pos = ftell(file_);
  if (-1 == pos) return -1;

  if (0 != fseek(file_, 0, SEEK_END)) return -1;
  *size = ftell(file_);

  if (0 != fseek(file_, pos, SEEK_SET)) {
    cerr << "FileStream::getSize fatal error!" << endl;
    abort();
    return -1;
  }

  if (-1 == *size) return -1;
  return 0;
}

int FileStream::getName(BSL_CHAR* nameBuf, int nameBufSize) {
  if (NULL == nameBuf || nameBufSize < 1) return -1;

  memset(nameBuf, 0, nameBufSize);
  strncpy((char*)nameBuf, name_.c_str(), nameBufSize / sizeof(BSL_CHAR) - 1);
  return 0;
}

int FileStream::getFullPath(BSL_CHAR* pathBuf, int pathBufSize) {
  if (NULL == pathBuf || pathBufSize < 1) return -1;

  memset(pathBuf, 0, pathBufSize);
  strncpy((char*)pathBuf, path_.c_str(), pathBufSize / sizeof(BSL_CHAR) - 1);
  return 0;
}

int FileStream::getProperty(SCAN_OBJECT_PROPERTY* property) {
  if (NULL == property) return -1;

  property->unarchLayer = 0;
  property->unpackLayer = 0;
  return 0;
}

int FileStream::read(void* buf, int bytesToRead, int* bytesRead) {
  if (NULL == buf || NULL == bytesRead || bytesToRead < 1) return -1;

  *bytesRead = fread(buf, 1, bytesToRead, file_);
  if (0 == *bytesRead) return -1;
  return 0;
}

int FileStream::write(void* buf, int bytesToWrite, int* bytesWritten) {
  if (NULL == buf || NULL == bytesWritten || bytesToWrite < 1) return -1;

  *bytesWritten = fwrite(buf, 1, bytesToWrite, file_);
  if (0 == *bytesWritten) return -1;
  return 0;
}

int FileStream::setSize(int64_t size) { return 0; }

int FileStream::flush() { return 0; }

int FileStream::seek(int64_t offset, int method) {
  if (SEEK_SET != method && SEEK_CUR != method && SEEK_END != method) return -1;

  if (0 == fseek(file_, offset, method)) return 0;
  return -1;
}

int FileStream::tell(int64_t* pos) {
  *pos = ftell(file_);
  if (-1 == *pos) return -1;
  return 0;
}
