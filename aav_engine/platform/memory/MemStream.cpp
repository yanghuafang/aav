#include "MemStream.h"

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <new>

#include "MemSource.h"
#include "ScanObjectProperty.h"
using namespace std;

MemStream::MemStream() {
  ref_ = 1;
  mode_ = 0;
  buf_ = NULL;
  bufSize_ = 0;
  cur_ = NULL;
}

MemStream::~MemStream() { uninit(); }

int MemStream::retain() {
  mutex_.lock();
  int ref = ++ref_;
  mutex_.unlock();
  return ref;
}

int MemStream::release() {
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

int MemStream::init(MemSource* source) {
  if (NULL == source) return -1;

  try {
    mode_ = source->mode;
    if (O_RDONLY != mode_ && O_WRONLY != mode_ && O_RDWR != mode_) return -1;

    if (NULL != source->name) name_ = (char*)source->name;

    if (NULL == source->buf) return -1;
    buf_ = (char*)source->buf;
    cur_ = (uint8_t*)buf_;

    if (0 == source->bufSize) return -1;
    bufSize_ = source->bufSize;
  } catch (bad_alloc& e) {
    return -1;
  }

  return 0;
}

int MemStream::uninit() {
  mode_ = 0;
  buf_ = NULL;
  bufSize_ = 0;
  cur_ = NULL;
  return 0;
}

int MemStream::getSize(int64_t* size) { return bufSize_; }

int MemStream::getName(BSL_CHAR* nameBuf, int nameBufSize) {
  if (NULL == nameBuf || nameBufSize < 1) return -1;

  memset(nameBuf, 0, nameBufSize);
  strncpy((char*)nameBuf, name_.c_str(), nameBufSize / sizeof(BSL_CHAR) - 1);
  return 0;
}

int MemStream::getFullPath(BSL_CHAR* pathBuf, int pathBufSize) { return 0; }

int MemStream::getProperty(SCAN_OBJECT_PROPERTY* property) {
  if (NULL == property) return -1;

  property->unarchLayer = 0;
  property->unpackLayer = 0;
  return 0;
}

int MemStream::read(void* buf, int bytesToRead, int* bytesRead) {
  if (NULL == buf || NULL == bytesRead || bytesToRead < 1) return -1;

  int bytesLeft = bufSize_ - (cur_ - (uint8_t*)buf_);
  if (0 == bytesLeft) return -1;
  int bytesRealRead = bytesToRead < bytesLeft ? bytesToRead : bytesLeft;
  memcpy(buf, cur_, bytesRealRead);
  *bytesRead = bytesRealRead;
  cur_ += bytesRealRead;
  return 0;
}

int MemStream::write(void* buf, int bytesToWrite, int* bytesWritten) {
  if (NULL == buf || NULL == bytesWritten || bytesToWrite < 1) return -1;

  int bytesLeft = bufSize_ - (cur_ - (uint8_t*)buf_);
  if (0 == bytesLeft) return -1;
  int bytesRealWritten = bytesToWrite < bytesLeft ? bytesToWrite : bytesLeft;
  memcpy(cur_, buf, bytesRealWritten);
  *bytesWritten = bytesRealWritten;
  cur_ += bytesRealWritten;
  return 0;
}

int MemStream::setSize(int64_t size) { return 0; }

int MemStream::flush() { return 0; }

int MemStream::seek(int64_t offset, int method) {
  if (SEEK_SET != method && SEEK_CUR != method && SEEK_END != method) return -1;

  int ret = 0;
  switch (method) {
    case SEEK_SET: {
      if (offset > bufSize_ || offset < 0)
        ret = -1;
      else
        cur_ = (uint8_t*)buf_ + offset;
      break;
    }
    case SEEK_CUR: {
      if (offset > 0) {
        int bytesLeft = bufSize_ - (cur_ - (uint8_t*)buf_);
        if (offset > bytesLeft) ret = -1;
      } else if (offset < 0) {
        if (-offset > (cur_ - (uint8_t*)buf_)) ret = -1;
      }

      if (0 == ret) cur_ += offset;
      break;
    }
    case SEEK_END: {
      if (offset > 0)
        ret = -1;
      else {
        if (-offset > bufSize_) ret = -1;
      }

      if (0 == ret) cur_ = (uint8_t*)buf_ + bufSize_ + offset;
      break;
    }
    default:
      break;
  }

  return ret;
}

int MemStream::tell(int64_t* pos) {
  *pos = cur_ - (uint8_t*)buf_;
  return 0;
}
