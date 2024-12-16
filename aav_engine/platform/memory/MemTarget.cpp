#include "MemTarget.h"

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <new>

#include "MemSource.h"
#include "ScanObjectProperty.h"
using namespace std;

MemTarget::MemTarget() {
  ref_ = 1;
  mode_ = 0;
  buf_ = NULL;
  bufSize_ = 0;
}

MemTarget::~MemTarget() { uninit(); }

int MemTarget::retain() {
  mutex_.lock();
  int ref = ++ref_;
  mutex_.unlock();
  return ref;
}

int MemTarget::release() {
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

int MemTarget::init(MemSource* source) {
  if (NULL == source) return -1;

  try {
    mode_ = source->mode;
    if (O_RDONLY != mode_ && O_WRONLY != mode_ && O_RDWR != mode_) return -1;

    if (NULL != source->name) name_ = (char*)source->name;

    if (NULL == source->buf) return -1;
    buf_ = (char*)source->buf;

    if (0 == source->bufSize) return -1;
    bufSize_ = source->bufSize;
  } catch (bad_alloc& e) {
    return -1;
  }

  return 0;
}

int MemTarget::uninit() {
  mode_ = 0;
  buf_ = NULL;
  bufSize_ = 0;
  return 0;
}

int MemTarget::getSize(int64_t* size) { return bufSize_; }

int MemTarget::getName(BSL_CHAR* nameBuf, int nameBufSize) {
  if (NULL == nameBuf || nameBufSize < 1) return -1;

  memset(nameBuf, 0, nameBufSize);
  strncpy((char*)nameBuf, name_.c_str(), nameBufSize / sizeof(BSL_CHAR) - 1);
  return 0;
}

int MemTarget::getFullPath(BSL_CHAR* pathBuf, int pathBufSize) { return 0; }

int MemTarget::getProperty(SCAN_OBJECT_PROPERTY* property) {
  if (NULL == property) return -1;

  property->unarchLayer = 0;
  property->unpackLayer = 0;
  return 0;
}

int MemTarget::getBuf(void** buf) {
  if (NULL == buf) return -1;

  *buf = buf_;
  return 0;
}
