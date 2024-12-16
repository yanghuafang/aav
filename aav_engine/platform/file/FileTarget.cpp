#include "FileTarget.h"

#include <fcntl.h>
#include <stdlib.h>
#include <string.h>

#include "FileMap.h"
#include "FileSource.h"
#include "ScanObjectProperty.h"

#if defined(ANDROID_BUILD) && defined(DEBUG_BUILD)
#include <android/log.h>
#include <errno.h>
#include <jni.h>

#endif

#include <iostream>
#include <new>

using namespace std;

FileTarget::FileTarget() {
  ref_ = 1;
  mode_ = 0;
  fileMap_ = NULL;
}

FileTarget::~FileTarget() { uninit(); }

int FileTarget::retain() {
  mutex_.lock();
  int ref = ++ref_;
  mutex_.unlock();
  return ref;
}

int FileTarget::release() {
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

int FileTarget::init(FileSource* source) {
  if (NULL == source) return -1;

  try {
    mode_ = source->mode;
    if (O_RDONLY != mode_ && O_WRONLY != mode_ && O_RDWR != mode_) return -1;

    if (NULL != source->name) name_ = (char*)source->name;

    if (NULL == source->path) return -1;
    path_ = (char*)source->path;
  } catch (bad_alloc& e) {
#if defined(ANDROID_BUILD) && defined(DEBUG_BUILD)
    __android_log_print(ANDROID_LOG_ERROR, "aaveng",
                        "in FileTarget::init bad_alloc caught: %s", e.what());
#endif
    return -1;
  }

  fileMap_ = new (nothrow) FileMap;
  if (NULL == fileMap_) {
#if defined(ANDROID_BUILD) && defined(DEBUG_BUILD)
    __android_log_print(ANDROID_LOG_ERROR, "aaveng", "failed to new FileMap.");
#endif
    return -1;
  }
  return fileMap_->open((const BSL_CHAR*)path_.c_str(), mode_);
}

int FileTarget::uninit() {
  mode_ = 0;

  if (NULL != fileMap_) {
    fileMap_->release();
    fileMap_ = NULL;
  }
  return 0;
}

int FileTarget::getSize(int64_t* size) {
  int size32 = 0;
  int ret = fileMap_->getSize(&size32);
  if (0 != ret) return -1;
  *size = size32;
  return 0;
}

int FileTarget::getName(BSL_CHAR* nameBuf, int nameBufSize) {
  if (NULL == nameBuf || nameBufSize < 1) return -1;

  memset(nameBuf, 0, nameBufSize);
  strncpy((char*)nameBuf, name_.c_str(), nameBufSize / sizeof(BSL_CHAR) - 1);
  return 0;
}

int FileTarget::getFullPath(BSL_CHAR* pathBuf, int pathBufSize) {
  if (NULL == pathBuf || pathBufSize < 1) return -1;

  memset(pathBuf, 0, pathBufSize);
  strncpy((char*)pathBuf, path_.c_str(), pathBufSize / sizeof(BSL_CHAR) - 1);
  return 0;
}

int FileTarget::getProperty(SCAN_OBJECT_PROPERTY* property) {
  if (NULL == property) return -1;

  property->unarchLayer = 0;
  property->unpackLayer = 0;
  return 0;
}

int FileTarget::getBuf(void** buf) { return fileMap_->getPtr(buf); }
