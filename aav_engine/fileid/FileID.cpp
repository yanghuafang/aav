#include "FileID.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

#include <iostream>
#include <new>

#include "IStream.h"
#include "ITarget.h"
using namespace std;

FileID::FileID() { ref_ = 1; }

FileID::~FileID() { uninit(); }

int FileID::retain() {
  mutex_.lock();
  int ref = ++ref_;
  mutex_.unlock();
  return ref;
}

int FileID::release() {
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

int FileID::init(void* context) { return 0; }

int FileID::uninit() { return 0; }

int FileID::getFileType(IStream* stream, FILE_TYPE* fileType) {
  if (NULL == stream || NULL == fileType) return -1;

  int64_t fileSize = 0;
  if (0 != stream->getSize(&fileSize)) return -1;
  if (fileSize < 16) return -1;

  char buf[16] = {0};
  int bytesRead = 0;
  if (0 != stream->read(buf, sizeof(buf), &bytesRead)) return -1;

  uint8_t DEX_FILE_MAGIC[8] = {0x64, 0x65, 0x78, 0x0a,
                               0x30, 0x33, 0x35, 0x00};  //"dex\n035\0"
  if (0 == memcmp(buf, DEX_FILE_MAGIC, sizeof(DEX_FILE_MAGIC))) {
    *fileType = FILE_TYPE_DEX;
    return 0;
  }

  uint8_t ZIP_FILE_MAGIC[4] = {0x50, 0x4b, 0x03, 0x04};
  if (0 == memcmp(buf, ZIP_FILE_MAGIC, sizeof(ZIP_FILE_MAGIC))) {
    *fileType = FILE_TYPE_ZIP;
    return 0;
  }

  *fileType = FILE_TYPE_UNKNOWN;
  return -1;
}

int FileID::getFileType(ITarget* target, FILE_TYPE* fileType) {
  if (NULL == target || NULL == fileType) return -1;

  int64_t fileSize = 0;
  if (0 != target->getSize(&fileSize)) return -1;
  if (fileSize < 16) return -1;

  void* buf = NULL;
  if (0 != target->getBuf(&buf)) return -1;

  uint8_t DEX_FILE_MAGIC[8] = {0x64, 0x65, 0x78, 0x0a,
                               0x30, 0x33, 0x35, 0x00};  //"dex\n035\0"
  if (0 == memcmp(buf, DEX_FILE_MAGIC, sizeof(DEX_FILE_MAGIC))) {
    *fileType = FILE_TYPE_DEX;
    return 0;
  }

  uint8_t ZIP_FILE_MAGIC[4] = {0x50, 0x4b, 0x03, 0x04};
  if (0 == memcmp(buf, ZIP_FILE_MAGIC, sizeof(ZIP_FILE_MAGIC))) {
    *fileType = FILE_TYPE_ZIP;
    return 0;
  }

  *fileType = FILE_TYPE_UNKNOWN;
  return -1;
}

int FileID::getPackType(IStream* stream, PACK_TYPE* packType) {
  if (NULL == stream || NULL == packType) return -1;
  *packType = PACK_TYPE_UNKNOWN;
  return 0;
}

int FileID::getPackType(ITarget* target, PACK_TYPE* packType) {
  if (NULL == target || NULL == packType) return -1;
  *packType = PACK_TYPE_UNKNOWN;
  return 0;
}
