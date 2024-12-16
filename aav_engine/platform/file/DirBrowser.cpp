#include "DirBrowser.h"

#include <string.h>
#include <sys/stat.h>

DirBrowser::DirBrowser() {
  ref_ = 1;
  dir_ = NULL;
}

DirBrowser::~DirBrowser() { close(); }

int DirBrowser::retain() {
  mutex_.lock();
  int ref = ++ref_;
  mutex_.unlock();
  return ref;
}

int DirBrowser::release() {
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

int DirBrowser::open(const BSL_CHAR* path) {
  if (NULL == path) return -1;

  dir_ = opendir((const char*)path);
  if (NULL == dir_) return -1;

  return 0;
}

int DirBrowser::getItem(BSL_CHAR* pathBuf, int pathBufSize) {
  if (NULL == pathBuf) return -1;

  int ret = -1;
  struct dirent* d = NULL;
  while (NULL != (d = readdir(dir_))) {
    if (0 == strcmp(d->d_name, ".") || 0 == strcmp(d->d_name, "..")) continue;
    memset(pathBuf, 0, pathBufSize);
    strncpy((char*)pathBuf, d->d_name, pathBufSize - 1);
    ret = 0;
    break;
  }

  return ret;
}

bool DirBrowser::isFile(const BSL_CHAR* path) {
  if (NULL == path) return false;

  struct stat st;
  if (0 != stat((char*)path, &st)) return false;
  if (S_IFREG & st.st_mode) return true;
  return false;
}

bool DirBrowser::isDir(const BSL_CHAR* path) {
  if (NULL == path) return false;

  struct stat st;
  if (0 != stat((char*)path, &st)) return false;
  if (S_IFDIR & st.st_mode) return true;
  return false;
}

int DirBrowser::close() {
  if (NULL != dir_) {
    closedir(dir_);
    dir_ = NULL;
  }
  return 0;
}
