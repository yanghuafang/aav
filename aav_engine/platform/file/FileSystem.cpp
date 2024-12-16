#include "FileSystem.h"

#include <stdio.h>
#include <sys/stat.h>
#include <unistd.h>

FileSystem::FileSystem() { ref_ = 1; }

FileSystem::~FileSystem() {}

int FileSystem::retain() {
  mutex_.lock();
  int ref = ++ref_;
  mutex_.unlock();
  return ref;
}

int FileSystem::release() {
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

int FileSystem::createFile(const BSL_CHAR* path) {
  if (NULL == path) return -1;

  FILE* file = fopen((char*)path, "r+");
  if (NULL == file) return -1;
  fclose(file);
  file = NULL;
  return 0;
}

int FileSystem::removeFile(const BSL_CHAR* path) { return unlink((char*)path); }

int FileSystem::copyFile(const BSL_CHAR* src, const BSL_CHAR* dst) { return 0; }

int FileSystem::moveFile(const BSL_CHAR* src, const BSL_CHAR* dst) {
  return rename((char*)src, (char*)dst);
}

bool FileSystem::fileExists(const BSL_CHAR* path) {
  if (NULL == path) return false;

  struct stat st;
  if (0 != stat((char*)path, &st)) return false;
  if (S_IFREG & st.st_mode) return true;
  return false;
}

int FileSystem::getFileSize(const BSL_CHAR* path, int64_t* fileSize) {
  struct stat64 st;
  if (0 != lstat64((char*)path, &st)) return -1;
  if (!(S_IFREG & st.st_mode)) return -1;
  *fileSize = st.st_size;
  return 0;
}

int FileSystem::createTempFile(BSL_CHAR* pathBuf, int pathBufSize) { return 0; }

int FileSystem::makeDir(const BSL_CHAR* path) {
  return mkdir((char*)path, S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH);
}

int FileSystem::removeDir(const BSL_CHAR* path) { return rmdir((char*)path); }

bool FileSystem::dirExists(const BSL_CHAR* path) {
  if (NULL == path) return false;

  struct stat st;
  if (0 != stat((char*)path, &st)) return false;
  if (S_IFDIR & st.st_mode) return true;
  return false;
}

int FileSystem::getCurrentDir(BSL_CHAR* pathBuf, int pathBufSize) {
  if (NULL == getcwd((char*)pathBuf, pathBufSize)) return -1;
  return 0;
}

int FileSystem::setCurrentDir(const BSL_CHAR* path) {
  return chdir((char*)path);
}
