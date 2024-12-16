#include "FileMap.h"

#include <assert.h>
#include <fcntl.h>
#include <stdio.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#if defined(ANDROID_BUILD) && defined(DEBUG_BUILD)
#include <android/log.h>
#include <errno.h>
#include <jni.h>

#endif

FileMap::FileMap() {
  ref_ = 1;
  ptr_ = NULL;
  size_ = 0;
}

FileMap::~FileMap() { close(); }

int FileMap::retain() {
  mutex_.lock();
  int ref = ++ref_;
  mutex_.unlock();
  return ref;
}

int FileMap::release() {
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

int FileMap::open(const BSL_CHAR* path, int mode) {
  if (NULL == path) return -1;
  if (O_RDONLY != mode && O_WRONLY != mode && O_RDWR != mode) return -1;

  int fd = -1;
  int ret = -1;
  do {
    fd = ::open((char*)path, mode);
    if (-1 == fd) {
#if defined(ANDROID_BUILD) && defined(DEBUG_BUILD)
      __android_log_print(ANDROID_LOG_ERROR, "aaveng",
                          "failed to open file: %s errno: %d", (char*)path,
                          errno);
#endif
      break;
    }

    struct stat st;
    if (0 != fstat(fd, &st)) {
#if defined(ANDROID_BUILD) && defined(DEBUG_BUILD)
      __android_log_print(ANDROID_LOG_ERROR, "aaveng",
                          "failed to fstat file: %s errno: %d", (char*)path,
                          errno);
#endif
      break;
    }
    if (!(S_IFREG & st.st_mode)) {
#if defined(ANDROID_BUILD) && defined(DEBUG_BUILD)
      __android_log_print(ANDROID_LOG_ERROR, "aaveng",
                          "%s is not regular file. errno: %d", (char*)path,
                          errno);
#endif
      break;
    }

    ptr_ = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    if (MAP_FAILED == ptr_) {
#if defined(ANDROID_BUILD) && defined(DEBUG_BUILD)
      __android_log_print(ANDROID_LOG_ERROR, "aaveng",
                          "mmap %s size: %d failed.", (char*)path, st.st_size);
#endif
      break;
    }
    size_ = st.st_size;
    ret = 0;
  } while (false);

  if (-1 != fd) {
    ::close(fd);
    fd = -1;
  }

  return ret;
}

int FileMap::close() {
  int ret = 0;
  if (NULL != ptr_) {
    ret = munmap(ptr_, size_);
    ptr_ = NULL;
    size_ = 0;
  }
  return ret;
}

int FileMap::getPtr(void** ptr) {
  if (NULL == ptr) return -1;
  if (NULL == ptr_) return -1;

  *ptr = ptr_;
  return 0;
}

int FileMap::getSize(int* size) {
  if (NULL == size) return -1;

  *size = size_;
  return 0;
}
