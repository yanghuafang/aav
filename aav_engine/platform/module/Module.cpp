#include "Module.h"

#include <dlfcn.h>
#include <stdio.h>

Module::Module() {
  ref_ = 1;
  handle_ = NULL;
}

Module::~Module() { unload(); }

int Module::retain() {
  mutex_.lock();
  int ref = ++ref_;
  mutex_.unlock();
  return ref;
}

int Module::release() {
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

int Module::load(const BSL_CHAR* path) {
  if (NULL == path) return -1;

  handle_ = dlopen((char*)path, RTLD_LAZY);
  if (NULL == handle_) return -1;
  return 0;
}

int Module::getFuncAddress(const char* funcName, void** funcAddress) {
  if (NULL == funcName || NULL == funcAddress) return -1;

  dlerror();
  *funcAddress = dlsym(handle_, funcName);
  if (NULL != dlerror()) return -1;
  if (NULL == *funcAddress) return -1;
  return 0;
}

int Module::unload() {
  int ret = 0;
  if (NULL != handle_) {
    ret = dlclose(handle_);
    handle_ = NULL;
  }
  return ret;
}
