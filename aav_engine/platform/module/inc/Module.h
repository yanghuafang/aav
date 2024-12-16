#ifndef _MODULE_H_
#define _MODULE_H_

#include <mutex>

#include "IModule.h"
using namespace std;

class Module : public IModule {
 public:
  Module();

  int retain();
  int release();

  int load(const BSL_CHAR* path);
  int getFuncAddress(const char* funcName, void** funcAddress);
  int unload();

 private:
  ~Module();

 private:
  int ref_;
  recursive_mutex mutex_;
  void* handle_;
};

#endif
