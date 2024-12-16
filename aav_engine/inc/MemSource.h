#ifndef _MEMSOURCE_H_
#define _MEMSOURCE_H_

#include <stdint.h>

#include "TypeDefine.h"

struct MemSource {
  int32_t mode;  // mode 0: O_RDONLY 1: O_WRONLY 2: O_RDWR
  BSL_CHAR* name;
  void* buf;
  int32_t bufSize;
};

#endif
