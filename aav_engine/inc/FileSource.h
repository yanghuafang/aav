#ifndef _FILESOURCE_H_
#define _FILESOURCE_H_

#include <stdint.h>

#include "TypeDefine.h"

struct FileSource {
  int32_t mode;  // mode 0: O_RDONLY 1: O_WRONLY 2: O_RDWR
  BSL_CHAR* name;
  BSL_CHAR* path;
};

#endif
