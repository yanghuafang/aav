#include "libutil_export.h"

#include <stdio.h>

#include <new>

#include "FileCRC32.h"
#include "MemCRC32.h"
using namespace std;

int libutil_createInstance(IN UTIL_ID id, OUT IObject** object) {
  if (NULL == object) return -1;

  int ret = 0;
  switch (id) {
    case UTIL_ID_FILECRC32: {
      *object = new (nothrow) FileCRC32;
      if (NULL == *object) ret = -1;
      break;
    }
    case UTIL_ID_MEMCRC32: {
      *object = new (nothrow) MemCRC32;
      if (NULL == *object) ret = -1;
      break;
    }
    default:
      ret = -1;
      break;
  }
  return ret;
}
