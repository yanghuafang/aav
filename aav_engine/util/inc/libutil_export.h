#ifndef _LIBUTIL_EXPORT_H_
#define _LIBUTIL_EXPORT_H_

#include "TypeDefine.h"

enum UTIL_ID {
  UTIL_ID_UNKNOWN = 0,
  UTIL_ID_FILECRC32,
  UTIL_ID_MEMCRC32,
};

class IObject;

int libutil_createInstance(IN UTIL_ID id, OUT IObject** object);

#endif
