#include "libplatform_export.h"

#include <stdio.h>

#include <new>

#include "DirBrowser.h"
#include "FileMap.h"
#include "FileStream.h"
#include "FileSystem.h"
#include "FileTarget.h"
#include "MemStream.h"
#include "MemTarget.h"
#include "Module.h"
using namespace std;

int libplatform_createInstance(IN PLATFORM_ID id, OUT IObject** object) {
  if (NULL == object) return -1;

  int ret = 0;
  switch (id) {
    case PLATFORM_ID_FILESYSTEM: {
      *object = new (nothrow) FileSystem;
      if (NULL == *object) ret = -1;
      break;
    }
    case PLATFORM_ID_FILEMAP: {
      *object = new (nothrow) FileMap;
      if (NULL == *object) ret = -1;
      break;
    }
    case PLATFORM_ID_DIRBROWSER: {
      *object = new (nothrow) DirBrowser;
      if (NULL == *object) ret = -1;
      break;
    }
    case PLATFORM_ID_FILESTREAM: {
      *object = new (nothrow) FileStream;
      if (NULL == *object) ret = -1;
      break;
    }
    case PLATFORM_ID_FILETARGET: {
      *object = new (nothrow) FileTarget;
      if (NULL == *object) ret = -1;
      break;
    }
    case PLATFORM_ID_MEMSTREAM: {
      *object = new (nothrow) MemStream;
      if (NULL == *object) ret = -1;
      break;
    }
    case PLATFORM_ID_MEMTARGET: {
      *object = new (nothrow) MemTarget;
      if (NULL == *object) ret = -1;
      break;
    }
    case PLATFORM_ID_MODULE: {
      *object = new (nothrow) Module;
      if (NULL == *object) ret = -1;
      break;
    }
    default:
      ret = -1;
      break;
  }
  return ret;
}
