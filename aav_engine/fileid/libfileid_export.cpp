#include "libfileid_export.h"

#include <stdio.h>

#include <new>

#include "FileID.h"
using namespace std;

int libfileid_createInstance(IFileID** fileID) {
  if (NULL == fileID) return -1;

  *fileID = new (nothrow) FileID;
  if (NULL == *fileID) return -1;

  return 0;
}
