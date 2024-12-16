#include "libsigmgr_export.h"

#include <stdio.h>

#include <new>

#include "SigMgr.h"
using namespace std;
int libsigmgr_createInstance(ISigMgr** sigmgr) {
  if (NULL == sigmgr) return -1;

  int ret = 0;
  //*sigmgr = new (nothrow) SigMgr;
  *sigmgr = new SigMgr;
  if (NULL == *sigmgr) ret = -1;

  return ret;
}
