#include "aaveng.h"

#include "TypeDefine.h"

DYNAMIC_EXPORT int libfileid_createInstance__(IFileID** fileID) {
  return libfileid_createInstance(fileID);
}

DYNAMIC_EXPORT int libsigmgr_createInstance__(ISigMgr** sigMgr) {
  return libsigmgr_createInstance(sigMgr);
}

DYNAMIC_EXPORT int libapk_createInstance__(IScanner** scanner) {
  return libapk_createInstance(scanner);
}

DYNAMIC_EXPORT int libdex_createInstance__(IScanner** scanner) {
  return libdex_createInstance(scanner);
}
