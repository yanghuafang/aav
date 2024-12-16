#ifndef _AAVENG_H_
#define _AAVENG_H_

#include "libapk_export.h"
#include "libdex_export.h"
#include "libfileid_export.h"
#include "libsigmgr_export.h"

#ifdef __cplusplus
extern "C" {
#endif

int libfileid_createInstance__(IFileID** fileID);
int libsigmgr_createInstance__(ISigMgr** sigMgr);
int libapk_createInstance__(IScanner** scanner);
int libdex_createInstance__(IScanner** scanner);

#ifdef __cplusplus
}
#endif

#endif
