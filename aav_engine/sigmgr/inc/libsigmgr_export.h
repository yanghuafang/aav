#ifndef _LIBSIGMGR_EXPORT_H_
#define _LIBSIGMGR_EXPORT_H_

#include "BaseFormat.h"
#include "MalwareName.h"

class ISigMgr;

int libsigmgr_createInstance(ISigMgr** sigmgr);

#endif