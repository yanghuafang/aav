#ifndef _ISIGMGR_H_
#define _ISIGMGR_H_

#include "BaseFormat.h"
#include "IObject.h"
#include "TypeDefine.h"

struct LOAD_FORMAT_CONFIG;
struct SIG_ITEM;
struct AD_INFO;

class ISigMgr : public IObject {
 public:
  virtual int init(void* context) = 0;
  virtual int uninit() = 0;
  virtual int loadBases(const BSL_CHAR* path,
                        const LOAD_FORMAT_CONFIG* config) = 0;
  virtual int unloadBases() = 0;
  virtual int updateBases(const BSL_CHAR* dir) = 0;
  virtual int baseVersion() = 0;
  virtual int getData(BASE_FORMAT format, SIG_ITEM** item) = 0;
  virtual int getMalwareName(int sigID, char* nameBuf, int nameBufSize) = 0;
  virtual int getADInfo(int sigID, void** adInfo) = 0;
};

#endif
