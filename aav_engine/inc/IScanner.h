#ifndef _ISCANNER_H_
#define _ISCANNER_H_

#include "IObject.h"
#include "TypeDefine.h"

class IStream;
class ITarget;

struct SCAN_OPTION;
struct SCAN_RESULT;

enum SCANNER_ID {
  SCANNER_ID_UNKNOWN = 0,
  SCANNER_ID_APK,
  SCANNER_ID_DEX,
  SCANNER_ID_ELF,
  SCANNER_ID_OAT,
};

class IScanner : public IObject {
 public:
  virtual int init(void* context) = 0;
  virtual int uninit() = 0;
  virtual int scanStream(IStream* stream, const SCAN_OPTION* option,
                         OUT SCAN_RESULT** result) = 0;
  virtual int scanTarget(ITarget* target, const SCAN_OPTION* option,
                         OUT SCAN_RESULT** result) = 0;
  virtual int getScannerID(SCANNER_ID* id) = 0;
};

#endif
