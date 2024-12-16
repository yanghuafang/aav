#ifndef _SCANRESULT_H_
#define _SCANRESULT_H_

#include <stdint.h>

#pragma pack(push, 1)

struct SCAN_RESULT {
  uint8_t isWhite;
  uint8_t isMalware;
  uint16_t scannerID;
  uint16_t fileType;
  uint16_t sigCount;
  uint32_t sigID[1];
};

#pragma pack(pop)

#endif
