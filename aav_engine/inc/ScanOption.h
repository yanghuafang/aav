#ifndef _SCANOPTION_H_
#define _SCANOPTION_H_

#include <stdint.h>

#include "LoadConfig.h"

#pragma pack(push, 1)

struct SCAN_OPTION {
  LOAD_MODULE_CONFIG config;
  uint32_t maxFileSize;
  uint32_t maxUnarchLayer;
  uint8_t maxUnpackLayer;
  uint8_t heurLevel;
  uint8_t reserve[2];
};

#pragma pack(pop)

#endif
