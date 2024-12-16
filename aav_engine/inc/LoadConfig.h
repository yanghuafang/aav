#ifndef _LOADCONFIG_H_
#define _LOADCONFIG_H_

#include <stdint.h>

#pragma pack(push, 1)

struct LOAD_MODULE_CONFIG {
  uint8_t unarch;
  uint8_t unpack;
  uint8_t apk;
  uint8_t dex;
  uint8_t elf;
  uint8_t oat;
  uint8_t reserve[2];  // padding
};

struct LOAD_FORMAT_CONFIG {
  uint8_t ad;
  uint8_t apk;
  uint8_t dex;
  uint8_t elf;
  uint8_t oat;
  uint8_t white;
  uint8_t heur;
  uint8_t analyzer;
};

#pragma pack(pop)

#endif
