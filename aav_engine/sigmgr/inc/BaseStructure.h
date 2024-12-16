#ifndef _BASESTRUCTURE_H_
#define _BASESTRUCTURE_H_

#include <stdint.h>

#pragma pack(push, 1)

typedef struct BASE_HEADER {
  uint32_t magic;
  uint32_t version;
  uint32_t timestamp;
  uint32_t crc;
} BASE_HEADER;

typedef struct BASE_SECTION_HEADER {
  uint32_t format;
  uint32_t sigCount;
  uint32_t packedSize;
  uint32_t unpackedSize;
} BASE_SECTION_HEADER;

typedef struct BASE_SECTION {
  BASE_SECTION_HEADER header;
  uint8_t data[1];
} BASE_SECTION;

typedef struct BASE_FILE {
  BASE_HEADER header;
  BASE_SECTION sections[1];
} BASE_FILE;

#pragma pack(pop)

#endif
