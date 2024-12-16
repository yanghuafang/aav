#ifndef _CRC32_H_
#define _CRC32_H_

#include <stdint.h>

uint32_t crc32(uint32_t crc, const void* buf, uint32_t size);

#endif
