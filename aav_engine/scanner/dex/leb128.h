#ifndef _LEB128_H_
#define _LEB128_H_

#include <stdint.h>

#include "TypeDefine.h"

int read_sleb128(IN const uint8_t* buf, OUT int32_t* value, OUT int* bytesRead);
int read_uleb128(IN const uint8_t* buf, OUT uint32_t* value,
                 OUT int* bytesRead);
int read_uleb128p1(IN const uint8_t* buf, OUT uint32_t* value,
                   OUT int* bytesRead);

#endif
