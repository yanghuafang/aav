#ifndef _MUTF8_H_
#define _MUTF8_H_

#include <stdint.h>

#include "TypeDefine.h"

int get_utf8_from_mutf8(IN const uint8_t* mutf8, OUT uint8_t** utf8,
                        OUT int* bytesRead);

#endif
