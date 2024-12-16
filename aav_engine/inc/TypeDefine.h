#ifndef _TYPEDEFINE_H_
#define _TYPEDEFINE_H_

#include <stdint.h>

#ifdef WIN32
#define BSL_CHAR uint16_t
#else
#define BSL_CHAR uint8_t
#endif

#define IN
#define OUT

#define DYNAMIC_EXPORT __attribute__((visibility("default")))

#endif