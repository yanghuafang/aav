#include "leb128.h"

#include <assert.h>

#include <iostream>
using namespace std;

int read_sleb128(const uint8_t* buf, int32_t* value, int* bytesRead) {
  int ret = 0;
  const uint8_t* p = buf;
  int32_t v = *(p++);
  if (v <= 0x7f)
    v = (v << 25) >> 25;  // expand the sign bit
  else {
    int cur = *(p++);
    v = (v & 0x7f) | ((cur & 0x7f) << 7);
    if (cur <= 0x7f)
      v = (v << 18) >> 18;
    else {
      cur = *(p++);
      v |= (cur & 0x7f) << 14;
      if (cur <= 0x7f)
        v = (v << 11) >> 11;
      else {
        cur = *(p++);
        v |= (cur & 0x7f) << 21;
        if (cur <= 0x7f)
          v |= (v << 4) >> 4;
        else {
          cur = *(p++);
          v |= (cur & 0x7f) << 28;
          if (cur <= 0x7f) ret = -1;
        }
      }
    }
  }
  *value = v;
  *bytesRead = p - buf;
  return ret;
}

int read_uleb128(const uint8_t* buf, uint32_t* value, int* bytesRead) {
  int ret = 0;
  const uint8_t* p = buf;
  uint32_t v = *(p++);
  if (v > 0x7f) {
    int cur = *(p++);
    v = (v & 0x7f) | ((cur & 0x7f) << 7);
    if (cur > 0x7f) {
      cur = *(p++);
      v |= (cur & 0x7f) << 14;
      if (cur > 0x7f) {
        cur = *(p++);
        v |= (cur & 0x7f) << 21;
        if (cur > 0x7f) {
          cur = *(p++);
          v |= (cur & 0x7f) << 28;
          if (cur > 0x7f) {
            ret = -1;
            // assert(false);
          }
        }
      }
    }
  }
  *value = v;
  *bytesRead = p - buf;
  // cout << "uleb128 value: 0x" << hex << *value << dec
  //     << " bytesRead: " << *bytesRead << endl;
  return ret;
}

int read_uleb128p1(const uint8_t* buf, uint32_t* value, int* bytesRead) {
  int ret = read_uleb128(buf, value, bytesRead);
  if (0 == ret) (*value)++;
  return ret;
}
