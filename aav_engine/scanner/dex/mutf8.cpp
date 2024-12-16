#include "mutf8.h"

#include "leb128.h"

int get_utf8_from_mutf8(IN const uint8_t* mutf8, OUT const uint8_t** utf8,
                        OUT int* bytesRead) {
  uint32_t size = 0;
  int read = 0;
  const uint8_t* p = mutf8;
  if (0 != read_uleb128(mutf8, &size, &read)) return -1;
  p += read;
  *bytesRead = read + size;
  *utf8 = p;
  // TODO: convert mutf8 string to utf8 string
  return 0;
}
