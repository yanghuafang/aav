#ifndef _FILE_UNCOMPRESS_H
#define _FILE_UNCOMPRESS_H

#include <string.h>

#include <iostream>

#include "CommonDefine.h"

int uncompress_file(std::string compressFileName, std::string& uncompressData);
bool gzipInflate(const std::string& compressedBytes,
                 std::string& uncompressedBytes);
ulong crc32_buffer(Byte* ptr, int buf_len);

#endif
