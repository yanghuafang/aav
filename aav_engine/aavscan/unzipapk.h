#ifndef _UNZIPAPK_H_
#define _UNZIPAPK_H_

int unzip_file(const char* zipFilePath, const char* innerFileName,
               const char* dstFilePath);

#endif
