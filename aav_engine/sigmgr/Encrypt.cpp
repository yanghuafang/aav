#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <iostream>
#include <string>

#include "BlowFish.h"

#define FILE_NAME_LEN 256

int main(int argc, const char* argv[]) {
  char key[] = "bai#du#se!c#@!@#239urity ";

  Blowfish blowfish;
  blowfish.SetKey(key);

  std::string encrypted, decrypted;

  FILE* pFile = NULL;

  if (argc < 2) {
    printf("usage: ./encrypt file");
    return 0;
  }

  pFile = fopen(argv[1], "rb");
  struct stat sb;
  int fd = fileno(pFile);
  fstat(fd, &sb);

  int mFileBufferLen = sb.st_size;
  char* mFileBufferPtr = (char*)malloc(mFileBufferLen);

  memset(mFileBufferPtr, '\0', mFileBufferLen);
  if (fread(mFileBufferPtr, 1, mFileBufferLen, pFile) < mFileBufferLen) {
    fclose(pFile);
    return 1;
  }
  fclose(pFile);

  std::string plaintext(mFileBufferPtr, mFileBufferLen);
  blowfish.Encrypt(&encrypted, plaintext);
  free(mFileBufferPtr);
  mFileBufferPtr = NULL;

  char encryptFileName[FILE_NAME_LEN];
  bzero(encryptFileName, FILE_NAME_LEN);
  snprintf(encryptFileName, FILE_NAME_LEN - 1, "%s.encrypted", argv[1]);
  pFile = fopen(encryptFileName, "wb");
  fwrite(encrypted.c_str(), encrypted.length(), 1, pFile);
  fclose(pFile);

  return 0;
}
