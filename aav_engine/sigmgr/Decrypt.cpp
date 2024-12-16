#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <iostream>
#include <string>

#include "BlowFish.h"
#include "CommonDefine.h"

int main(int argc, const char* argv[]) {
  char key[] = "bai#du#se!c#@!@#239urity ";

  Blowfish blowfish;
  blowfish.SetKey(key);

  std::string decrypted;

  FILE* pFile = NULL;

  if (argc < 2) {
    printf("usage: ./decrypt file");
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
  std::string decryptedText(mFileBufferPtr, mFileBufferLen);
  blowfish.Decrypt(&decrypted, decryptedText);

  free(mFileBufferPtr);
  mFileBufferPtr = NULL;

  char decryptFileName[FILE_NAME_LEN];
  bzero(decryptFileName, FILE_NAME_LEN);
  snprintf(decryptFileName, FILE_NAME_LEN - 1, "%s.decrypted", argv[1]);
  pFile = fopen(decryptFileName, "wb");
  fwrite(decrypted.c_str(), decrypted.length(), 1, pFile);
  fclose(pFile);

  return 0;
}
