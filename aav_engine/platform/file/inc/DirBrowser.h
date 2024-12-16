#ifndef _DIRBROWSER_H_
#define _DIRBROWSER_H_

#include <dirent.h>

#include <mutex>

#include "IDirBrowser.h"
using namespace std;

class DirBrowser : public IDirBrowser {
 public:
  DirBrowser();

  int retain();
  int release();

  int open(const BSL_CHAR* path);
  int getItem(BSL_CHAR* pathBuf, int pathBufSize);
  bool isFile(const BSL_CHAR* path);
  bool isDir(const BSL_CHAR* path);
  int close();

 private:
  ~DirBrowser();

 private:
  int ref_;
  recursive_mutex mutex_;
  DIR* dir_;
};

#endif
