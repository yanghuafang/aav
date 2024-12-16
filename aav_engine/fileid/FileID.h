#ifndef _FILEID_H_
#define _FILEID_H_

#include "IFileID.h"

// #include <atomic>
#include <mutex>
using namespace std;

class FileID : public IFileID {
 public:
  FileID();

  int retain();
  int release();

  int init(void* context);
  int uninit();
  int getFileType(IStream* stream, FILE_TYPE* fileType);
  int getFileType(ITarget* target, FILE_TYPE* fileType);
  int getPackType(IStream* stream, PACK_TYPE* packType);
  int getPackType(ITarget* target, PACK_TYPE* packType);

 private:
  ~FileID();

 private:
  int ref_;
  recursive_mutex mutex_;
};

#endif
