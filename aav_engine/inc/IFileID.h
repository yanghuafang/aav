#ifndef _IFILEID_H_
#define _IFILEID_H_

#include "IObject.h"

class IStream;
class ITarget;

enum FILE_TYPE {
  FILE_TYPE_UNKNOWN = 0,

  // Android Dex
  FILE_TYPE_DEX = 10,
  FILE_TYPE_ODEX,

  // Linux format
  FILE_TYPE_ELF = 20,
  FILE_TYPE_ELF64,

  // Android OAT
  FILE_TYPE_OAT = 30,

  // Apple format
  FILE_TYPE_MACHO = 40,
  FILE_TYPE_MACHO64,

  // Microsoft format
  FILE_TYPE_PE = 50,
  FILE_TYPE_PE64,

  // archive format
  FILE_TYPE_ZIP = 100,
};

enum PACK_TYPE {
  PACK_TYPE_UNKNOWN = 0,
};

class IFileID : public IObject {
 public:
  virtual int init(void* context) = 0;
  virtual int uninit() = 0;
  virtual int getFileType(IStream* stream, FILE_TYPE* fileType) = 0;
  virtual int getFileType(ITarget* target, FILE_TYPE* fileType) = 0;
  virtual int getPackType(IStream* stream, PACK_TYPE* packType) = 0;
  virtual int getPackType(ITarget* target, PACK_TYPE* packType) = 0;
};

#endif
