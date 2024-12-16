/*
 * signature load - called by framework to load signature database
 */

#include "SigMgr.h"

#include <fcntl.h>
#include <getopt.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#include <zlib.h>

#include <vector>

#include "BaseFormat.h"
#include "BaseStructure.h"
#include "BlowFish.h"
#include "CommonDefine.h"
#include "FileUncompress.h"
#include "MalwareName.h"

#define VERSION "0.1"
#define ALIGN_SIZE4(s) (((s) + 3) & ~3)

#define return_error(msg, ret) \
  do {                         \
    perror(msg);               \
    return (ret);              \
  } while (0)

#define debug_info(msg)  \
  do {                   \
    printf("%x\n", msg); \
  } while (0)
#define debug_str(msg)   \
  do {                   \
    printf("%s\n", msg); \
  } while (0)

SigMgr::SigMgr() { init(NULL); }

SigMgr::~SigMgr() { uninit(); }

int SigMgr::init(void* context) {
  ref_ = 1;
  mFileBufferPtr = NULL;
  mBaseFilePath = NULL;
  mFileBufferLen = 0;
  bzero(&mBaseHeader, sizeof(BASE_HEADER));

  return AD_SUCCESS;
}

int SigMgr::uninit() {
  unloadBases();
  bzero(&mBaseHeader, sizeof(BASE_HEADER));
  if (mBaseFilePath != NULL) {
    free(mBaseFilePath);
    mBaseFilePath = NULL;
  }

  return AD_SUCCESS;
}

/* Reads a file into memory. */
int SigMgr::loadBinaryFile(const std::string& filename, std::string& contents) {
  // Open the gzip file in binary mode
  FILE* f = fopen(filename.c_str(), "rb");
  if (f == NULL) return AD_ERROR;

  // Clear existing bytes in output vector
  contents.clear();

  // Read all the bytes in the file
  int c = fgetc(f);
  while (c != EOF) {
    contents += (char)c;
    c = fgetc(f);
  }
  fclose(f);
  return AD_SUCCESS;
}

int SigMgr::loadBases(const BSL_CHAR* path, const LOAD_FORMAT_CONFIG* config) {
  return checkAndLoadBases(path, config, false);
}

int SigMgr::checkAndLoadBases(const BSL_CHAR* path,
                              const LOAD_FORMAT_CONFIG* config, bool bUpdated) {
  int offset = 0;
  int baseHeaderLen = sizeof(BASE_HEADER);
  int baseSectionHeaderLen = sizeof(BASE_SECTION_HEADER);
  BASE_HEADER tmpBaseHeader;
  bzero(&tmpBaseHeader, baseHeaderLen);

  // load file
  std::string fileData;
  std::string filname((char*)path);
  if (loadBinaryFile(filname, fileData) == AD_ERROR) {
    return_error("loadBinaryFile", AD_BASE_LOAD);
  }

  // blowfish decrypt
  char key[] = "bai#du#se!c#@!@#239urity ";
  Blowfish blowfish;
  std::string decrypted;
  blowfish.SetKey(key);
  blowfish.Decrypt(&decrypted, fileData);
  if (decrypted.length() == 0) {
    return_error("Blowfish", AD_BASE_ENCRYPT);
  }

  // uncompress
  std::string uncompressData;
  if (gzipInflate(decrypted, uncompressData) == false) {
    return_error("uncompress", AD_BASE_UNCOMPRESS);
  }

  mFileBufferLen = uncompressData.length();
  if (mFileBufferLen <= baseHeaderLen) {
    return_error("uncompress", AD_BASE_UNCOMPRESS);
  }
  mFileBufferPtr = (unsigned char*)malloc(mFileBufferLen);
  memset(mFileBufferPtr, '\0', mFileBufferLen);
  memcpy(mFileBufferPtr, uncompressData.c_str(), mFileBufferLen);

#ifdef DEBUG
  char decryptFileName[FILE_NAME_LEN];
  bzero(decryptFileName, FILE_NAME_LEN);
  snprintf(decryptFileName, FILE_NAME_LEN - 1, "%s.decrypted", path);
  FILE* pFile = fopen(decryptFileName, "wb");
  fwrite(mFileBufferPtr, mFileBufferLen, 1, pFile);
  fclose(pFile);
#endif

  // get base file header
  memcpy(&tmpBaseHeader, mFileBufferPtr, baseHeaderLen);
  debug_info(tmpBaseHeader.magic);

  offset = baseHeaderLen;
  ulong crc =
      crc32_buffer((Byte*)(mFileBufferPtr + offset), mFileBufferLen - offset);
  if (tmpBaseHeader.crc != crc) {
    return_error("crc", AD_BASE_CRC);
  }

  if (bUpdated && tmpBaseHeader.version <= mBaseHeader.version) {
    return_error("version", AD_BASE_LOW_VERSION);
  }

  // get base section
  while (offset < mFileBufferLen) {
    SIG_ITEM* pSigItem = NULL;
    BASE_SECTION* pBaseSection = NULL;
    BASE_SECTION_HEADER* pBaseSectionHeader = NULL;

    pSigItem = (SIG_ITEM*)malloc(sizeof(SIG_ITEM));
    memset(pSigItem, '\0', sizeof(SIG_ITEM));

    // read section header
    pBaseSectionHeader = (BASE_SECTION_HEADER*)(mFileBufferPtr + offset);
    pSigItem->format = pBaseSectionHeader->format;
    pSigItem->bufSize = pBaseSectionHeader->packedSize;
    pSigItem->sigCount = pBaseSectionHeader->sigCount;
    debug_info(pSigItem->format);
    debug_info(pSigItem->bufSize);

    // read section data
    offset += baseSectionHeaderLen;
    pSigItem->buf = (void*)(mFileBufferPtr + offset);
    mSectionVector.push_back(pSigItem);

    deal_with_section(pSigItem);
    offset += pSigItem->bufSize;
  }

  int path_len = strlen((const char*)path);
  mBaseFilePath = (unsigned char*)malloc(path_len + 1);
  memset(mBaseFilePath, '\0', path_len + 1);
  strncpy((char*)mBaseFilePath, (char*)path, path_len);
  memcpy(&mBaseHeader, &tmpBaseHeader, baseHeaderLen);
  return AD_SUCCESS;
}

int SigMgr::unloadBases() {
  for (std::vector<SIG_ITEM*>::iterator it = mSectionVector.begin();
       it != mSectionVector.end(); ++it) {
    free(*it);
  }

  // clear all vector
  mMalwareTypeVector.clear();
  mMalwareTypeVector.clear();
  mPlatformVector.clear();
  mFileFormatVector.clear();
  mVariantVector.clear();
  mFamilyNameVector.clear();
  mFamilyIDeVector.clear();
  mADInfoVector.clear();
  mSectionVector.clear();

  // free the file buffer
  free(mFileBufferPtr);
  mFileBufferPtr = NULL;

  return 0;
}

int SigMgr::updateBases(const BSL_CHAR* dir) {
  int ret;

  unloadBases();
  ret = checkAndLoadBases(mBaseFilePath, NULL, false);
  if (ret != AD_SUCCESS) {
    unloadBases();
    checkAndLoadBases(mBaseFilePath, NULL, false);
  }

  return ret;
}

int SigMgr::baseVersion() { return mBaseHeader.version; }

int SigMgr::getData(BASE_FORMAT format, SIG_ITEM** item) {
  for (std::vector<SIG_ITEM*>::iterator it = mSectionVector.begin();
       it != mSectionVector.end(); ++it) {
    if ((*it)->format == format) {
      *item = *it;
      return AD_SUCCESS;
    }
  }

  return AD_ERROR;
}

int SigMgr::getADInfo(int sig_id, void** adInfo) {
  *adInfo = NULL;
  for (std::vector<AD_INFO_NODE>::iterator it = mADInfoVector.begin();
       it != mADInfoVector.end(); ++it) {
    if ((it)->sig_id == sig_id) {
      *adInfo = (it)->pADInfo;
      return AD_SUCCESS;
    }
  }

  return AD_ERROR;
}

int SigMgr::getMalwareName(int sigID, char* nameBuf, int nameBufSize) {
  int index = 0;
  int nameID = -1;

  SIG_ITEM* pSigItem = NULL;
  SIG_NAME* pSigName = NULL;

  MALWARE_NAME* pMalwareName = NULL;

  // get malware name id
  getData(BASE_FORMAT_SIG, &pSigItem);
  while (index < pSigItem->bufSize) {
    pSigName = (SIG_NAME*)((char*)(pSigItem->buf) + index);
    if (pSigName->sig_id == sigID) {
      nameID = pSigName->name_id;
      break;
    }
    index += sizeof(SIG_NAME);
  }

  if (nameID < 0) return AD_SUCCESS;

  // get malware info
  index = 0;
  pMalwareName = NULL;
  getData(BASE_FORMAT_NAME, &pSigItem);
  while (index < pSigItem->bufSize) {
    pMalwareName = (MALWARE_NAME*)((char*)pSigItem->buf + index);
    if (pMalwareName->id == nameID) {
      // get malware family name
      int i = 0;
      std::string strFamily;
      while (i < mFamilyIDeVector.size()) {
        if (mFamilyIDeVector[i] == pMalwareName->family) {
          break;
        }
        ++i;
      }
      // conmalware name
      memset(nameBuf, '\0', nameBufSize);
      snprintf(nameBuf, nameBufSize, "%s!%s.%s@%s.%s",
               mMalwareTypeVector[pMalwareName->type].c_str(),
               mFamilyNameVector[i].c_str(),
               mVariantVector[pMalwareName->variant].c_str(),
               mPlatformVector[pMalwareName->platform].c_str(),
               mFileFormatVector[pMalwareName->file_format].c_str());
      return AD_SUCCESS;
    }
    index += sizeof(MALWARE_NAME);
  }

  return AD_ERROR;
}

int SigMgr::deal_with_section(SIG_ITEM* pSigItem) {
  int format = pSigItem->format;

  switch (format) {
    case BASE_FORMAT_TYPE:
      build_data(pSigItem, mMalwareTypeVector);
      break;
    case BASE_FORMAT_FAMILY:
      build_data_family(pSigItem);
      break;
    case BASE_FORMAT_AD_INFO:
      build_data_adinfo(pSigItem);
      break;
    case BASE_FORMAT_FILE_FORMAT:
      build_data(pSigItem, mFileFormatVector);
      break;
    case BASE_FORMAT_PLATFORM:
      build_data(pSigItem, mPlatformVector);
      break;
    case BASE_FORMAT_VARIANT:
      build_data(pSigItem, mVariantVector);
      break;
    default:
      break;
  }

  return AD_SUCCESS;
}

int SigMgr::build_data_adinfo(SIG_ITEM* pSigItem) {
  int index = 0;
  int count = 0;
  char* p = NULL;

  while (index < pSigItem->bufSize) {
    AD_INFO_NODE adInfoNode;
    memset(&adInfoNode, '\0', sizeof(AD_INFO_NODE));
    adInfoNode.pADInfo = (char*)pSigItem->buf + index;
    adInfoNode.sig_id = *((uint32_t*)((uint8_t*)pSigItem->buf + index));
    //*((uint8_t*)pSigItem->buf+index);

    // compulate the length of AD INFO node
    index += sizeof(uint32_t);  // sig id
    count = *((uint8_t*)((char*)pSigItem->buf + index));
    index += sizeof(uint8_t);          // ad type count
    index += count * sizeof(uint8_t);  // ad type array
    count = *((uint8_t*)((char*)pSigItem->buf + index));
    index += sizeof(uint8_t);          // ad action count
    index += count * sizeof(uint8_t);  // ad action array
    index += sizeof(uint8_t);          // riks level
    p = (char*)pSigItem->buf + index;
    index += strlen(p) + 1;  // ad id
    p = (char*)pSigItem->buf + index;
    index += strlen(p) + 1;  // ad en name
    p = (char*)pSigItem->buf + index;
    index += strlen(p) + 1;  // ad zh name

    index = ALIGN_SIZE4(index);

    mADInfoVector.push_back(adInfoNode);
  }

  return AD_SUCCESS;
}

int SigMgr::build_data_family(SIG_ITEM* pSigItem) {
  int index = 0;
  MALWARE_FAMILY* pFamily = NULL;

  while (index < pSigItem->bufSize) {
    pFamily = (MALWARE_FAMILY*)((char*)(pSigItem->buf) + index);
    mFamilyIDeVector.push_back(pFamily->id);
    index += sizeof(pFamily->id);
    std::string str((char*)pSigItem->buf + index);
    mFamilyNameVector.push_back(str);
    index += str.length();
    index += 1;  // add '\0' character
    index = ALIGN_SIZE4(index);
  }

  return AD_SUCCESS;
}

int SigMgr::build_data(SIG_ITEM* pSigItem, std::vector<std::string>& data) {
  int index = 0;
  while (index < pSigItem->bufSize) {
    std::string str((char*)pSigItem->buf + index);
    data.push_back(str);
    debug_str(str.c_str());
    index += str.length();
    index += 1;  // add '\0' character
  }

  return AD_SUCCESS;
}

int SigMgr::retain() {
  mutex_.lock();
  int ref = ++ref_;
  mutex_.unlock();
  return ref;
}

int SigMgr::release() {
  int ref = 0;
  bool kill = false;

  mutex_.lock();
  if (ref_ > 0) {
    ref = --ref_;
    if (0 == ref) kill = true;
  }
  mutex_.unlock();

  if (kill) delete this;
  return ref;
}
