#ifndef _SIGMGR_H_
#define _SIGMGR_H_

#include <mutex>
#include <string>
#include <vector>

#include "BaseStructure.h"
#include "ISigMgr.h"

using namespace std;
typedef struct AD_INFO_NODE {
  uint32_t sig_id;
  void* pADInfo;
} AD_INFO_NODE;

class SigMgr : public ISigMgr {
 public:
  SigMgr();
  ~SigMgr();

  int retain();
  int release();
  int init(void* context);
  int uninit();
  int loadBases(const BSL_CHAR* path, const LOAD_FORMAT_CONFIG* config);
  int unloadBases();
  int updateBases(const BSL_CHAR* dir);
  int baseVersion();
  int getData(BASE_FORMAT format, SIG_ITEM** item);
  int getMalwareName(int sigID, char* nameBuf, int nameBufSize);
  // int getADInfo(int sig_id, AD_INFO** adInfo);
  int getADInfo(int sig_id, void** adInfo);

 private:
  int checkAndLoadBases(const BSL_CHAR* path, const LOAD_FORMAT_CONFIG* config,
                        bool bUpdate = false);
  int deal_with_section(SIG_ITEM* pSigItem);
  int loadBinaryFile(const std::string& filename, std::string& contents);
  int build_data(SIG_ITEM*, std::vector<std::string>& data);
  int build_data_family(SIG_ITEM* pSigItem);
  int build_data_adinfo(SIG_ITEM* pSigItem);

  int mFileBufferLen;
  unsigned char* mFileBufferPtr;
  unsigned char* mBaseFilePath;
  BASE_HEADER mBaseHeader;
  std::vector<int> mFamilyIDeVector;
  std::vector<std::string> mMalwareTypeVector;
  std::vector<std::string> mPlatformVector;
  std::vector<std::string> mFileFormatVector;
  std::vector<std::string> mVariantVector;
  std::vector<std::string> mFamilyNameVector;
  std::vector<AD_INFO_NODE> mADInfoVector;
  std::vector<SIG_ITEM*> mSectionVector;

  int ref_;
  recursive_mutex mutex_;
};

#endif
