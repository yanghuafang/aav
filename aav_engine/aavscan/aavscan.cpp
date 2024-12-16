#include "aavscan.h"

#include "libapk_export.h"
#include "libdex_export.h"
#include "libfileid_export.h"
#include "libplatform_export.h"
#include "libsigmgr_export.h"
#include "libutil_export.h"
#include "unzipapk.h"

#ifdef ANALYSISASSISTDEXINFO
#include "AnalysisAssistDexInfo.h"
#endif

#include <assert.h>
#include <dirent.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>

#include <iostream>
#include <string>
#include <vector>

#include "FileSource.h"
#include "IFileCRC32.h"
#include "IFileID.h"
#include "IFileStream.h"
#include "IFileSystem.h"
#include "IFileTarget.h"
#include "IMemCRC32.h"
#include "IScanner.h"
#include "ISigMgr.h"
#include "LoadConfig.h"
#include "ScanOption.h"
#include "ScanResult.h"

using namespace std;

int fileCount__ = 0;

int GetNameFromPath(char* path, char** name) {
  if (NULL == path || 0 == path[0]) {
    *name = NULL;
    return -1;
  }

  int len = strlen(path);
  char* end = path + len - 1;
  if ('/' == *end) {
    *name = NULL;
    return -1;
  }

  while (end >= path) {
    if ('/' == *end) {
      *name = end + 1;
      break;
    }
    --end;
  }
  if (end < path) *name = path;
  return 0;
}

void PrintADInfo(const void* adInfo) {
  if (NULL == adInfo) return;
  const char* cur = (const char*)adInfo;

  uint32_t sigID = *(uint32_t*)cur;
  cur += 4;

  uint8_t adTypeCount = *(uint8_t*)cur++;
  vector<uint8_t> adTypes;
  adTypes.reserve(adTypeCount);
  for (int i = 0; i < adTypeCount; i++) {
    adTypes.push_back(*(uint8_t*)cur++);
  }
  assert(adTypes.size() == adTypeCount);

  uint8_t adActionCount = *(uint8_t*)cur++;
  vector<uint8_t> adActions;
  adActions.reserve(adActionCount);
  for (int i = 0; i < adActionCount; i++) {
    adActions.push_back(*(uint8_t*)cur++);
  }
  assert(adActions.size() == adActionCount);

  uint8_t riskLevel = *(uint8_t*)cur++;
  string adID = cur;
  cur += adID.size() + 1;
  string adEnName = cur;
  cur += adEnName.size() + 1;
  string adZhName = cur;
  cur += adZhName.size() + 1;

  cout << "Ad info: " << endl;
  cout << "    sigID: " << (unsigned int)sigID << endl;
  cout << "    adTypeCount: " << (int)adTypeCount << endl;
  cout << "    adTypes: ";
  for (int i = 0; i < adTypeCount; i++) {
    cout << (int)adTypes[i] << " ";
  }
  cout << endl;
  cout << "    adActionCount: " << (int)adActionCount << endl;
  cout << "    adActions: ";
  for (int i = 0; i < adActionCount; i++) {
    cout << (int)adActions[i] << " ";
  }
  cout << endl;
  cout << "    riskLevel: " << (int)riskLevel << endl;
  cout << "    adID: " << adID.c_str() << endl;
  cout << "    adEnName: " << adEnName.c_str() << endl;
  cout << "    adZhName: " << adZhName.c_str() << endl;
}

void PrintScanResult(ISigMgr* sigMgr, SCAN_RESULT* scanResult) {
  if (NULL == sigMgr || NULL == scanResult) return;

  cout << "scan result: " << endl;
  cout << "    isWhite: " << (int)scanResult->isWhite << endl;
  cout << "    isMalware: " << (int)scanResult->isMalware << endl;
  cout << "    scannerID: " << (int)scanResult->scannerID << endl;
  cout << "    fileType: " << (int)scanResult->fileType << endl;
  cout << "    sigCount: " << (int)scanResult->sigCount << endl;
  for (int i = 0; i < scanResult->sigCount; i++) {
    char nameBuf[64];
    if (0 != sigMgr->getMalwareName(scanResult->sigID[i], nameBuf,
                                    sizeof(nameBuf))) {
      cout << "failed to get malware name for sig ID "
           << (unsigned int)scanResult->sigID[i] << endl;
      continue;
    }
    cout << "sigID: " << (unsigned int)scanResult->sigID[i]
         << " malwareName: " << nameBuf << endl;
    if (0 == strncmp(nameBuf, "Adware", strlen("Adware"))) {
      void* adInfo = NULL;
      if (0 != sigMgr->getADInfo(scanResult->sigID[i], &adInfo)) {
        cout << "failed to get Ad info for sig ID "
             << (unsigned int)scanResult->sigID[i] << endl;
        continue;
      }
      PrintADInfo(adInfo);
    }
  }
}

#ifdef ANALYSISASSISTDEXINFO
void PrintAnalysisAssistDexInfo() {
  cout << "analysisassist result:" << endl;
  AnalysisAssistDexInfo* analysisAssist = NULL;
  if (0 != getAnalysisAssistDexInfo(&analysisAssist)) {
    cout << "failed to get analysis assist dex info!" << endl;
    return;
  }
  for (list<AnalysisAssistClassInfo>::iterator i =
           analysisAssist->classInfoList.begin();
       i != analysisAssist->classInfoList.end(); ++i) {
    cout << "classPath: " << i->classPath << endl;
    cout << "known: " << i->known << endl;
    for (list<AnalysisAssistMethodInfo>::iterator j = i->methodInfoList.begin();
         j != i->methodInfoList.end(); ++j) {
      cout << "    methodName: " << j->methodName << endl;
      cout << "    protoName: " << j->protoName << endl;
      cout << "    known: " << j->known << endl;
      cout << "    fastOpcodes: [0x" << hex << (int)j->fastOpcodes.opcode01
           << " 0x" << (int)j->fastOpcodes.opcode23 << " 0x"
           << (int)j->fastOpcodes.opcode45 << " 0x"
           << (int)j->fastOpcodes.opcode67 << " 0x"
           << (int)j->fastOpcodes.opcode89 << "]" << dec << endl;
      for (list<OpcodeInfo>::iterator k = j->opcodeBuf.begin();
           k != j->opcodeBuf.end(); ++k) {
        cout << "        0x" << hex << (int)k->opcode << dec;
        cout << "    " << k->instruction << endl;
      }
      cout << "    opcodeCRC32: 0x" << hex << j->opcodeCRC32 << dec << endl;
      for (list<string>::iterator k = j->stringBuf.begin();
           k != j->stringBuf.end(); ++k) {
        cout << "        " << *k << endl;
      }
      cout << "    stringCRC32: 0x" << hex << j->stringCRC32 << dec << endl;
    }
  }
}
#endif

int ScanFile(AAV_ENGINE_CONTEXT* context, const char* filePath) {
  if (NULL == context || NULL == filePath) return -1;

  if (NULL == context->scanOption) {
    cout << "scanOption is NULL." << endl;
    return -1;
  }
  if (NULL == context->fileID) {
    cout << "fileID is NULL." << endl;
    return -1;
  }
  if (NULL == context->sigMgr) {
    cout << "sigMgr is NULL." << endl;
    return -1;
  }
  if (NULL == context->apkScanner) {
    cout << "apkScanner is NULL." << endl;
    return -1;
  }
  if (NULL == context->dexScanner) {
    cout << "dexScanner is NULL." << endl;
    return -1;
  }
  fileCount__++;

  IObject* fileStreamObject = NULL;
  IObject* innerFileStreamObject = NULL;
  IObject* fileTargetObject = NULL;
  IObject* crc32 = NULL;
  IScanner* dexScanner = NULL;

  bool extracted = false;
  char extractedPath[260];

  int ret = -1;
  do {
    char* name = NULL;
    GetNameFromPath((char*)filePath, &name);
    FileSource source;
    source.mode = 0;
    source.name = (BSL_CHAR*)name;
    source.path = (BSL_CHAR*)filePath;

    if (0 !=
        libplatform_createInstance(PLATFORM_ID_FILESTREAM, &fileStreamObject)) {
      cout << "failed to create file stream." << endl;
      break;
    }
    IFileStream* fileStream = (IFileStream*)fileStreamObject;
    if (0 != fileStream->init(&source)) {
      cout << "failed to init file stream" << endl;
      break;
    }

    FILE_TYPE fileType = FILE_TYPE_UNKNOWN;
    if (0 != context->fileID->getFileType(fileStream, &fileType)) {
      cout << "unknown file type" << endl;
      break;
    }

    SCAN_RESULT* scanResult = NULL;
    if (FILE_TYPE_ZIP == fileType) {
      if (0 != context->apkScanner->scanStream(fileStream, context->scanOption,
                                               &scanResult)) {
        cout << "failed to scan apk." << endl;
        break;
      }
      if (NULL != scanResult && scanResult->isWhite) {
        PrintScanResult(context->sigMgr, scanResult);
        free(scanResult);
        scanResult = NULL;

        ret = 0;
        break;
      }
      free(scanResult);
      scanResult = NULL;

      snprintf(extractedPath, sizeof(extractedPath), "%s/classes.dex",
               filePath);
      cout << "inner object: " << extractedPath << endl;

#ifdef MULTITHREAD_SCAN
      if (0 != libutil_createInstance(UTIL_ID_MEMCRC32, &crc32)) {
        cout << "failed to create mem crc32." << endl;
        break;
      }
      if (0 !=
          ((IMemCRC32*)crc32)->init(extractedPath, strlen(extractedPath))) {
        cout << "failed to init mem crc32." << endl;
        break;
      }
      uint32_t crc = 0;
      if (0 != ((IMemCRC32*)crc32)->getCRC32(&crc)) {
        cout << "failed to getCRC32." << endl;
        break;
      }

      memset(extractedPath, 0, sizeof(extractedPath));
      snprintf(extractedPath, sizeof(extractedPath), "%x_%x_classes.dex",
               (uint32_t)time(NULL), crc);
#else
      memset(extractedPath, 0, sizeof(extractedPath));
      strncpy(extractedPath, "classes.dex", sizeof(extractedPath) - 1);
#endif

      if (0 != unzip_file(filePath, "classes.dex", extractedPath)) {
        cout << "failed to unzip " << filePath << " as APK file" << endl;
        break;
      }
      extracted = true;

      source.mode = 0;
      source.name = (BSL_CHAR*)"classes.dex";
      source.path = (BSL_CHAR*)extractedPath;

      if (0 != libplatform_createInstance(PLATFORM_ID_FILESTREAM,
                                          &innerFileStreamObject)) {
        cout << "failed to create inner file stream." << endl;
        break;
      }
      IFileStream* innerFileStream = (IFileStream*)innerFileStreamObject;

      if (0 != innerFileStream->init(&source)) {
        cout << "failed to init inner file stream" << endl;
        break;
      }

      FILE_TYPE fileType = FILE_TYPE_UNKNOWN;
      if (0 != context->fileID->getFileType(innerFileStream, &fileType)) {
        cout << "unknown file type" << endl;
        break;
      }
      if (FILE_TYPE_DEX != fileType) {
        cout << "inner file classes.dex is not a dex file." << endl;
        break;
      }
    } else if (FILE_TYPE_DEX == fileType) {
      ;
    } else {
      cout << "unknown file type" << endl;
      break;
    }

    if (0 !=
        libplatform_createInstance(PLATFORM_ID_FILETARGET, &fileTargetObject)) {
      cout << "failed to create file target." << endl;
      break;
    }
    IFileTarget* fileTarget = (IFileTarget*)fileTargetObject;
    if (0 != fileTarget->init(&source)) {
      cout << "failed to init file target" << endl;
      break;
    }

    if (0 != context->dexScanner->scanTarget(fileTarget, context->scanOption,
                                             &scanResult)) {
      cout << "failed to scan dex." << endl;
      break;
    }

    PrintScanResult(context->sigMgr, scanResult);
    free(scanResult);
    scanResult = NULL;

#ifdef ANALYSISASSISTDEXINFO
    PrintAnalysisAssistDexInfo();
#endif
    ret = 0;
  } while (false);

  if (NULL != crc32) {
    crc32->release();
    crc32 = NULL;
  }
  if (NULL != innerFileStreamObject) {
    innerFileStreamObject->release();
    innerFileStreamObject = NULL;
  }
  if (NULL != fileTargetObject) {
    fileTargetObject->release();
    fileTargetObject = NULL;
  }
  if (NULL != fileStreamObject) {
    fileStreamObject->release();
    fileStreamObject = NULL;
  }

#ifndef DEX_DEBUG
  if (extracted) {
    IObject* fileSystemObject = NULL;
    if (0 ==
        libplatform_createInstance(PLATFORM_ID_FILESYSTEM, &fileSystemObject)) {
      IFileSystem* fileSystem = (IFileSystem*)fileSystemObject;
      if (0 == fileSystem->removeFile((const BSL_CHAR*)extractedPath)) {
#ifdef DEBUG_BUILD
        cout << "succeed to remove file " << extractedPath << endl;
#endif
      }
      fileSystem = NULL;
      fileSystemObject->release();
      fileSystemObject = NULL;
    }
  }
#endif

  return ret;
}

bool StartWith(const char* pre, const char* str) {
  return (0 == strncmp(pre, str, strlen(pre)));
}

bool EndWith(const char* pre, const char* str) {
  int preLen = strlen(pre);
  int strLen = strlen(str);

  if (preLen < strLen) return false;

  return (0 == strcmp(pre + (preLen - strLen), str));
}

bool IsDir(const char* path) {
  if (NULL == path) return false;

  struct stat st;
  lstat(path, &st);
  if (S_ISDIR(st.st_mode))
    return true;
  else
    return false;
}

#if 0
int ScanDir(ISigMgr* sigMgr, const char* dirPath)
{
    if (NULL == sigMgr || NULL == dirPath)
        return -1;

    DIR* dir = opendir(dirPath);
    if (NULL == dir)
        return -1;

    struct dirent* ent = NULL;
    while (NULL != (ent = readdir(dir))) {
        char childPath[260];
        if (ent->d_type & DT_REG) {
            if (EndWith(ent->d_name,"apk")) {
                memset(childPath, 0, sizeof(childPath));
                snprintf(childPath, sizeof(childPath), "%s/%s", dirPath, ent->d_name);
                ScanFile(sigMgr, childPath);
            }
        } else if (ent->d_type & DT_DIR) {
            if (0 == strcmp(ent->d_name, ".") || 0 == strcmp(ent->d_name, ".."))
                continue;
            memset(childPath, 0, sizeof(childPath));
            sprintf(childPath, "%s/%s", dirPath, ent->d_name);
            ScanDir(sigMgr, childPath);
        }
    }

    closedir(dir);
    dir = NULL;
    return 0;
}
#endif

int ScanDir(AAV_ENGINE_CONTEXT* context, const char* dirPath) {
  if (NULL == context || NULL == dirPath) return -1;

  DIR* dir = opendir(dirPath);
  if (NULL == dir) return -1;

  struct dirent* ent = NULL;
  while (NULL != (ent = readdir(dir))) {
    char childPath[260];
    if (0 == strcmp(ent->d_name, ".") || 0 == strcmp(ent->d_name, ".."))
      continue;

    if (EndWith(ent->d_name, ".apk") || EndWith(ent->d_name, ".dex")) {
      memset(childPath, 0, sizeof(childPath));
      snprintf(childPath, sizeof(childPath), "%s/%s", dirPath, ent->d_name);
      cout << "file: " << childPath << endl;
      ScanFile(context, childPath);
    } else {
      memset(childPath, 0, sizeof(childPath));
      sprintf(childPath, "%s/%s", dirPath, ent->d_name);
      ScanDir(context, childPath);
    }
  }

  closedir(dir);
  dir = NULL;
  return 0;
}

#ifdef CALC_FILE_CRC
#if 1
int ScanFileCrc(const char* filePath) {
  if (NULL == filePath) return -1;
  fileCount__++;

  IObject* fileTargetObject = NULL;
  IObject* crc32 = NULL;

  int ret = -1;
  do {
    char* name = NULL;
    GetNameFromPath((char*)filePath, &name);
    FileSource source;
    source.mode = 0;
    source.name = (BSL_CHAR*)name;
    source.path = (BSL_CHAR*)filePath;
    cout << "file: " << name << endl;

    if (0 !=
        libplatform_createInstance(PLATFORM_ID_FILETARGET, &fileTargetObject)) {
      cout << "failed to create file target." << endl;
      break;
    }
    IFileTarget* fileTarget = (IFileTarget*)fileTargetObject;
    if (0 != fileTarget->init(&source)) {
      cout << "failed to init file target." << endl;
      break;
    }

    void* buf = NULL;
    int64_t size = 0;
    if (0 != fileTarget->getBuf(&buf)) {
      cout << "failed to getBuf." << endl;
      break;
    }
    if (0 != fileTarget->getSize(&size)) {
      cout << "failed to getSize." << endl;
      break;
    }

    if (0 != libutil_createInstance(UTIL_ID_MEMCRC32, &crc32)) {
      cout << "failed to create mem crc32." << endl;
      break;
    }
#if 0
        if (size > 512) {
            if (0 != ((IMemCRC32*)crc32)->init(buf, 512)) {
                cout << "failed to init mem crc32." << endl;
                break;
            }            
            uint32_t crc = 0;
            if (0 != ((IMemCRC32*)crc32)->getCRC32(&crc)) {
                cout << "failed to getCRC32." << endl;
                break;
            }
            cout << "    512 crc32: 0x" << hex << crc << dec << endl;
        }
#endif
    {
      if (0 != ((IMemCRC32*)crc32)->init(buf, size)) {
        cout << "failed to init mem crc32." << endl;
        break;
      }
      uint32_t crc = 0;
      if (0 != ((IMemCRC32*)crc32)->getCRC32(&crc)) {
        cout << "failed to getCRC32." << endl;
        break;
      }
      cout << "    " << size << " crc32: 0x" << hex << crc << dec << endl;
    }
    ret = 0;
  } while (false);

  if (NULL != crc32) {
    crc32->release();
    crc32 = NULL;
  }
  if (NULL != fileTargetObject) {
    fileTargetObject->release();
    fileTargetObject = NULL;
  }
  return ret;
}
#else
int ScanFileCrc(const char* filePath) {
  if (NULL == filePath) return -1;
  fileCount__++;

  IObject* crc32 = NULL;

  int ret = -1;
  do {
    cout << "filePath: " << filePath << endl;

    if (0 != libutil_createInstance(UTIL_ID_FILECRC32, &crc32)) {
      cout << "failed to create file crc32." << endl;
      break;
    }
    if (0 != ((IFileCRC32*)crc32)->init((BSL_CHAR*)filePath)) {
      cout << "failed to init file crc32." << endl;
      break;
    }
    uint32_t crc = 0;
    if (0 != ((IFileCRC32*)crc32)->getCRC32(&crc)) {
      cout << "failed to getCRC32." << endl;
      break;
    }
    cout << "    " << "all" << " crc32: 0x" << hex << crc << dec << endl;
    ret = 0;
  } while (false);

  if (NULL != crc32) {
    crc32->release();
    crc32 = NULL;
  }
  return ret;
}
#endif

int ScanDirCrc(const char* dirPath) {
  if (NULL == dirPath) return -1;

  DIR* dir = opendir(dirPath);
  if (NULL == dir) return -1;

  struct dirent* ent = NULL;
  while (NULL != (ent = readdir(dir))) {
    char childPath[260];
    if (0 == strcmp(ent->d_name, ".") || 0 == strcmp(ent->d_name, ".."))
      continue;

    if (EndWith(ent->d_name, "dex")) {
      memset(childPath, 0, sizeof(childPath));
      snprintf(childPath, sizeof(childPath), "%s/%s", dirPath, ent->d_name);
      ScanFileCrc(childPath);
    } else {
      memset(childPath, 0, sizeof(childPath));
      sprintf(childPath, "%s/%s", dirPath, ent->d_name);
      ScanDirCrc(childPath);
    }
  }

  closedir(dir);
  dir = NULL;
  return 0;
}

int main(int argc, char** argv) {
  if (argc != 2) {
    cout << "usage: ./aavscan <dex file/dir path>" << endl;
    return 0;
  }
  char* filePath = argv[1];
  cout << "path: " << filePath << endl;

  time_t start = time(NULL);
  if (IsDir(filePath)) {
    ScanDirCrc(filePath);
  } else {
    ScanFileCrc(filePath);
  }
  time_t end = time(NULL);
  int duration = (int)(end - start);
  cout << "duration: " << duration << endl;
  cout << "fileCount: " << fileCount__ << endl;
  if (0 != fileCount__) {
    float speed = (float)duration / fileCount__;
    cout << "speed: " << speed << " seconds/file" << endl;
  }
  return 0;
}
#else
int main(int argc, char** argv) {
  if (argc != 3) {
    cout << "usage: ./aavscan <sig lib file path> <apk/dex file/dir path>"
         << endl;
    return 0;
  }
  char* basePath = argv[1];
  char* filePath = argv[2];
  cout << "basePath: " << basePath << endl;
  cout << "filePath: " << filePath << endl;

  IFileID* fileID = NULL;
  ISigMgr* sigMgr = NULL;
  IScanner* apkScanner = NULL;
  IScanner* dexScanner = NULL;
  int ret = -1;
  do {
    if (0 != libfileid_createInstance(&fileID)) {
      cout << "failed to create file ID." << endl;
      break;
    }

    if (0 != libsigmgr_createInstance(&sigMgr)) {
      cout << "failed to create sig mgr." << endl;
      break;
    }
    if (0 != sigMgr->init(NULL)) {
      cout << "failed to init sig mgr." << endl;
      break;
    }
    LOAD_FORMAT_CONFIG loadFormatConfig;
    loadFormatConfig.ad = true;
    loadFormatConfig.apk = true;
    loadFormatConfig.dex = true;
    loadFormatConfig.elf = false;
    loadFormatConfig.oat = false;
    loadFormatConfig.white = true;
    loadFormatConfig.heur = false;
    loadFormatConfig.analyzer = false;
    if (0 != sigMgr->loadBases((BSL_CHAR*)basePath, &loadFormatConfig)) {
      cout << "sig mgr failed to load base." << endl;
      break;
    }

    if (0 != libapk_createInstance(&apkScanner)) {
      cout << "failed to create apk scanner." << endl;
      break;
    }
    if (0 != apkScanner->init(sigMgr)) {
      cout << "failed to init apk scanner." << endl;
      break;
    }

    if (0 != libdex_createInstance(&dexScanner)) {
      cout << "failed to create dex scanner." << endl;
      break;
    }
    if (0 != dexScanner->init(sigMgr)) {
      cout << "failed to init dex scanner." << endl;
      break;
    }

    SCAN_OPTION scanOption;
    scanOption.config.unarch = true;
    scanOption.config.unpack = false;
    scanOption.config.apk = true;
    scanOption.config.dex = true;
    scanOption.config.elf = false;
    scanOption.config.oat = false;

    AAV_ENGINE_CONTEXT engineContext;
    engineContext.scanOption = &scanOption;
    engineContext.fileID = fileID;
    engineContext.sigMgr = sigMgr;
    engineContext.apkScanner = apkScanner;
    engineContext.dexScanner = dexScanner;

    time_t start = time(NULL);
    if (IsDir(filePath)) {
      ScanDir(&engineContext, filePath);
    } else {
      ScanFile(&engineContext, filePath);
    }
    time_t end = time(NULL);
    int duration = (int)(end - start);
    cout << "duration: " << duration << endl;
    cout << "fileCount: " << fileCount__ << endl;
    if (0 != fileCount__) {
      float speed = (float)duration / fileCount__;
      cout << "speed: " << speed << " seconds/file" << endl;
    }

    ret = 0;
  } while (false);

  if (NULL != dexScanner) {
    dexScanner->release();
    dexScanner = NULL;
  }
  if (NULL != apkScanner) {
    apkScanner->release();
    apkScanner = NULL;
  }
  if (NULL != sigMgr) {
    sigMgr->release();
    sigMgr = NULL;
  }
  if (NULL != fileID) {
    fileID->release();
    fileID = NULL;
  }
  return 0;
}
#endif
