#include "aavjni.h"

#include <android/log.h>
#include <assert.h>
#include <jni.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include <fstream>
#include <new>
#include <string>
#include <vector>

#include "FileSource.h"
#include "IFileCRC32.h"
#include "IFileID.h"
#include "IFileStream.h"
#include "IFileSystem.h"
#include "IFileTarget.h"
#include "IMemCRC32.h"
#include "IModule.h"
#include "IScanner.h"
#include "ISigMgr.h"
#include "LoadConfig.h"
#include "ScanOption.h"
#include "ScanResult.h"
#include "jniUtil.h"
#include "libapk_export.h"
#include "libdex_export.h"
#include "libfileid_export.h"
#include "libplatform_export.h"
#include "libsigmgr_export.h"
#include "libutil_export.h"
#include "unzipapk.h"

using namespace std;

int (*libfileid_createInstance__)(IFileID** fileID) = NULL;
int (*libsigmgr_createInstance__)(ISigMgr** sigmgr) = NULL;
int (*libapk_createInstance__)(IScanner** scanner) = NULL;
int (*libdex_createInstance__)(IScanner** scanner) = NULL;

IFileID* fileID__ = NULL;
ISigMgr* sigMgr__ = NULL;
IScanner* apkScanner__ = NULL;
IScanner* dexScanner__ = NULL;

LANGUAGE_ID lang__ = LANGUAGE_ID_ENGLISH;
string tmpPath__;

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

jobject CreateScanResult(JNIEnv* env, jint isWhite, jint isMalware,
                         jint scannerID, jint fileType, jint sigCount,
                         jintArray& sigIDs) {
  jclass cls_scanResult = LoadClassByClassName(env, AAV_SCANRESULT_CLS);
  if (NULL == cls_scanResult) {
    __android_log_print(ANDROID_LOG_ERROR, "aavjni", "failed to load class %s.",
                        AAV_SCANRESULT_CLS);
    return NULL;
  }
  cls_scanResult = (jclass)env->NewLocalRef(cls_scanResult);

  const char* params = "(IIIII[I)V";
  jmethodID cls_scanResult_constructor =
      FindMethodFromClass(env, cls_scanResult, "<init>", params);
  if (NULL == cls_scanResult_constructor) {
    __android_log_print(ANDROID_LOG_ERROR, "aavjni",
                        "failed to find method %s::<init>.",
                        AAV_SCANRESULT_CLS);
    return NULL;
  }

  return env->NewObject(cls_scanResult, cls_scanResult_constructor, isWhite,
                        isMalware, scannerID, fileType, sigCount, sigIDs);
}

jobject CreateAdInfo(JNIEnv* env, jint sigID, jint adTypeCount,
                     jintArray adTypes, jint adActionCount,
                     jintArray& adActions, jint riskLevel, jstring& adID,
                     jstring& adName) {
  jclass cls_adInfo = LoadClassByClassName(env, AAV_ADINFO_CLS);
  if (NULL == cls_adInfo) {
    __android_log_print(ANDROID_LOG_ERROR, "aavjni", "failed to load class %s.",
                        AAV_ADINFO_CLS);
    return NULL;
  }
  cls_adInfo = (jclass)env->NewLocalRef(cls_adInfo);

  const char* params = "(II[II[IILjava/lang/String;Ljava/lang/String;)V";
  jmethodID cls_adInfo_constructor =
      FindMethodFromClass(env, cls_adInfo, "<init>", params);
  if (NULL == cls_adInfo_constructor) {
    __android_log_print(ANDROID_LOG_ERROR, "aavjni",
                        "failed to find method %s::<init>.", AAV_ADINFO_CLS);
    return NULL;
  }

  return env->NewObject(cls_adInfo, cls_adInfo_constructor, sigID, adTypeCount,
                        adTypes, adActionCount, adActions, riskLevel, adID,
                        adName);
}

jint uninit(JNIEnv* env, jobject thiz) {
  if (NULL != sigMgr__) {
    sigMgr__->release();
    sigMgr__ = NULL;
  }

  if (NULL != fileID__) {
    fileID__->release();
    fileID__ = NULL;
  }

  lang__ = LANGUAGE_ID_ENGLISH;
  tmpPath__.clear();
  return 0;
}

jint init(JNIEnv* env, jobject thiz, jobject context, jstring tmpPath) {
  const char* path = env->GetStringUTFChars(tmpPath, NULL);
  int ret = -1;
  do {
    try {
      tmpPath__ = path;
      if (tmpPath__.empty()) {
        __android_log_print(ANDROID_LOG_ERROR, "aavjni", "invalid tmpPath.");
        break;
      }
      if ('/' != tmpPath__.back()) tmpPath__.append("/");
    } catch (bad_alloc& e) {
      __android_log_print(ANDROID_LOG_ERROR, "aavjni",
                          "failed to set tmpPath__: %s", e.what());
      break;
    }

    if (0 != libfileid_createInstance__(&fileID__)) {
      __android_log_print(ANDROID_LOG_ERROR, "aavjni",
                          "failed to create fileID instance.");
      break;
    }

    if (0 != libsigmgr_createInstance__(&sigMgr__)) {
      __android_log_print(ANDROID_LOG_ERROR, "aavjni",
                          "failed to create SigMgr instance.");
      break;
    }
    if (0 != sigMgr__->init(NULL)) {
      __android_log_print(ANDROID_LOG_ERROR, "aavjni",
                          "failed to init SigMgr.");
      break;
    }
    ret = 0;
  } while (false);
  env->ReleaseStringUTFChars(tmpPath, path);
  path = NULL;

  if (0 != ret) uninit(env, thiz);
  return ret;
}

jobject scan(JNIEnv* env, jobject thiz, jstring filePath) {
  if (NULL == fileID__) {
    __android_log_print(ANDROID_LOG_ERROR, "aavjni", "fileID__ is NULL!");
    return NULL;
  }
  if (NULL == apkScanner__) {
    __android_log_print(ANDROID_LOG_ERROR, "aavjni", "apkScanner__ is NULL!");
    return NULL;
  }
  if (NULL == dexScanner__) {
    __android_log_print(ANDROID_LOG_ERROR, "aavjni", "dexScanner__ is NULL!");
    return NULL;
  }

  IObject* fileStreamObject = NULL;
  IObject* innerFileStreamObject = NULL;
  IObject* fileTargetObject = NULL;
  IObject* crc32 = NULL;
  SCAN_RESULT* scanResult = NULL;
  jobject jscanResult = NULL;
  const char* path = env->GetStringUTFChars(filePath, NULL);

  SCAN_OPTION scanOption;
  scanOption.config.unarch = true;
  scanOption.config.unpack = false;
  scanOption.config.apk = true;
  scanOption.config.dex = true;
  scanOption.config.elf = false;
  scanOption.config.oat = false;

  bool extracted = false;
  char extractedPath[260];
  string dexFilePath;

  int ret = -1;
  do {
    char* name = NULL;
    GetNameFromPath((char*)path, &name);
    FileSource source;
    source.mode = 0;
    source.name = (BSL_CHAR*)name;
    source.path = (BSL_CHAR*)path;
#ifdef DEBUG_BUILD
    __android_log_print(ANDROID_LOG_INFO, "aaveng", "source file path: %s",
                        (char*)source.path);
#endif

    if (0 !=
        libplatform_createInstance(PLATFORM_ID_FILESTREAM, &fileStreamObject)) {
      __android_log_print(ANDROID_LOG_ERROR, "aavjni",
                          "failed to create file stream.");
      break;
    }
    IFileStream* fileStream = (IFileStream*)fileStreamObject;
    if (0 != fileStream->init(&source)) {
      __android_log_print(ANDROID_LOG_ERROR, "aavjni",
                          "failed to init file stream.");
      break;
    }

    FILE_TYPE fileType = FILE_TYPE_UNKNOWN;
    if (0 != fileID__->getFileType(fileStream, &fileType)) {
#ifdef DEBUG_BUILD
      __android_log_print(ANDROID_LOG_INFO, "aavjni", "unknown file type.");
#endif
      break;
    }

    if (FILE_TYPE_ZIP == fileType) {
      if (0 != apkScanner__->scanStream(fileStream, &scanOption, &scanResult)) {
        __android_log_print(ANDROID_LOG_INFO, "aavjni", "failed to scan apk.");
        break;
      }
      if (NULL != scanResult && scanResult->isWhite) {
        ret = 0;
        break;
      }

      snprintf(extractedPath, sizeof(extractedPath), "%s/classes.dex", path);
#ifdef DEBUG_BUILD
      __android_log_print(ANDROID_LOG_INFO, "aavjni", "inner object: %s",
                          extractedPath);
#endif

#ifdef MULTITHREAD_SCAN
      if (0 != libutil_createInstance(UTIL_ID_MEMCRC32, &crc32)) {
        __android_log_print(ANDROID_LOG_ERROR, "aavjni",
                            "failed to create mem crc32.");
        break;
      }
      if (0 !=
          ((IMemCRC32*)crc32)->init(extractedPath, strlen(extractedPath))) {
        __android_log_print(ANDROID_LOG_ERROR, "aavjni",
                            "failed to init mem crc32.");
        break;
      }
      uint32_t crc = 0;
      if (0 != ((IMemCRC32*)crc32)->getCRC32(&crc)) {
        __android_log_print(ANDROID_LOG_ERROR, "aavjni", "failed to getCRC32.");
        break;
      }

      memset(extractedPath, 0, sizeof(extractedPath));
      snprintf(extractedPath, sizeof(extractedPath), "%x_%x_classes.dex",
               (uint32_t)time(NULL), crc);
#else
      memset(extractedPath, 0, sizeof(extractedPath));
      strncpy(extractedPath, "classes.dex", sizeof(extractedPath) - 1);
#endif

      try {
        dexFilePath = tmpPath__;
        dexFilePath.append(extractedPath);
      } catch (bad_alloc& e) {
        __android_log_print(ANDROID_LOG_ERROR, "aavjni",
                            "in scan, bad_alloc caught: %s", e.what());
        break;
      }

      if (0 != unzip_file(path, "classes.dex", dexFilePath.c_str())) {
        __android_log_print(ANDROID_LOG_ERROR, "aavjni",
                            "failed to unzip %s as APK file.", path);
        break;
      }
      extracted = true;

      source.mode = 0;
      source.name = (BSL_CHAR*)"classes.dex";
      source.path = (BSL_CHAR*)dexFilePath.c_str();
#ifdef DEBUG_BUILD
      __android_log_print(ANDROID_LOG_INFO, "aaveng", "source dex path: %s",
                          (char*)source.path);
#endif
      if (0 != libplatform_createInstance(PLATFORM_ID_FILESTREAM,
                                          &innerFileStreamObject)) {
        __android_log_print(ANDROID_LOG_ERROR, "aavjni",
                            "failed to create inner file stream.");
        break;
      }
      IFileStream* innerFileStream = (IFileStream*)innerFileStreamObject;
      if (0 != innerFileStream->init(&source)) {
        __android_log_print(ANDROID_LOG_ERROR, "aavjni",
                            "failed to init inner file stream.");
        break;
      }

      FILE_TYPE fileType = FILE_TYPE_UNKNOWN;
      if (0 != fileID__->getFileType(innerFileStream, &fileType)) {
#ifdef DEBUG_BUILD
        __android_log_print(ANDROID_LOG_INFO, "aavjni",
                            "unknown inner stream file type.");
#endif
        break;
      }
      if (FILE_TYPE_DEX != fileType) {
#ifdef DEBUG_BUILD
        __android_log_print(ANDROID_LOG_INFO, "aavjni",
                            "inner file classes.dex is not a dex file.");
#endif
        break;
      }
    } else if (FILE_TYPE_DEX == fileType) {
#ifdef DEBUG_BUILD
      __android_log_print(ANDROID_LOG_INFO, "aavjni", "dex file type.");
#endif
    } else {
#ifdef DEBUG_BUILD
      __android_log_print(ANDROID_LOG_INFO, "aavjni",
                          "unknown inner file type.");
#endif
      break;
    }

#ifdef DEBUG_BUILD
    __android_log_print(ANDROID_LOG_INFO, "aaveng", "source path: %s",
                        (char*)source.path);
#endif
    if (0 !=
        libplatform_createInstance(PLATFORM_ID_FILETARGET, &fileTargetObject)) {
      __android_log_print(ANDROID_LOG_ERROR, "aavjni",
                          "failed to create file target.");
      break;
    }
    IFileTarget* fileTarget = (IFileTarget*)fileTargetObject;
    if (0 != fileTarget->init(&source)) {
      __android_log_print(ANDROID_LOG_ERROR, "aavjni",
                          "failed to init file target.");
      break;
    }

    if (0 != dexScanner__->scanTarget(fileTarget, &scanOption, &scanResult)) {
      __android_log_print(ANDROID_LOG_ERROR, "aavjni",
                          "failed to scan target.");
      break;
    }
    ret = 0;
  } while (false);

  if (0 == ret) {
    jintArray jsigIDs =
        IntArrayToJintArray(env, (int*)scanResult->sigID, scanResult->sigCount);
    jscanResult = CreateScanResult(
        env, scanResult->isWhite, scanResult->isMalware, scanResult->scannerID,
        scanResult->fileType, scanResult->sigCount, jsigIDs);
    if (NULL == jscanResult) {
      __android_log_print(ANDROID_LOG_ERROR, "aavjni",
                          "failed to construct scan result.");
      ret = -1;
    }
  }

  free(scanResult);
  scanResult = NULL;

  env->ReleaseStringUTFChars(filePath, path);
  path = NULL;

  if (NULL != crc32) {
    crc32->release();
    crc32 = NULL;
  }
  if (NULL != fileTargetObject) {
    fileTargetObject->release();
    fileTargetObject = NULL;
  }
  if (NULL != innerFileStreamObject) {
    innerFileStreamObject->release();
    innerFileStreamObject = NULL;
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
      if (0 == fileSystem->removeFile((const BSL_CHAR*)dexFilePath.c_str())) {
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

  if (0 != ret) return NULL;
  return jscanResult;
}

jstring getMalwareName(JNIEnv* env, jobject thiz, jint sigID) {
  if (NULL == sigMgr__) {
    __android_log_print(ANDROID_LOG_ERROR, "aavjni", "sigMgr__ is NULL!");
    return NULL;
  }

  char nameBuf[64];
  if (0 != sigMgr__->getMalwareName(sigID, nameBuf, sizeof(nameBuf))) {
    __android_log_print(ANDROID_LOG_ERROR, "aavjni",
                        "failed to get malware name for sig ID: %d.", sigID);
    return NULL;
  }
  return StrToJstring(env, nameBuf);
}

jobject getAdInfo(JNIEnv* env, jobject thiz, jint sigID) {
  if (NULL == sigMgr__) {
    __android_log_print(ANDROID_LOG_ERROR, "aavjni", "sigMgr__ is NULL!");
    return NULL;
  }

  void* adInfo = NULL;
  if (0 != sigMgr__->getADInfo(sigID, &adInfo)) {
    __android_log_print(ANDROID_LOG_ERROR, "aavjni",
                        "failed to get Ad info for sig ID: %d.", sigID);
    return NULL;
  }

  const char* cur = (const char*)adInfo;
  assert(sigID == *(uint32_t*)cur);
  cur += 4;

  uint8_t adTypeCount = *(uint8_t*)cur++;
  vector<int> adTypes;
  adTypes.reserve(adTypeCount);
  for (int i = 0; i < adTypeCount; i++) {
    adTypes.push_back(*(uint8_t*)cur++);
  }
  assert(adTypes.size() == adTypeCount);

  uint8_t adActionCount = *(uint8_t*)cur++;
  vector<int> adActions;
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

  jintArray jadTypes = IntArrayToJintArray(env, adTypes.data(), adTypeCount);
  jintArray jadActions =
      IntArrayToJintArray(env, adActions.data(), adActionCount);
  jstring jadID = StrToJstring(env, adID.c_str());
  jstring jadName = NULL;
  switch (lang__) {
    case LANGUAGE_ID_ENGLISH:
      jadName = StrToJstring(env, adEnName.c_str());
      break;
    case LANGUAGE_ID_SIMPLIFY_CHINESE:
      jadName = StrToJstring(env, adZhName.c_str());
      break;
    default:
      jadName = StrToJstring(env, adEnName.c_str());
      break;
  }
  return CreateAdInfo(env, sigID, adTypeCount, jadTypes, adActionCount,
                      jadActions, riskLevel, jadID, jadName);
}

jint loadSigLib(JNIEnv* env, jobject thiz, jstring sigLibPath) {
  if (NULL == sigMgr__) {
    __android_log_print(ANDROID_LOG_ERROR, "aavjni", "sigMgr__ is NULL!");
    return -1;
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

  int ret = -1;
  const char* path = env->GetStringUTFChars(sigLibPath, NULL);
  do {
    if (0 != sigMgr__->loadBases((BSL_CHAR*)path, &loadFormatConfig)) {
      __android_log_print(ANDROID_LOG_ERROR, "aavjni",
                          "failed to load sig lib.");
      break;
    }

    if (0 != libapk_createInstance__(&apkScanner__)) {
      __android_log_print(ANDROID_LOG_ERROR, "aavjni",
                          "failed to create apk scanner.");
      break;
    }
    if (0 != apkScanner__->init(sigMgr__)) {
      __android_log_print(ANDROID_LOG_ERROR, "aavjni",
                          "failed to init apk scanner.");
      break;
    }

    if (0 != libdex_createInstance__(&dexScanner__)) {
      __android_log_print(ANDROID_LOG_ERROR, "aavjni",
                          "failed to create dex scanner.");
      break;
    }
    if (0 != dexScanner__->init(sigMgr__)) {
      __android_log_print(ANDROID_LOG_ERROR, "aavjni",
                          "failed to init dex scanner.");
      break;
    }
    ret = 0;
  } while (false);
  env->ReleaseStringUTFChars(sigLibPath, path);
  return ret;
}

jint unloadSigLib(JNIEnv* env, jobject thiz) {
  if (NULL != dexScanner__) {
    dexScanner__->release();
    dexScanner__ = NULL;
  }
  if (NULL != apkScanner__) {
    apkScanner__->release();
    apkScanner__ = NULL;
  }

  if (NULL == sigMgr__) {
    __android_log_print(ANDROID_LOG_ERROR, "aavjni",
                        "sig lib is already unloaded!");
    return -1;
  }
  return sigMgr__->unloadBases();
}

jint sigLibVersion(JNIEnv* env, jobject thiz) {
  if (NULL == sigMgr__) {
    __android_log_print(ANDROID_LOG_ERROR, "aavjni", "sigMgr__ is NULL!");
    return -1;
  }

  return sigMgr__->baseVersion();
}

jint engineVersion(JNIEnv* env, jobject thiz) { return 2; }

jint setLang(JNIEnv* env, jobject thiz, jint lang) {
  if (lang < LANGUAGE_ID_ENGLISH || lang >= LANGUAGE_ID_END) return -1;
  lang__ = (LANGUAGE_ID)lang;
  return 0;
}

static JNINativeMethod NativeMethods__[] = {
    {"init", "(Landroid/content/Context;Ljava/lang/String;)I", (void*)init},
    {"uninit", "()I", (void*)uninit},
    {"scan", "(Ljava/lang/String;)Lcom/av/aav/ScanResult;", (void*)scan},
    {"getMalwareName", "(I)Ljava/lang/String;", (void*)getMalwareName},
    {"getAdInfo", "(I)Lcom/av/aav/AdInfo;", (void*)getAdInfo},
    {"loadSigLib", "(Ljava/lang/String;)I", (void*)loadSigLib},
    {"unloadSigLib", "()I", (void*)unloadSigLib},
    {"sigLibVersion", "()I", (void*)sigLibVersion},
    {"engineVersion", "()I", (void*)engineVersion},
    {"setLang", "(I)I", (void*)setLang},
};

int GetModulePath(const char* jniName, string& modulePath) {
  int pid = (int)getpid();
  char pidPath[32] = {0};
  snprintf(pidPath, sizeof(pidPath), "/proc/%d/maps", pid);
  ifstream fin(pidPath);
  if (!fin) {
    __android_log_print(ANDROID_LOG_ERROR, "aavjni", "failed to open file %s",
                        pidPath);
    return -1;
  }

  int ret = -1;
  char buf[512];
  while (!fin.eof()) {
    fin.getline(buf, sizeof(buf));
    if (strlen(buf) <= 2) continue;
    const char* libaavjni = strstr(buf, jniName);
    if (NULL == libaavjni) continue;
    const char* end = libaavjni - 1;
    if (end <= buf || '/' != *end) continue;
    const char* begin = end;
    while (begin > buf) {
      char c = *begin;
      if (' ' == c || '\t' == c) {
        ++begin;
        break;
      }
      --begin;
    }
    if (begin <= buf || '/' != *begin) continue;
    char libPath[512] = {0};
    strncpy(libPath, begin, end - begin + 1);
    try {
      modulePath = libPath;
      //__android_log_print(ANDROID_LOG_INFO, "aavjni", "line: %s", buf);
    } catch (bad_alloc& e) {
      __android_log_print(ANDROID_LOG_ERROR, "aavjni",
                          "in GetModulePath, bad_alloc caught: %s", e.what());
    }
    ret = 0;
    break;
  }

  fin.close();
  return ret;
}

int LoadEngine(const char* engineName) {
  IObject* object = NULL;
  IModule* module = NULL;
  int ret = -1;
  do {
    if (0 != libplatform_createInstance(PLATFORM_ID_MODULE, &object)) {
      __android_log_print(ANDROID_LOG_ERROR, "aavjni",
                          "failed to create module instance.");
      break;
    }
    module = (IModule*)object;

    string modulePath;
    if (0 != GetModulePath("libaavjni.so", modulePath)) {
      __android_log_print(ANDROID_LOG_ERROR, "aavjni",
                          "failed to find module path.");
      break;
    }
    string enginePath;
    try {
      enginePath = modulePath + engineName;
    } catch (bad_alloc& e) {
      __android_log_print(ANDROID_LOG_ERROR, "aavjni",
                          "in LoadEngine, bad_alloc caught: %s", e.what());
    }
    if (0 != module->load((const BSL_CHAR*)enginePath.c_str())) {
      __android_log_print(ANDROID_LOG_ERROR, "aavjni",
                          "failed to load libaaveng.so.");
      break;
    }
    if (0 != module->getFuncAddress("libfileid_createInstance__",
                                    (void**)&libfileid_createInstance__)) {
      __android_log_print(ANDROID_LOG_ERROR, "aavjni",
                          "failed to get libfileid_createInstance__.");
      break;
    }
    if (0 != module->getFuncAddress("libsigmgr_createInstance__",
                                    (void**)&libsigmgr_createInstance__)) {
      __android_log_print(ANDROID_LOG_ERROR, "aavjni",
                          "failed to get libsigmgr_createInstance__.");
      break;
    }
    if (0 != module->getFuncAddress("libapk_createInstance__",
                                    (void**)&libapk_createInstance__)) {
      __android_log_print(ANDROID_LOG_ERROR, "aavjni",
                          "failed to get libapk_createInstance__.");
      break;
    }
    if (0 != module->getFuncAddress("libdex_createInstance__",
                                    (void**)&libdex_createInstance__)) {
      __android_log_print(ANDROID_LOG_ERROR, "aavjni",
                          "failed to get libdex_createInstance__.");
      break;
    }
    ret = 0;
  } while (false);

  if (0 != ret) {
    if (NULL != module) {
      module->unload();
      module = NULL;
    }
    if (NULL != object) {
      object->release();
      object = NULL;
    }
  }
  return ret;
}

static int RegisterNativeMethods(JNIEnv* env, const char* className,
                                 JNINativeMethod* nativeMethods,
                                 int numMethods) {
  __android_log_print(ANDROID_LOG_INFO, "aavjni",
                      "enter RegisterNativeMethods.");
  jclass clazz;
  clazz = env->FindClass(className);
  if (clazz == NULL) {
    __android_log_print(ANDROID_LOG_ERROR, "aavjni", "failed to find class %s.",
                        className);
    return JNI_FALSE;
  }
  if (env->RegisterNatives(clazz, nativeMethods, numMethods) < 0) {
    __android_log_print(ANDROID_LOG_ERROR, "aavjni",
                        "failed to register class: %s method: %s.", className,
                        nativeMethods->name);
    return JNI_FALSE;
  }
  __android_log_print(ANDROID_LOG_INFO, "aavjni",
                      "complete RegisterNativeMethods successfully.");
  return JNI_TRUE;
}

JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM* vm, void* reserved) {
  JNIEnv* env = NULL;
  jint result = -1;

  __android_log_print(ANDROID_LOG_INFO, "aavjni", "enter JNI_OnLoad.");
  if (vm->GetEnv((void**)&env, JNI_VERSION_1_4) != JNI_OK) {
    __android_log_print(ANDROID_LOG_ERROR, "aavjni", "JNI version is not 1.4.");
    return -1;
  }
  assert(env != NULL);

  if (0 != LoadEngine("libaaveng.so")) {
    __android_log_print(ANDROID_LOG_ERROR, "aavjni", "failed to load engine.");
    return -1;
  }

  if (JNI_TRUE != RegisterNativeMethods(
                      env, AAV_ENGINE_CLS, NativeMethods__,
                      sizeof(NativeMethods__) / sizeof(NativeMethods__[0]))) {
    __android_log_print(ANDROID_LOG_ERROR, "aavjni",
                        "failed to registerNatives.");
    return -1;
  }

  result = JNI_VERSION_1_4;
  __android_log_print(ANDROID_LOG_INFO, "aavjni",
                      "JNI_OnLoad complete successfully.");
  return result;
}
