#include "DexPathSigMgr.h"

#include <assert.h>
#include <string.h>

#include "ACMatcher.h"
#include "BaseFormat.h"
#include "DexSig.h"
#include "IMemCRC32.h"
#include "ISigMgr.h"
#include "libutil_export.h"

#if defined(ANDROID_BUILD) && defined(DEBUG_BUILD)
#include <android/log.h>
#include <jni.h>

#endif

#include <iostream>
#include <new>

using namespace std;

DexPathSigMgr::DexPathSigMgr() {}

DexPathSigMgr::~DexPathSigMgr() { uninit(); }

int DexPathSigMgr::init(ISigMgr* sigMgr) {
  if (NULL == sigMgr) return -1;

  int ret = -1;
  SIG_ITEM* pathSig = NULL;
  do {
    if (0 != sigMgr->getData(BASE_FORMAT_DEX_PATH, &pathSig)) {
#if defined(ANDROID_BUILD) && defined(DEBUG_BUILD)
      __android_log_print(ANDROID_LOG_ERROR, "aaveng",
                          "sigMgr failed to getData BASE_FORMAT_DEX_PATH");
#endif
      break;
    }
    if (0 != parsePathSig(pathSig)) {
#if defined(ANDROID_BUILD) && defined(DEBUG_BUILD)
      __android_log_print(ANDROID_LOG_ERROR, "aaveng",
                          "failed to parsePathSig");
#endif
      break;
    }
    if (0 != createACTree()) {
#if defined(ANDROID_BUILD) && defined(DEBUG_BUILD)
      __android_log_print(ANDROID_LOG_ERROR, "aaveng",
                          "failed to createACTree");
#endif
      break;
    }
    ret = 0;
  } while (false);

  if (0 != ret) uninit();
  return ret;
}

int DexPathSigMgr::uninit() {
  delete acTree_;
  acTree_ = NULL;

  pathSigList_.clear();
  return 0;
}

int DexPathSigMgr::parsePathSig(const SIG_ITEM* pathSigItem) {
  assert(NULL != pathSigItem);
  assert(BASE_FORMAT_DEX_PATH == pathSigItem->format);
  assert(NULL != pathSigItem->buf);
  if (NULL == pathSigItem) return -1;
  if (NULL == pathSigItem->buf) return -1;

  int count = 0;
  char* cur = (char*)pathSigItem->buf;
  DEX_PATH_SIG* sig = (DEX_PATH_SIG*)cur;
  char* end = (char*)pathSigItem->buf + pathSigItem->bufSize;
  if (0 == pathSigItem->bufSize) {
    cout << "warning: path sig buf size is zero!" << endl;
    return 0;
  }

  try {
    while (true) {
      DexPathSig pathSig;

      pathSig.sigID = sig->sig_id;
      pathSig.strMatchType = (STR_MATCH_TYPE)sig->str_match_type;
      assert(pathSig.strMatchType > STR_MATCH_TYPE_UNKNOWN &&
             pathSig.strMatchType < STR_MATCH_TYPE_END_UNKNOWN);
      if (pathSig.strMatchType <= STR_MATCH_TYPE_UNKNOWN ||
          pathSig.strMatchType >= STR_MATCH_TYPE_END_UNKNOWN)
        return -1;

      pathSig.logicMatchType = (LOGIC_MATCH_TYPE)sig->logic_match_type;
      assert(pathSig.logicMatchType > LOGIC_MATCH_TYPE_UNKNOWN &&
             pathSig.logicMatchType < LOGIC_MATCH_TYPE_END_UNKNOWN);
      if (pathSig.logicMatchType <= LOGIC_MATCH_TYPE_UNKNOWN ||
          pathSig.logicMatchType >= LOGIC_MATCH_TYPE_END_UNKNOWN)
        return -1;

      assert(sig->path_max_layer > 0);
      pathSig.pathCrcs.reserve(sig->path_max_layer);
      for (int i = 0; i < sig->path_max_layer; i++) {
        pathSig.pathCrcs.push_back(sig->path_crcs[i]);
      }

      pathSigList_.push_back(pathSig);
      count++;

      cur +=
          (sizeof(DEX_PATH_SIG) + (sig->path_max_layer - 1) * sizeof(uint32_t));
      sig = (DEX_PATH_SIG*)cur;
      if (cur >= end) break;
    }
  } catch (bad_alloc& e) {
    cerr << "DexPathSigMgr::parsePathSig bad_alloc caught: " << e.what()
         << endl;
    return -1;
  }
  assert(count == pathSigItem->sigCount);

  return 0;
}

int DexPathSigMgr::createACTree() {
  acTree_ = new (nothrow) ACTree;
  if (NULL == acTree_) return -1;
  return acTree_->create(pathSigList_);
}

int DexPathSigMgr::searchClassPath(const char* classPath,
                                   DexPathSig** pathSig) {
  assert(NULL != classPath && NULL != pathSig);
  if (NULL == classPath || NULL == pathSig) return -1;

  list<int> dotIndexes;
  int i = 0;
  int len = 0;
  try {
    while (classPath[i] != 0) {
      if ('.' == classPath[i]) dotIndexes.push_back(i);
      len++;
      i++;
    }
  } catch (bad_alloc& e) {
    cout << "DexPathSigMgr::searchClassPath bad_alloc caught: " << e.what()
         << endl;
    return -1;
  }

  vector<uint32_t> pathCrcs;
  try {
    pathCrcs.reserve(dotIndexes.size() + 1);

    const char* begin = classPath;
    int beginIndex = 0;
    for (list<int>::iterator i = dotIndexes.begin(); i != dotIndexes.end();
         ++i) {
      if (*i > beginIndex) {
        uint32_t crc;
        if (0 != calcCRC32(begin, *i - beginIndex, crc)) return -1;
        pathCrcs.push_back(crc);
      }
      begin = &classPath[*i + 1];
      beginIndex = *i + 1;
    }
    if (beginIndex < len) {
      uint32_t crc;
      if (0 != calcCRC32(begin, len - beginIndex, crc)) return -1;
      pathCrcs.push_back(crc);
    }
  } catch (bad_alloc& e) {
    cout << "DexPathSigMgr::searchClassPath bad_alloc caught: " << e.what()
         << endl;
    return -1;
  }

  return acTree_->search(pathCrcs, pathSig);
}

int DexPathSigMgr::calcCRC32(const char* str, int len, uint32_t& crc) {
  IObject* crc32 = NULL;
  int ret = -1;
  do {
    if (0 != libutil_createInstance(UTIL_ID_MEMCRC32, &crc32)) break;
    if (0 != ((IMemCRC32*)crc32)->init(str, len)) break;
    if (0 != ((IMemCRC32*)crc32)->getCRC32(&crc)) break;
    ret = 0;
  } while (false);

  if (NULL != crc32) crc32->release();
  return ret;
}
