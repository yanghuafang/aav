#ifndef _DEXPATHSIGMGR_H_
#define _DEXPATHSIGMGR_H_

#include <list>
#include <string>
#include <vector>

#include "DexSig.h"
using namespace std;

struct SIG_ITEM;

class ISigMgr;
class ACTree;

struct DexPathSig {
  uint32_t sigID;
  STR_MATCH_TYPE strMatchType;
  LOGIC_MATCH_TYPE logicMatchType;
  vector<uint32_t> pathCrcs;
};

class DexPathSigMgr {
 public:
  DexPathSigMgr();
  ~DexPathSigMgr();

  int init(ISigMgr* sigMgr);
  int uninit();

  int searchClassPath(const char* classPath, DexPathSig** pathSig);

 private:
  int parsePathSig(const SIG_ITEM* pathSigItem);
  int createACTree();
  int calcCRC32(const char* str, int len, uint32_t& crc);

 private:
  list<DexPathSig> pathSigList_;
  ACTree* acTree_;
};

#endif
