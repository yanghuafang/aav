#ifndef _ACMATCHER_H_
#define _ACMATCHER_H_

#include <stdint.h>

#include <list>
#include <string>
#include <vector>

#include "DexPathSigMgr.h"
using namespace std;

struct ACNode;

struct ACChild {
  uint32_t value;
  ACNode* node;

  ACChild() {
    value = 0;
    node = NULL;
  }
};

struct ACNode {
  uint32_t layer;
  ACNode* parent;
  ACNode* next;
  ACNode* first;
  vector<ACChild> children;
  ACNode* failure;
  uint32_t value;  // CRC
  struct DexPathSig* sig;

  ACNode() {
    layer = 0;
    parent = NULL;
    next = NULL;
    first = NULL;
    failure = NULL;
    value = 0;
    sig = NULL;
  }
};

class ACTree {
 public:
  ACTree();
  ~ACTree();

  int create(list<DexPathSig>& pathSigs);
  int destroy();
  int search(vector<uint32_t>& path, DexPathSig** sig);
  int search2(vector<uint32_t>& path, DexPathSig** sig);

 private:
  int createRoot();
  int createTrieTree(list<DexPathSig>& pathSigs);
  int processSig(DexPathSig& sig);
  int linkFailure(ACNode* root);
  int linkFailureNode(ACNode* node);
  int getSuffixPath(ACNode* node, list<uint32_t>& suffixPath);
  int searchPrefixPath(list<uint32_t>& suffixPath, ACNode** failureNode);
  int destroyTrieTree(ACNode* root);
  int sigMatched(uint32_t size, uint32_t index, uint32_t layer,
                 STR_MATCH_TYPE matchType);
  int speedChildren(ACNode* node);
#ifdef DEBUG_BUILD
  void printNodeSig(ACNode* node);
  void printCollideNodes(ACNode* node);
#endif

 private:
  ACNode* root_;
};

#endif