#include "ACMatcher.h"

#include <assert.h>

#include <iostream>
#include <new>
using namespace std;

ACTree::ACTree() { root_ = NULL; }

ACTree::~ACTree() { destroy(); };

int ACTree::create(list<DexPathSig>& pathSigs) {
  int ret = -1;
  do {
    if (0 != createRoot()) break;
    if (0 != createTrieTree(pathSigs)) break;
    if (0 != speedChildren(root_)) break;
    if (0 != linkFailure(root_)) break;
    ret = 0;
  } while (false);

  if (0 != ret) destroy();
  return ret;
}

int ACTree::destroy() {
  destroyTrieTree(root_);
  root_ = NULL;
  return 0;
}

int ACTree::search(vector<uint32_t>& path, DexPathSig** sig) {
  if (NULL == sig) return -1;
  if (NULL == root_ || NULL == root_->first) return -1;

  ACNode* cur = root_;
  uint32_t i = 0;
  int ret = -1;
  while (true) {
    if (i >= path.size()) break;

    if (cur->children.size() > 0) {
      int l = 0;
      int r = cur->children.size() - 1;
      bool found = false;
      while (l <= r) {
        int m = (l + r) / 2;
        uint32_t v = cur->children[m].value;
        if (v < path[i])
          l = m + 1;
        else if (v > path[i])
          r = m - 1;
        else {
          // printf("found at %d\n", m);
          cur = cur->children[m].node;
          found = true;
          break;
        }
      }

      if (found) {
        if (NULL != cur->sig) {
          if (0 ==
              sigMatched(path.size(), i, cur->layer, cur->sig->strMatchType)) {
            *sig = cur->sig;
#ifdef DEBUG_BUILD
            printNodeSig(cur);
#endif
            if (NULL == cur->first) {
              ret = 0;
              break;
            }
          }
        }

        i++;
      } else {
        cur = cur->failure;
        if (root_ == cur) i++;
      }
    } else {
      if (NULL != cur->sig) {
        if (0 ==
            sigMatched(path.size(), i, cur->layer, cur->sig->strMatchType)) {
          *sig = cur->sig;
#ifdef DEBUG_BUILD
          printNodeSig(cur);
#endif
          if (NULL == cur->first) {
            ret = 0;
            break;
          }
        }
      }

      cur = cur->failure;
      if (root_ == cur) i++;
    }
  }
  return ret;
}

int ACTree::search2(vector<uint32_t>& path, DexPathSig** sig) {
  if (NULL == sig) return -1;
  if (NULL == root_ || NULL == root_->first) return -1;

  ACNode* cur = root_->first;
  uint32_t i = 0;
  int ret = -1;
  while (true) {
    if (i >= path.size()) break;

    if (path[i] == cur->value) {
      if (NULL != cur->sig) {
        if (0 ==
            sigMatched(path.size(), i, cur->layer, cur->sig->strMatchType)) {
          *sig = cur->sig;
#ifdef DEBUG_BUILD
          printNodeSig(cur);
#endif
          if (NULL == cur->first) {
            ret = 0;
            break;
          }
        }
      }

      if (NULL == cur->first) {
        cur = cur->failure;
        if (root_ == cur) cur = root_->first;
      } else {
        cur = cur->first;
        i++;
      }
    } else {
      if (NULL == cur->next) {
        if (root_ == cur->parent) {
          cur = root_->first;
          i++;
        } else {
          cur = cur->parent->failure;
          if (root_ == cur) {
            cur = root_->first;
          }
        }
      } else
        cur = cur->next;
    }
  }
  return ret;
}

int ACTree::createRoot() {
  root_ = new (nothrow) ACNode;
  if (NULL == root_) return -1;
  return 0;
}

int ACTree::createTrieTree(list<DexPathSig>& pathSigs) {
  for (list<DexPathSig>::iterator i = pathSigs.begin(); i != pathSigs.end();
       ++i) {
    if (0 != processSig(*i)) return -1;
  }
  return 0;
}

int ACTree::processSig(DexPathSig& sig) {
  assert(sig.pathCrcs.size() > 0);
  assert(root_ != NULL);
  ACNode* cur = root_;
  for (uint32_t i = 0; i < sig.pathCrcs.size(); i++) {
    ACNode* child = cur->first;
    if (NULL == child) {
      ACNode* node = new (nothrow) ACNode;
      if (NULL == node) return -1;
      node->layer = i + 1;
      node->parent = cur;
      node->value = sig.pathCrcs[i];
      if (sig.pathCrcs.size() - 1 == i) node->sig = &sig;

      cur->first = node;
      assert(cur->layer + 1 == node->layer);
      cur = node;
    } else {
      bool exist = false;
      while (NULL != child) {
        if (sig.pathCrcs[i] == child->value) {
          exist = true;
          break;
        }
        if (NULL == child->next)
          break;
        else
          child = child->next;
      }

      if (exist) {
        cur = child;
        if (sig.pathCrcs.size() - 1 == i) {
          if (NULL != cur->sig) {
#ifdef DEBUG_BUILD
            printCollideNodes(cur);
#endif
          }
          cur->sig = &sig;
#ifdef DEBUG_BUILD
          printCollideNodes(cur);
#endif
          assert(false);
        }
      } else {
        ACNode* node = new (nothrow) ACNode;
        if (NULL == node) return -1;
        node->layer = i + 1;
        node->parent = cur;
        node->value = sig.pathCrcs[i];
        if (sig.pathCrcs.size() - 1 == i) node->sig = &sig;

        child->next = node;
        assert(child->layer == node->layer);
        cur = node;
      }
    }
  }
  return 0;
}

int ACTree::linkFailure(ACNode* root) {
  if (NULL == root) return 0;

  if (0 != linkFailure(root->first)) return -1;
  if (0 != linkFailureNode(root)) return -1;
  if (0 != linkFailure(root->next)) return -1;
  return 0;
}

int ACTree::linkFailureNode(ACNode* node) {
  if (NULL == node) return 0;
  if (node == root_) {
    node->failure = node;
    return 0;
  }

  if (root_ == node->parent) {
    node->failure = root_;
    return 0;
  }

  list<uint32_t> suffixPath;
  if (0 != getSuffixPath(node, suffixPath)) return -1;

  while (!suffixPath.empty()) {
    ACNode* failureNode = NULL;
    if (0 == searchPrefixPath(suffixPath, &failureNode)) {
      node->failure = failureNode;
      break;
    }
    suffixPath.erase(suffixPath.begin());
  }
  if (suffixPath.empty()) node->failure = root_;

  return 0;
}

int ACTree::getSuffixPath(ACNode* node, list<uint32_t>& suffixPath) {
  ACNode* cur = node;
  try {
    while (NULL != cur && cur->layer > 1) {
      suffixPath.push_front(cur->value);
      cur = cur->parent;
    }
  } catch (bad_alloc& e) {
    cout << "ACTree::linkFailureNode bad_alloc caught: " << e.what() << endl;
    return -1;
  }
  return 0;
}

int ACTree::searchPrefixPath(list<uint32_t>& suffixPath, ACNode** failureNode) {
  ACNode* cur = root_;
  if (NULL == cur) return -1;
  cur = cur->first;

  int ret = 0;
  for (list<uint32_t>::iterator i = suffixPath.begin(); i != suffixPath.end();
       ++i) {
    bool found = false;
    while (NULL != cur) {
      if (*i == cur->value) {
        found = true;
        break;
      }
      cur = cur->next;
    }

    if (found) {
      *failureNode = cur;
      cur = cur->first;
    } else {
      ret = -1;
      break;
    }
  }
  return ret;
}

int ACTree::destroyTrieTree(ACNode* root) {
  if (NULL == root) return 0;
  destroyTrieTree(root->first);
  destroyTrieTree(root->next);
  delete root;
  root = NULL;
  return 0;
}

int ACTree::sigMatched(uint32_t size, uint32_t index, uint32_t layer,
                       STR_MATCH_TYPE matchType) {
  if (index + 1 == layer) {
    if (layer == size && STR_MATCH_TYPE_EQUAL == matchType) return 0;
    if (layer < size && STR_MATCH_TYPE_START_WITH == matchType) return 0;
  } else if (index + 1 > layer) {
    if (layer < size && STR_MATCH_TYPE_END_WITH == matchType) return 0;
  } else
    assert(false);

  if (STR_MATCH_TYPE_CONTAIN == matchType) return 0;
  return -1;
}

int ACTree::speedChildren(ACNode* node) {
  if (NULL == node) return 0;

  if (NULL != node->first) {
    ACNode* cur = node->first;
    int count = 0;
    while (NULL != cur) {
      count++;
      cur = cur->next;
    }

    node->children.reserve(count);
    cur = node->first;
    try {
      while (NULL != cur) {
        ACChild child;
        child.value = cur->value;
        child.node = cur;
        node->children.push_back(child);

        if (NULL != cur->next) assert(cur->value <= cur->next->value);
        cur = cur->next;
      }
    } catch (bad_alloc& e) {
      cout << "ACTree::speedChildren bad_alloc caught: " << e.what() << endl;
      return -1;
    }

    if (0 != speedChildren(node->first)) return -1;
  }

  if (NULL != node->next) {
    if (0 != speedChildren(node->next)) return -1;
  }
  return 0;
}

#ifdef DEBUG_BUILD
void ACTree::printNodeSig(ACNode* node) {
  if (NULL == node) return;

  if (NULL == node->first)
    cout << "node crc: [";
  else
    cout << "    node crc: [";
  for (uint32_t ii = 0; ii < node->sig->pathCrcs.size(); ii++) {
    cout << "0x" << hex << node->sig->pathCrcs[ii] << dec << " ";
  }
  cout << "] sigID: " << node->sig->sigID << endl;
}

void ACTree::printCollideNodes(ACNode* node) {
  if (NULL == node) return;

  if (NULL != node->sig) {
    cout << "signature collision!!!" << endl;
    printNodeSig(node);
  }
  printCollideNodes(node->first);
  printCollideNodes(node->next);
}
#endif
