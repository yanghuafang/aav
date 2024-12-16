#ifndef _DEXCODESIGMGR_H_
#define _DEXCODESIGMGR_H_

#include <stdint.h>

#include <bitset>
#include <vector>

#include "DexSig.h"
#include "ISigMgr.h"
using namespace std;

struct SIG_ITEM;

class ISigMgr;

struct DexOpcodeMap {
  bitset<BIT_MAP_SIZE> map01;
  bitset<BIT_MAP_SIZE> map23;
  bitset<BIT_MAP_SIZE> map45;
  bitset<BIT_MAP_SIZE> map67;
};

struct DexCodeCrcSig {
  uint32_t crc;
  vector<uint32_t> sigIDs;
};

struct DexCodeLogicSig {
  uint32_t sigID;
  vector<uint32_t> notCrcs;
  vector<uint32_t> xorCrcs;
  vector<uint32_t> andCrcs;
  vector<uint32_t> orCrcs;
};

#define FAST_OPCODES_COUNT 8
#define MAX_FAST_OPCODES_COUNT 10

struct FastOpcodes {
  uint16_t opcode01;
  uint16_t opcode23;
  uint16_t opcode45;
  uint16_t opcode67;
#ifdef ANALYSISASSISTDEXINFO
  uint16_t opcode89;
#endif
};

class DexCodeSigMgr {
 public:
  DexCodeSigMgr();
  ~DexCodeSigMgr();

  int init(ISigMgr* sigMgr);
  int uninit();

  int searchOpcodeMap(const FastOpcodes* opcodes);
  int searchOpcodeCrc(uint32_t crc, DexCodeCrcSig** opcodeSig);
  int searchOperandCrc(uint32_t crc, DexCodeCrcSig** operandSig);
  int searchCodeLogic(uint32_t sigID, DexCodeLogicSig** logicSig);

 private:
  int parseOpcodeMap(const SIG_ITEM* opcodeMapItem);
  int parseOpcodeCrcSig(const SIG_ITEM* opcodeCrcSigItem);
  int parseOperandCrcSig(const SIG_ITEM* operandCrcSigItem);
  int parseCodeLogicSig(const SIG_ITEM* codeLogicSigItem);

  int prepareOpcodeMap(const uint8_t* mapInFile,
                       bitset<BIT_MAP_SIZE>& mapInMem);

 private:
  DexOpcodeMap opcodeMap_;
  vector<DexCodeCrcSig> opcodeCrcSigArray_;
  vector<DexCodeCrcSig> operandCrcSigArray_;
  vector<DexCodeLogicSig> codeLogicSigArray_;
};

#endif
