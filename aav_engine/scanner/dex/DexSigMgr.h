#ifndef _DEXSIGMGR_H_
#define _DEXSIGMGR_H_

#include <stdint.h>

struct DexPathSig;
struct FastOpcodes;
struct DexCodeCrcSig;

class ISigMgr;
class DexPathSigMgr;
class DexCodeSigMgr;
class DexCodeLogicSig;

class DexSigMgr {
 public:
  DexSigMgr();
  ~DexSigMgr();

  int init(ISigMgr* sigMgr);
  int uninit();

  int searchClassPath(const char* classPath, DexPathSig** pathSig);
  int searchOpcodeMap(const FastOpcodes* opcodes);
  int searchOpcodeCrc(uint32_t crc, DexCodeCrcSig** opcodeSig);
  int searchOperandCrc(uint32_t crc, DexCodeCrcSig** operandSig);
  int searchCodeLogic(uint32_t sigID, DexCodeLogicSig** logicSig);

 private:
  DexPathSigMgr* pathSigMgr_;
  DexCodeSigMgr* codeSigMgr_;
};

#endif
