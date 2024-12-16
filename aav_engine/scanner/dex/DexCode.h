#ifndef _DEXCODE_H_
#define _DEXCODE_H_

#ifdef ANALYSISASSISTDEXINFO
#include "AnalysisAssistDexInfo.h"
#endif

#include <stdint.h>

#include <list>
#include <string>
#include <vector>
using namespace std;

struct FastOpcodes;
class DexFile;

struct DexInstruction {
  uint16_t opcode;
  int size;
#ifdef ANALYSISASSISTDEXINFO
  string instructionStr;
#endif
};

class DexCode {
 public:
  DexCode();
  ~DexCode();

  int init(DexFile* dexFile, void* funcStart, void* funcEnd);
  int uninit();
  int parseCode();
  int getFastOpcodes(FastOpcodes& fastOpcodes);
  int getOpcodeCRC32(uint32_t& crc);
  int getOperandStrCRC32(uint32_t& crc);
#ifdef ANALYSISASSISTDEXINFO
  int parseCode(list<OpcodeInfo>& opcodeBuf, list<string>& stringBuf);
#endif

 private:
  int pushOperandStr(string& constStr);
#ifdef ANALYSISASSISTDEXINFO
  int pushOperandStr(list<string>& stringBuf, string& constStr);
#endif

 private:
  DexFile* dexFile_;
  void* funcStart_;
  void* funcEnd_;
  void* codeEnd_;
  vector<uint8_t> opcodeBuf_;
  vector<char> operandStrBuf_;
};

#endif
