#ifndef _ANALYSISASSISTDEXINFO_H_
#define _ANALYSISASSISTDEXINFO_H_

#include <list>
#include <string>

#include "../DexCodeSigMgr.h"
using namespace std;

struct OpcodeInfo {
  uint16_t opcode;
  string instruction;
};

struct AnalysisAssistMethodInfo {
  AnalysisAssistMethodInfo();
  ~AnalysisAssistMethodInfo();

  bool known;
  string methodName;
  string protoName;
  FastOpcodes fastOpcodes;
  list<OpcodeInfo> opcodeBuf;
  string opcodeCRC32;
  list<string> stringBuf;
  string stringCRC32;
};

struct AnalysisAssistClassInfo {
  AnalysisAssistClassInfo();
  ~AnalysisAssistClassInfo();

  bool known;
  string classPath;
  list<AnalysisAssistMethodInfo> methodInfoList;
};

struct AnalysisAssistDexInfo {
  list<AnalysisAssistClassInfo> classInfoList;
};

extern AnalysisAssistDexInfo* analysisAssistDexInfo;

#endif
