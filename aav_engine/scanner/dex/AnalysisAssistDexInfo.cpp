#include "AnalysisAssistDexInfo.h"

AnalysisAssistMethodInfo::AnalysisAssistMethodInfo() {
  known = false;
  fastOpcodes.opcode01 = 0;
  fastOpcodes.opcode23 = 0;
  fastOpcodes.opcode45 = 0;
  fastOpcodes.opcode67 = 0;
  fastOpcodes.opcode89 = 0;
}

AnalysisAssistMethodInfo::~AnalysisAssistMethodInfo() {
  known = false;
  fastOpcodes.opcode01 = 0;
  fastOpcodes.opcode23 = 0;
  fastOpcodes.opcode45 = 0;
  fastOpcodes.opcode67 = 0;
  fastOpcodes.opcode89 = 0;
}

AnalysisAssistClassInfo::AnalysisAssistClassInfo() { known = false; }

AnalysisAssistClassInfo::~AnalysisAssistClassInfo() { known = false; }

AnalysisAssistDexInfo* analysisAssistDexInfo = NULL;
