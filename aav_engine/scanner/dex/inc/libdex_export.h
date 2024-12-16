#ifndef _LIBDEX_EXPORT_H_
#define _LIBDEX_EXPORT_H_

#include "DexSig.h"

class IScanner;
class AnalysisAssistDexInfo;

int libdex_createInstance(IScanner** scanner);

#ifdef ANALYSISASSISTDEXINFO
int getAnalysisAssistDexInfo(AnalysisAssistDexInfo** dexInfo);
#endif

#endif