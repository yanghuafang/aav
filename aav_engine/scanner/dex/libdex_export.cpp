#include "libdex_export.h"

#include "DexScanner.h"
#ifdef ANALYSISASSISTDEXINFO
#include "AnalysisAssistDexInfo.h"
#endif

#include <stdio.h>

#include <new>
using namespace std;

int libdex_createInstance(IScanner** scanner) {
  if (NULL == scanner) return -1;

  *scanner = new (nothrow) DexScanner;
  if (NULL == *scanner) return -1;

  return 0;
}

#ifdef ANALYSISASSISTDEXINFO
int getAnalysisAssistDexInfo(AnalysisAssistDexInfo** dexInfo) {
  if (NULL == dexInfo) return -1;

  if (NULL == analysisAssistDexInfo) return -1;

  *dexInfo = analysisAssistDexInfo;
  return 0;
}
#endif
