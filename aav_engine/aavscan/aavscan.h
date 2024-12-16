#ifndef _AAVSCAN_H_
#define _AAVSCAN_H_

#define MULTITHREAD_SCAN

struct SCAN_OPTION;

class IFileID;
class ISigMgr;
class IScanner;

struct AAV_ENGINE_CONTEXT {
  SCAN_OPTION* scanOption;
  IFileID* fileID;
  ISigMgr* sigMgr;
  IScanner* apkScanner;
  IScanner* dexScanner;
};

#endif
