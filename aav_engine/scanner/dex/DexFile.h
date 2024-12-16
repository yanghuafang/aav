#ifndef _DEXFILE_H_
#define _DEXFILE_H_

#include <stdint.h>

#include <string>
#include <vector>

#include "dex_format.h"
using namespace std;

#define MAX_DEX_ITEM_COUNT (65536 * 10)

class ITarget;
class DexCode;

struct ProtoInfo {
  string shorty;
  string returnType;
  vector<string> parameters;
};

struct FieldInfo {
  string classStr;
  string type;
  string name;
};

struct MethodInfo {
  string classStr;
  ProtoInfo protoInfo;
  string name;
};

struct ClassInfo {
  string classStr;
  string superClass;
  string sourceFile;
};

class DexFile {
 public:
  DexFile();
  ~DexFile();

  int init(ITarget* target);
  int uninit();

  int getClass(string& className);
  int getDirectMethod(string& methodName, string& protoName, DexCode& dexCode,
                      uint32_t& key);
  int getVirtualMethod(string& methodName, string& protoName, DexCode& dexCode,
                       uint32_t& key);

  int getStringString(uint32_t index, string& str);
  int getTypeString(uint32_t index, string& str);
  int getProtoInfo(uint32_t index, ProtoInfo& protoInfo);
  int getFieldInfo(uint32_t index, FieldInfo& fieldInfo);
  int getMethodInfo(uint32_t index, MethodInfo& methodInfo);
  int getClassInfo(uint32_t index, ClassInfo& classInfo);

 private:
  int parseHeader();
  int parseStringIDs();
  int parseTypeIDs();
  int parseProtoIDs();
  int parseFieldIDs();
  int parseMethodIDs();
  int parseClassDefs();

 private:
  dex_format* dexFormat_;
  class_data_item* classDataItem_;

  int maxStringID_;
  int maxTypeID_;
  int maxProtoID_;
  int maxFieldID_;
  int maxMethodID_;
  int maxClassDefID_;

  void* dexFileBuf_;
  uint32_t targetSize_;
  bool littleEndianTag_;

  vector<class_def_item>::iterator classDefsItor_;
  vector<encoded_method>::iterator directMethodsItor_;
  vector<encoded_method>::iterator virtualMethodsItor_;
};

#endif
