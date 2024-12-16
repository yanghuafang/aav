#include "DexFile.h"

#include <assert.h>
#include <string.h>

#include <iostream>
#include <new>

#include "DexCode.h"
#include "ITarget.h"
#include "leb128.h"
using namespace std;

uint8_t DEX_FILE_MAGIC[8] = {0x64, 0x65, 0x78, 0x0a,
                             0x30, 0x33, 0x35, 0x00};  //"dex\n035\0"
uint32_t ENDIAN_CONSTANT = 0x12345678;
uint32_t REVERSE_ENDIAN_CONSTANT = 0x78563412;

DexFile::DexFile() {
  dexFormat_ = NULL;
  classDataItem_ = NULL;

  maxStringID_ = 0;
  maxTypeID_ = 0;
  maxProtoID_ = 0;
  maxFieldID_ = 0;
  maxMethodID_ = 0;
  maxClassDefID_ = 0;

  dexFileBuf_ = NULL;
  targetSize_ = 0;
  littleEndianTag_ = true;
}

DexFile::~DexFile() { uninit(); }

int DexFile::init(ITarget* target) {
  if (NULL == target) return -1;

  int ret = -1;
  do {
    int64_t targetSize = 0;
    if (0 != target->getSize(&targetSize)) break;
    targetSize_ = (uint32_t)targetSize;
    if (0 != target->getBuf(&dexFileBuf_)) break;

    dexFormat_ = new (nothrow) dex_format;
    if (NULL == dexFormat_) break;

    if (0 != parseHeader()) break;
    if (0 != parseStringIDs()) break;
    if (0 != parseTypeIDs()) break;
    if (0 != parseProtoIDs()) break;
    if (0 != parseFieldIDs()) break;
    if (0 != parseMethodIDs()) break;
    if (0 != parseClassDefs()) break;

    ret = 0;
  } while (false);

  if (0 != ret) uninit();
  return ret;
}

int DexFile::uninit() {
  delete dexFormat_;
  dexFormat_ = NULL;
  delete classDataItem_;
  classDataItem_ = NULL;

  maxStringID_ = 0;
  maxTypeID_ = 0;
  maxProtoID_ = 0;
  maxFieldID_ = 0;
  maxMethodID_ = 0;
  maxClassDefID_ = 0;

  dexFileBuf_ = NULL;
  targetSize_ = 0;
  littleEndianTag_ = true;
  return 0;
}

int DexFile::getClass(string& className) {
#ifdef DEBUG_BUILD
  cout << endl;
#endif
  delete classDataItem_;
  classDataItem_ = NULL;

  int ret = -1;
  do {
    if (dexFormat_->class_defs.end() == classDefsItor_) break;

    if (classDefsItor_->class_idx > maxTypeID_) {
      // cout << "warning: invalid classDefsItor_->class_idx: " <<
      // classDefsItor_->class_idx << endl;
      ret = -2;
      break;
    }
    assert(classDefsItor_->class_idx <= maxTypeID_);
    int result = getTypeString(classDefsItor_->class_idx, className);
    if (0 != result) {
      ret = result;
      break;
    }

    if (classDefsItor_->class_data_off <= 0x70 ||
        classDefsItor_->class_data_off >= targetSize_) {
      // cout << "warning: invalid classDefsItor_->class_data_off: " <<
      // classDefsItor_->class_data_off << endl;
      ret = -2;
      break;
    }
    assert(classDefsItor_->class_data_off > 0x70 &&
           classDefsItor_->class_data_off < targetSize_);

    uint8_t* cur =
        (uint8_t*)((char*)dexFileBuf_ + classDefsItor_->class_data_off);
    uint32_t staticFieldsSize = 0;
    uint32_t instanceFieldsSize = 0;
    uint32_t directMethodsSize = 0;
    uint32_t virtualMethodsSize = 0;
    int bytesRead = 0;

    if (0 != read_uleb128(cur, &staticFieldsSize, &bytesRead)) break;
    cur += bytesRead;
    if (0 != read_uleb128(cur, &instanceFieldsSize, &bytesRead)) break;
    cur += bytesRead;
    if (0 != read_uleb128(cur, &directMethodsSize, &bytesRead)) break;
    cur += bytesRead;
    if (0 != read_uleb128(cur, &virtualMethodsSize, &bytesRead)) break;
    cur += bytesRead;

    bool success = true;
    for (int i = 0; i < staticFieldsSize; i++) {  // skip static_fields
      uint32_t data = 0;
      if (0 != read_uleb128(cur, &data, &bytesRead)) {
        success = false;
        break;
      }
      cur += bytesRead;
      if (0 != read_uleb128(cur, &data, &bytesRead)) {
        success = false;
        break;
      }
      cur += bytesRead;
    }
    if (!success) break;

    success = true;
    for (int i = 0; i < instanceFieldsSize; i++) {  // skip instance_fields
      uint32_t data = 0;
      if (0 != read_uleb128(cur, &data, &bytesRead)) {
        success = false;
        break;
      }
      cur += bytesRead;
      if (0 != read_uleb128(cur, &data, &bytesRead)) {
        success = false;
        break;
      }
      cur += bytesRead;
    }
    if (!success) break;

    classDataItem_ = new (nothrow) class_data_item;
    if (NULL == classDataItem_) break;

    try {
      success = true;
      classDataItem_->direct_methods.reserve(directMethodsSize);
      for (int i = 0; i < directMethodsSize; i++) {
        encoded_method encodedMethod;
        if (0 !=
            read_uleb128(cur, &encodedMethod.method_idx_diff, &bytesRead)) {
          success = false;
          break;
        }
        cur += bytesRead;
        if (0 != read_uleb128(cur, &encodedMethod.access_flags, &bytesRead)) {
          success = false;
          break;
        }
        cur += bytesRead;
        if (0 != read_uleb128(cur, &encodedMethod.code_off, &bytesRead)) {
          success = false;
          break;
        }
        cur += bytesRead;
        classDataItem_->direct_methods.push_back(encodedMethod);
      }
      if (!success) break;
      directMethodsItor_ = classDataItem_->direct_methods.begin();

      classDataItem_->virtual_methods.reserve(virtualMethodsSize);
      for (int i = 0; i < virtualMethodsSize; i++) {
        encoded_method encodedMethod;
        if (0 !=
            read_uleb128(cur, &encodedMethod.method_idx_diff, &bytesRead)) {
          success = false;
          break;
        }
        cur += bytesRead;
        if (0 != read_uleb128(cur, &encodedMethod.access_flags, &bytesRead)) {
          success = false;
          break;
        }
        cur += bytesRead;
        if (0 != read_uleb128(cur, &encodedMethod.code_off, &bytesRead)) {
          success = false;
          break;
        }
        cur += bytesRead;
        classDataItem_->virtual_methods.push_back(encodedMethod);
      }
      if (!success) break;
      virtualMethodsItor_ = classDataItem_->virtual_methods.begin();
    } catch (bad_alloc& e) {
      cerr << "DexFile::getClass bad_alloc caught: " << e.what() << endl;
      break;
    }

    ++classDefsItor_;
    ret = 0;
  } while (false);

  if (0 != ret) {
    delete classDataItem_;
    classDataItem_ = NULL;

    if (dexFormat_->class_defs.end() != classDefsItor_) ++classDefsItor_;
  }
  return ret;
}

int DexFile::getDirectMethod(string& methodName, string& protoName,
                             DexCode& dexCode, uint32_t& key) {
#ifdef DEBUG_BUILD
  cout << endl;
#endif
  methodName.clear();
  protoName.clear();
  int ret = -1;
  do {
    if (classDataItem_->direct_methods.end() == directMethodsItor_) break;

    if (0 == key)
      key = directMethodsItor_->method_idx_diff;
    else
      key += directMethodsItor_->method_idx_diff;

    if (key > maxMethodID_) {
      // cout << "warning: invalid directMethodsItor_->method_idx_diff: " <<
      // (int)directMethodsItor_->method_idx_diff
      //     << " key: " << (int)key << endl;
      ret = -2;
      break;
    }
    assert(key <= maxMethodID_);
#if 0  // def DEBUG_BUILD
        cout << "[direct encoded_method] method_idx_diff: " << (int)directMethodsItor_->method_idx_diff
            << " key: " << (int)key
            << " access_flags: 0x" << hex << (int)directMethodsItor_->access_flags << dec
            << " code_off: " << (int)directMethodsItor_->code_off
            << endl;
#endif

    uint32_t index = dexFormat_->method_ids[key].name_idx;
    int result = getStringString(index, methodName);
    if (0 != result) {
      ret = result;
      break;
    }

#ifdef ANALYSISASSISTDEXINFO
    index = dexFormat_->method_ids[key].proto_idx;
    ProtoInfo protoInfo;
    result = getProtoInfo(index, protoInfo);
    if (0 == result) {
      try {
        protoName = "{" + protoInfo.shorty + "|" + protoInfo.returnType + "|[";
        bool seperator = false;
        for (vector<string>::iterator i = protoInfo.parameters.begin();
             i != protoInfo.parameters.end(); ++i) {
          if (seperator)
            protoName += "|";
          else
            seperator = true;
          protoName += *i;
        }
        protoName += "]}";
      } catch (bad_alloc& e) {
        cerr << "DexFile::getDirectMethod bad_alloc caught: " << e.what()
             << endl;
        break;
      }
    }
#endif

#ifdef DEBUG_BUILD
    cout << "direct method: " << methodName
         << " method_idx_diff: " << (int)directMethodsItor_->method_idx_diff
         << " protoName: " << protoName << " key: " << (int)key
         << " code_off: " << (int)directMethodsItor_->code_off << endl;
    MethodInfo methodInfo;
    result = getMethodInfo(key, methodInfo);
    if (0 != result) {
      ret = result;
      break;
    }
    cout << "method[" << (int)directMethodsItor_->method_idx_diff << " "
         << (int)key << "] classStr: " << methodInfo.classStr;
    cout << "[proto shorty: " << methodInfo.protoInfo.shorty
         << " returnType: " << methodInfo.protoInfo.returnType
         << " parameters: ";
    for (int i = 0; i < methodInfo.protoInfo.parameters.size(); ++i) {
      cout << methodInfo.protoInfo.parameters[i] << " ";
    }
    cout << "] name: " << methodInfo.name << endl;
#endif
#if 0  // def DEBUG_BUILD
        cout << "[direct method_id_item] class_idx: " << (int)dexFormat_->method_ids[key].class_idx
            << " proto_idx: " << (int)dexFormat_->method_ids[key].proto_idx
            << " name_idx: " << (int)dexFormat_->method_ids[key].name_idx
            << endl;
#endif

    if (directMethodsItor_->code_off % 4 != 0 ||
        directMethodsItor_->code_off <= 0x70 ||
        directMethodsItor_->code_off >= targetSize_) {
      // cout << "warning: invalid directMethodsItor_->code_off: " <<
      // directMethodsItor_->code_off << endl;
      ret = -2;
      break;
    }
    assert(0 == directMethodsItor_->code_off % 4 &&
           directMethodsItor_->code_off > 0x70 &&
           directMethodsItor_->code_off < targetSize_);
    code_item* item =
        (code_item*)((char*)dexFileBuf_ + directMethodsItor_->code_off);
    char* codeStart = (char*)&item->insns;
    char* codeEnd = (char*)&item->insns + item->insns_size * sizeof(uint16_t);
    dexCode.uninit();
    if (0 != dexCode.init(this, codeStart, codeEnd)) break;
#if 0  // def DEBUG_BUILD
        cout << "[direct code_item] registers_size: " << (int)item->registers_size
            << " ins_size: " << (int)item->ins_size
            << " outs_size: " << (int)item->outs_size
            << " tries_size: " << (int)item->tries_size
            << " insns_size: " << (int)item->insns_size
            << endl;
#endif

    ++directMethodsItor_;
    ret = 0;
  } while (false);

  if (0 != ret && classDataItem_->direct_methods.end() != directMethodsItor_)
    ++directMethodsItor_;
  return ret;
}

int DexFile::getVirtualMethod(string& methodName, string& protoName,
                              DexCode& dexCode, uint32_t& key) {
#ifdef DEBUG_BUILD
  cout << endl;
#endif
  methodName.clear();
  protoName.clear();
  int ret = -1;
  do {
    if (classDataItem_->virtual_methods.end() == virtualMethodsItor_) break;

    if (0 == key)
      key = virtualMethodsItor_->method_idx_diff;
    else
      key += virtualMethodsItor_->method_idx_diff;

    if (key > maxMethodID_) {
      // cout << "warning: invalid virtualMethodsItor_->method_idx_diff: " <<
      // (int)virtualMethodsItor_->method_idx_diff
      //     << " key: " << (int)key << endl;
      ret = -2;
      break;
    }
    assert(key <= maxMethodID_);
#if 0  // def DEBUG_BUILD
        cout << "[virtual encoded_method] method_idx_diff: " << (int)virtualMethodsItor_->method_idx_diff
            << " key: " << (int)key
            << " access_flags: 0x" << hex << (int)virtualMethodsItor_->access_flags << dec
            << " code_off: " << (int)virtualMethodsItor_->code_off
            << endl;
#endif

    uint32_t index = dexFormat_->method_ids[key].name_idx;
    int result = getStringString(index, methodName);
    if (0 != result) {
      ret = result;
      break;
    }

#ifdef ANALYSISASSISTDEXINFO
    index = dexFormat_->method_ids[key].proto_idx;
    ProtoInfo protoInfo;
    result = getProtoInfo(index, protoInfo);
    if (0 == result) {
      try {
        protoName = "{" + protoInfo.shorty + "|" + protoInfo.returnType + "|[";
        bool seperator = false;
        for (vector<string>::iterator i = protoInfo.parameters.begin();
             i != protoInfo.parameters.end(); ++i) {
          if (seperator)
            protoName += "|";
          else
            seperator = true;
          protoName += *i;
        }
        protoName += "]}";
      } catch (bad_alloc& e) {
        cerr << "DexFile::getVirtualMethod bad_alloc caught: " << e.what()
             << endl;
        break;
      }
    }
#endif

#ifdef DEBUG_BUILD
    cout << "virtual method: " << methodName
         << " method_idx_diff: " << (int)virtualMethodsItor_->method_idx_diff
         << " protoName: " << protoName << " key: " << (int)key
         << " code_off: " << (int)virtualMethodsItor_->code_off << endl;
    MethodInfo methodInfo;
    result = getMethodInfo(key, methodInfo);
    if (0 != result) {
      ret = result;
      break;
    }
    cout << "method[" << (int)virtualMethodsItor_->method_idx_diff << " "
         << (int)key << "] classStr: " << methodInfo.classStr;
    cout << "[proto shorty: " << methodInfo.protoInfo.shorty
         << " returnType: " << methodInfo.protoInfo.returnType
         << " parameters: ";
    for (int i = 0; i < methodInfo.protoInfo.parameters.size(); ++i) {
      cout << methodInfo.protoInfo.parameters[i] << " ";
    }
    cout << "] name: " << methodInfo.name << endl;
#endif
#if 0  // def DEBUG_BUILD
        cout << "[virtual method_id_item] class_idx: " << (int)dexFormat_->method_ids[key].class_idx
            << " proto_idx: " << (int)dexFormat_->method_ids[key].proto_idx
            << " name_idx: " << (int)dexFormat_->method_ids[key].name_idx
            << endl;
#endif

    if (virtualMethodsItor_->code_off % 4 != 0 ||
        virtualMethodsItor_->code_off <= 0x70 ||
        virtualMethodsItor_->code_off >= targetSize_) {
      // cout << "warning: invalid virtualMethodsItor_->code_off: " <<
      // virtualMethodsItor_->code_off << endl;
      ret = -2;
      break;
    }
    code_item* item =
        (code_item*)((char*)dexFileBuf_ + virtualMethodsItor_->code_off);
    char* codeStart = (char*)&item->insns;
    char* codeEnd = (char*)&item->insns + item->insns_size * sizeof(uint16_t);
    dexCode.uninit();
    if (0 != dexCode.init(this, codeStart, codeEnd)) break;
#if 0  // def DEBUG_BUILD
        cout << "[virtual code_item] registers_size: " << (int)item->registers_size
            << " ins_size: " << (int)item->ins_size
            << " outs_size: " << (int)item->outs_size
            << " tries_size: " << (int)item->tries_size
            << " insns_size: " << (int)item->insns_size
            << endl;
#endif

    ++virtualMethodsItor_;
    ret = 0;
  } while (false);

  if (0 != ret && classDataItem_->virtual_methods.end() != virtualMethodsItor_)
    ++virtualMethodsItor_;
  return ret;
}

int DexFile::getStringString(uint32_t index, string& str) {
  if (index > maxStringID_) {
    // cout << "warning: getStringString invalid index: " << index << endl;
    return -2;
  }
  assert(index <= maxStringID_);

  if (dexFormat_->string_ids[index].string_data_off <= 0x70 ||
      dexFormat_->string_ids[index].string_data_off >= targetSize_) {
    // cout << "warning: getStringString invalid string_data_off: " <<
    // dexFormat_->string_ids[index].string_data_off << endl;
    return -2;
  }
  assert(dexFormat_->string_ids[index].string_data_off > 0x70 &&
         dexFormat_->string_ids[index].string_data_off < targetSize_);

  uint8_t* cur = (uint8_t*)((char*)dexFileBuf_ +
                            dexFormat_->string_ids[index].string_data_off);
  uint32_t utf16Size = 0;
  int bytesRead = 0;
  if (0 != read_uleb128(cur, &utf16Size, &bytesRead)) return -1;
  try {
    str = (char*)cur + bytesRead;
  } catch (bad_alloc& e) {
    cerr << "DexFile::getStringString bad_alloc caught: " << e.what() << endl;
    return -1;
  }
  return 0;
}

int DexFile::getTypeString(uint32_t index, string& str) {
  if (index > maxTypeID_) {
    // cout << "warning: getTypeString invalid index: " << index << endl;
    return -2;
  }
  assert(index <= maxTypeID_);

  return getStringString(dexFormat_->type_ids[index].descriptor_idx, str);
}

int DexFile::getProtoInfo(uint32_t index, ProtoInfo& protoInfo) {
  if (index > maxProtoID_) {
    // cout << "warning: getProtoInfo invalid index: " << index << endl;
    return -2;
  }
  assert(index <= maxProtoID_);

  int result = getStringString(dexFormat_->proto_ids[index].shorty_idx,
                               protoInfo.shorty);
  if (0 != result) return result;
  result = getTypeString(dexFormat_->proto_ids[index].return_type_idx,
                         protoInfo.returnType);
  if (0 != result) return result;

  try {
    if (dexFormat_->proto_ids[index].parameters_off <= 0x70 ||
        dexFormat_->proto_ids[index].parameters_off >= targetSize_) {
      // cout << "warning: " << index << " invalid parameters_off: " <<
      // dexFormat_->proto_ids[index].parameters_off << endl;
      return -2;
    }
    assert(dexFormat_->proto_ids[index].parameters_off > 0x70 &&
           dexFormat_->proto_ids[index].parameters_off < targetSize_);

    uint8_t* cur = (uint8_t*)((char*)dexFileBuf_ +
                              dexFormat_->proto_ids[index].parameters_off);
    int size = *(uint32_t*)cur;
    cur += sizeof(uint32_t);
    string str;
    for (int i = 0; i < size; i++) {
      uint16_t typeIndex = *(uint16_t*)cur;
      cur += sizeof(uint16_t);
      result = getTypeString(typeIndex, str);
      if (0 != result) return result;
      protoInfo.parameters.push_back(str);
    }
  } catch (bad_alloc& e) {
    cerr << "DexFile::getProtoString bad_alloc caught: " << e.what() << endl;
    return -1;
  }
  return 0;
}

int DexFile::getFieldInfo(uint32_t index, FieldInfo& fieldInfo) {
  if (index > maxFieldID_) {
    // cout << "warning: getFieldInfo invalid index: " << index << endl;
    return -2;
  }
  assert(index <= maxFieldID_);

  int result =
      getTypeString(dexFormat_->field_ids[index].class_idx, fieldInfo.classStr);
  if (0 != result) return result;
  result = getTypeString(dexFormat_->field_ids[index].type_idx, fieldInfo.type);
  if (0 != result) return result;
  result =
      getStringString(dexFormat_->field_ids[index].name_idx, fieldInfo.name);
  if (0 != result) return result;
  return 0;
}

int DexFile::getMethodInfo(uint32_t index, MethodInfo& methodInfo) {
  if (index > maxMethodID_) {
    // cout << "warning: getMethodInfo invalid index: " << index << endl;
    return -2;
  }
  assert(index <= maxMethodID_);

  int result = getTypeString(dexFormat_->method_ids[index].class_idx,
                             methodInfo.classStr);
  if (0 != result) return result;
  result = getProtoInfo(dexFormat_->method_ids[index].proto_idx,
                        methodInfo.protoInfo);
  if (0 != result) {
    // cout << "warning: failed to getProtoInfo. proto_idx: " <<
    // dexFormat_->method_ids[index].proto_idx << endl; return result;
  }
  result =
      getStringString(dexFormat_->method_ids[index].name_idx, methodInfo.name);
  if (0 != result) return result;
  return 0;
}

int DexFile::getClassInfo(uint32_t index, ClassInfo& classInfo) {
  if (index > maxClassDefID_) {
    // cout << "warning: getClassInfo invalid index: " << index << endl;
    return -2;
  }
  assert(index <= maxClassDefID_);

  int result = getTypeString(dexFormat_->class_defs[index].class_idx,
                             classInfo.classStr);
  if (0 != result) return result;
  result = getTypeString(dexFormat_->class_defs[index].superclass_idx,
                         classInfo.superClass);
  if (0 != result) return result;

  if (dexFormat_->class_defs[index].source_file_idx > maxStringID_) {
    // cout << "warning: " << index << " invalid source_file_idx: "  <<
    // dexFormat_->class_defs[index].source_file_idx << endl; return -2;
  }
  result = getStringString(dexFormat_->class_defs[index].source_file_idx,
                           classInfo.sourceFile);
  if (0 != result) {
    // return result;
  }
  return 0;
}

int DexFile::parseHeader() {
  int ret = -1;
  do {
    header_item* headerItem = &dexFormat_->header;
    assert(0x70 == sizeof(header_item));
    memcpy(headerItem, dexFileBuf_, sizeof(header_item));
    if (0 != memcmp(headerItem->magic, DEX_FILE_MAGIC, 8)) break;
    if (headerItem->file_size != targetSize_) break;
    if (0x70 != headerItem->header_size) break;

    if (ENDIAN_CONSTANT == headerItem->endian_tag)
      littleEndianTag_ = true;
    else if (REVERSE_ENDIAN_CONSTANT == headerItem->endian_tag)
      littleEndianTag_ = false;
    else
      break;
#if 0  // def DEBUG_BUILD
        cout << "[header_item] checksum: 0x" << hex << (unsigned int)headerItem->checksum << dec
            << " file_size: " << (unsigned int)headerItem->file_size
            << " header_size: 0x" << hex << (unsigned int)headerItem->header_size << dec
            << " endian_tag: 0x" << hex << (unsigned int)headerItem->endian_tag << dec
            << " link_size: " << (unsigned int)headerItem->link_size
            << " link_off: " << (unsigned int)headerItem->link_off
            << " map_off: " << (unsigned int)headerItem->map_off
            << " string_ids_size: " << (unsigned int)headerItem->string_ids_size
            << " string_ids_off: " << (unsigned int)headerItem->string_ids_off
            << " type_ids_size: " << (unsigned int)headerItem->type_ids_size
            << " type_ids_off: " << (unsigned int)headerItem->type_ids_off
            << " proto_ids_size: " << (unsigned int)headerItem->proto_ids_size
            << " proto_ids_off: " << (unsigned int)headerItem->proto_ids_off
            << " field_ids_size: " << (unsigned int)headerItem->field_ids_size
            << " field_ids_off: " << (unsigned int)headerItem->field_ids_off
            << " method_ids_size: " << (unsigned int)headerItem->method_ids_size
            << " method_ids_off: " << (unsigned int)headerItem->method_ids_off
            << " class_defs_size: " << (unsigned int)headerItem->class_defs_size
            << " class_defs_off: " << (unsigned int)headerItem->class_defs_off
            << " data_size: " << (unsigned int)headerItem->data_size
            << " data_off: " << (unsigned int)headerItem->data_off
            << endl;
#endif

    ret = 0;
  } while (false);

  return ret;
}

int DexFile::parseStringIDs() {
  header_item* headerItem = &dexFormat_->header;
  uint32_t size = headerItem->string_ids_size;
  if (size > MAX_DEX_ITEM_COUNT) return -1;
  maxStringID_ = size - 1;

  try {
    dexFormat_->string_ids.reserve(size);
    string_id_item* item =
        (string_id_item*)((char*)dexFileBuf_ + headerItem->string_ids_off);
    for (int i = 0; i < size; i++) {
      dexFormat_->string_ids.push_back(item[i]);
    }
  } catch (bad_alloc& e) {
    cerr << "DexFile::parseStringIDs bad_alloc caught: " << e.what() << endl;
    return -1;
  }
#if 0  // def DEBUG_BUILD
    cout << "string count: " << size << endl;
    string str;
    for (int i = 0; i < size; i++) {
        assert(0 == getStringString(i, str));
        cout << "string[" << i << "]: " << str << endl;
    }
#endif
  return 0;
}

int DexFile::parseTypeIDs() {
  header_item* headerItem = &dexFormat_->header;
  uint32_t size = headerItem->type_ids_size;
  if (size > MAX_DEX_ITEM_COUNT) return -1;
  maxTypeID_ = size - 1;

  try {
    dexFormat_->type_ids.reserve(size);
    type_id_item* item =
        (type_id_item*)((char*)dexFileBuf_ + headerItem->type_ids_off);
    for (int i = 0; i < size; i++) {
      dexFormat_->type_ids.push_back(item[i]);
    }
  } catch (bad_alloc& e) {
    cerr << "DexFile::parseTypeIDs bad_alloc caught: " << e.what() << endl;
    return -1;
  }
#if 0  // def DEBUG_BUILD
    cout << "type count: " << size << endl;
    string str;
    for (int i = 0; i < size; i++) {
        assert(0 == getTypeString(i, str));
        cout << "type[" << i << "]: " << str << endl;
    }
#endif
  return 0;
}

int DexFile::parseProtoIDs() {
  header_item* headerItem = &dexFormat_->header;
  uint32_t size = headerItem->proto_ids_size;
  if (size > MAX_DEX_ITEM_COUNT) return -1;
  maxProtoID_ = size - 1;

  try {
    dexFormat_->proto_ids.reserve(size);
    proto_id_item* item =
        (proto_id_item*)((char*)dexFileBuf_ + headerItem->proto_ids_off);
    for (int i = 0; i < size; i++) {
      // assert(item[i].parameters_off != 0);
      dexFormat_->proto_ids.push_back(item[i]);
    }
  } catch (bad_alloc& e) {
    cerr << "DexFile::parseProtoIDs bad_alloc caught: " << e.what() << endl;
    return -1;
  }
#if 0  // def DEBUG_BUILD
    cout << "proto count: " << size << endl;
    for (int i = 0; i < size; i++) {
        ProtoInfo protoInfo;
        if (0 != getProtoInfo(i, protoInfo))
            continue;
        cout << "proto[" << i << "] shorty: " << protoInfo.shorty
            << " returnType: " << protoInfo.returnType
            << " parameters: ";
        for (int i = 0; i < protoInfo.parameters.size(); ++i) {
            cout << protoInfo.parameters[i] << " ";
        }
        cout << endl;
    }
#endif
  return 0;
}

int DexFile::parseFieldIDs() {
  header_item* headerItem = &dexFormat_->header;
  uint32_t size = headerItem->field_ids_size;
  if (size > MAX_DEX_ITEM_COUNT) return -1;
  maxFieldID_ = size - 1;

  try {
    dexFormat_->field_ids.reserve(size);
    field_id_item* item =
        (field_id_item*)((char*)dexFileBuf_ + headerItem->field_ids_off);
    for (int i = 0; i < size; i++) {
      dexFormat_->field_ids.push_back(item[i]);
    }
  } catch (bad_alloc& e) {
    cerr << "DexFile::parseFieldIDs bad_alloc caught: " << e.what() << endl;
    return -1;
  }
#if 0  // def DEBUG_BUILD
    cout << "field count: " << size << endl;
    for (int i = 0; i < size; i++) {
        FieldInfo fieldInfo;
        if (0 != getFieldInfo(i, fieldInfo))
            continue;
        cout << "field[" << i << "] classStr: " << fieldInfo.classStr
            << " type: " << fieldInfo.type
            << " name: " << fieldInfo.name
            << endl;
    }
#endif
  return 0;
}

int DexFile::parseMethodIDs() {
  header_item* headerItem = &dexFormat_->header;
  uint32_t size = headerItem->method_ids_size;
  if (size > MAX_DEX_ITEM_COUNT) return -1;
  maxMethodID_ = size - 1;

  try {
    dexFormat_->method_ids.reserve(size);
    method_id_item* item =
        (method_id_item*)((char*)dexFileBuf_ + headerItem->method_ids_off);
    for (int i = 0; i < size; i++) {
      dexFormat_->method_ids.push_back(item[i]);
    }
  } catch (bad_alloc& e) {
    cerr << "DexFile::parseMethodIDs bad_alloc caught: " << e.what() << endl;
    return -1;
  }
#if 0  // def DEBUG_BUILD
    cout << "method count: " << size << endl;
    for (int i = 0; i < size; i++) {
        MethodInfo methodInfo;
        if (0 != getMethodInfo(i, methodInfo))
            continue;
        cout << "method[" << i << "] classStr: " << methodInfo.classStr;
        cout << "[proto shorty: " << methodInfo.protoInfo.shorty
            << " returnType: " << methodInfo.protoInfo.returnType
            << " parameters: ";
        for (int i = 0; i < methodInfo.protoInfo.parameters.size(); ++i) {
            cout << methodInfo.protoInfo.parameters[i] << " ";
        }
        cout << "] name: " << methodInfo.name << endl;
    }
#endif
  return 0;
}

int DexFile::parseClassDefs() {
  header_item* headerItem = &dexFormat_->header;
  uint32_t size = headerItem->class_defs_size;
  if (size > MAX_DEX_ITEM_COUNT) return -1;
  maxClassDefID_ = size - 1;

  try {
    dexFormat_->class_defs.reserve(size);
    class_def_item* item =
        (class_def_item*)((char*)dexFileBuf_ + headerItem->class_defs_off);
    for (int i = 0; i < size; i++) {
      dexFormat_->class_defs.push_back(item[i]);
    }
    classDefsItor_ = dexFormat_->class_defs.begin();
  } catch (bad_alloc& e) {
    cerr << "DexFile::parseClassDefs bad_alloc caught: " << e.what() << endl;
    return -1;
  }
#if 0  // def DEBUG_BUILD
    cout << "class count: " << size << endl;
    for (int i = 0; i < size; i++) {
        ClassInfo classInfo;
        if (0 != getClassInfo(i, classInfo))
            continue;
        cout << "class[" << i << "] classStr: " << classInfo.classStr
            << " superClass: " << classInfo.superClass
            << " sourceFile: " << classInfo.sourceFile
            << endl;
    }
#endif
  return 0;
}
