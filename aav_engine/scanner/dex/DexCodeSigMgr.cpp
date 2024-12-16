#include "DexCodeSigMgr.h"

#include <assert.h>

#include "BaseFormat.h"

#if defined(ANDROID_BUILD) && defined(DEBUG_BUILD)
#include <android/log.h>
#include <jni.h>

#endif

#include <iostream>
#include <new>

using namespace std;

DexCodeSigMgr::DexCodeSigMgr() {}

DexCodeSigMgr::~DexCodeSigMgr() { uninit(); }

int DexCodeSigMgr::init(ISigMgr* sigMgr) {
  if (NULL == sigMgr) return -1;

  int ret = -1;
  SIG_ITEM* opcodeMap = NULL;
  SIG_ITEM* opcodeCrcSig = NULL;
  SIG_ITEM* operandCrcSig = NULL;
  SIG_ITEM* codeLogicSig = NULL;
  do {
    if (0 != sigMgr->getData(BASE_FORMAT_DEX_OPCODE_MAP, &opcodeMap)) {
#if defined(ANDROID_BUILD) && defined(DEBUG_BUILD)
      __android_log_print(
          ANDROID_LOG_ERROR, "aaveng",
          "sigMgr failed to getData BASE_FORMAT_DEX_OPCODE_MAP");
#endif
      break;
    }

    if (0 != sigMgr->getData(BASE_FORMAT_DEX_OPCODE_CRC, &opcodeCrcSig)) {
#if defined(ANDROID_BUILD) && defined(DEBUG_BUILD)
      __android_log_print(
          ANDROID_LOG_ERROR, "aaveng",
          "sigMgr failed to getData BASE_FORMAT_DEX_OPCODE_CRC");
#endif
      break;
    }
    if (0 != sigMgr->getData(BASE_FORMAT_DEX_OPERAND_CRC, &operandCrcSig)) {
#if defined(ANDROID_BUILD) && defined(DEBUG_BUILD)
      __android_log_print(
          ANDROID_LOG_ERROR, "aaveng",
          "sigMgr failed to getData BASE_FORMAT_DEX_OPERAND_CRC");
#endif
      break;
    }

    if (0 != sigMgr->getData(BASE_FORMAT_DEX_CODE_LOGIC, &codeLogicSig)) {
#if defined(ANDROID_BUILD) && defined(DEBUG_BUILD)
      __android_log_print(
          ANDROID_LOG_ERROR, "aaveng",
          "sigMgr failed to getData BASE_FORMAT_DEX_CODE_LOGIC");
#endif
      break;
    }

    if (0 != parseOpcodeMap(opcodeMap)) {
#if defined(ANDROID_BUILD) && defined(DEBUG_BUILD)
      __android_log_print(ANDROID_LOG_ERROR, "aaveng",
                          "failed to parseOpcodeMap");
#endif
      break;
    }

    if (0 != parseOpcodeCrcSig(opcodeCrcSig)) {
#if defined(ANDROID_BUILD) && defined(DEBUG_BUILD)
      __android_log_print(ANDROID_LOG_ERROR, "aaveng",
                          "failed to parseOpcodeCrcSig");
#endif
      break;
    }
    if (0 != parseOperandCrcSig(operandCrcSig)) {
#if defined(ANDROID_BUILD) && defined(DEBUG_BUILD)
      __android_log_print(ANDROID_LOG_ERROR, "aaveng",
                          "failed to parseOperandCrcSig");
#endif
      break;
    }

    if (0 != parseCodeLogicSig(codeLogicSig)) {
#if defined(ANDROID_BUILD) && defined(DEBUG_BUILD)
      __android_log_print(ANDROID_LOG_ERROR, "aaveng",
                          "failed to parseCodeLogicSig");
#endif
      break;
    }

    ret = 0;
  } while (false);

  if (0 != ret) uninit();
  return ret;
}

int DexCodeSigMgr::uninit() {
  opcodeMap_.map01.reset();
  opcodeMap_.map23.reset();
  opcodeMap_.map45.reset();
  opcodeMap_.map67.reset();

  opcodeCrcSigArray_.clear();
  operandCrcSigArray_.clear();
  codeLogicSigArray_.clear();
  return 0;
}

int DexCodeSigMgr::searchOpcodeMap(const FastOpcodes* opcodes) {
  if (NULL == opcodes) return -1;

  if (!opcodeMap_.map01.test(opcodes->opcode01)) return -1;
  if (!opcodeMap_.map23.test(opcodes->opcode23)) return -1;
  if (!opcodeMap_.map45.test(opcodes->opcode45)) return -1;
  if (!opcodeMap_.map67.test(opcodes->opcode67)) return -1;

  return 0;
}

int DexCodeSigMgr::searchOpcodeCrc(uint32_t crc, DexCodeCrcSig** opcodeSig) {
  if (NULL == opcodeSig) return -1;
  if (0 == opcodeCrcSigArray_.size()) return -1;

  int l = 0;
  int r = opcodeCrcSigArray_.size() - 1;
  while (l <= r) {
    int m = (l + r) / 2;
    int v = opcodeCrcSigArray_[m].crc;
    if (v < crc)
      l = m + 1;
    else if (v > crc)
      r = m - 1;
    else {
      // printf("found at %d\n", m);
      *opcodeSig = &opcodeCrcSigArray_[m];
      return 0;
    }
  }
  return -1;
}

int DexCodeSigMgr::searchOperandCrc(uint32_t crc, DexCodeCrcSig** operandSig) {
  if (NULL == operandSig) return -1;
  if (0 == operandCrcSigArray_.size()) return -1;

  int l = 0;
  int r = operandCrcSigArray_.size() - 1;
  while (l <= r) {
    int m = (l + r) / 2;
    int v = operandCrcSigArray_[m].crc;
    if (v < crc)
      l = m + 1;
    else if (v > crc)
      r = m - 1;
    else {
      // printf("found at %d\n", m);
      *operandSig = &operandCrcSigArray_[m];
      return 0;
    }
  }
  return -1;
}

int DexCodeSigMgr::searchCodeLogic(uint32_t sigID, DexCodeLogicSig** logicSig) {
  if (NULL == logicSig) return -1;
  if (0 == codeLogicSigArray_.size()) return -1;

  int l = 0;
  int r = codeLogicSigArray_.size() - 1;
  while (l <= r) {
    int m = (l + r) / 2;
    int v = codeLogicSigArray_[m].sigID;
    if (v < sigID)
      l = m + 1;
    else if (v > sigID)
      r = m - 1;
    else {
      // printf("found at %d\n", m);
      *logicSig = &codeLogicSigArray_[m];
      return 0;
    }
  }
  return -1;
}

int DexCodeSigMgr::parseOpcodeMap(const SIG_ITEM* opcodeMapItem) {
  assert(NULL != opcodeMapItem);
  assert(BASE_FORMAT_DEX_OPCODE_MAP == opcodeMapItem->format);
  assert((FAST_OPCODES_COUNT / 2) == opcodeMapItem->sigCount);
  assert(NULL != opcodeMapItem->buf);
  assert(((BIT_MAP_SIZE / 8) * (FAST_OPCODES_COUNT / 2)) ==
         opcodeMapItem->bufSize);

  if (NULL == opcodeMapItem) return -1;
  if (BASE_FORMAT_DEX_OPCODE_MAP != opcodeMapItem->format) return -1;
  if ((FAST_OPCODES_COUNT / 2) != opcodeMapItem->sigCount) return -1;
  if (NULL == opcodeMapItem->buf) return -1;
  if (((BIT_MAP_SIZE / 8) * (FAST_OPCODES_COUNT / 2)) != opcodeMapItem->bufSize)
    return -1;

  DEX_OPCODE_MAP* opcodeMap = (DEX_OPCODE_MAP*)(opcodeMapItem->buf);
  const uint8_t* map01 = (uint8_t*)(opcodeMap->map01);
  const uint8_t* map23 = (uint8_t*)(opcodeMap->map23);
  const uint8_t* map45 = (uint8_t*)(opcodeMap->map45);
  const uint8_t* map67 = (uint8_t*)(opcodeMap->map67);

  if (0 != prepareOpcodeMap(map01, opcodeMap_.map01)) return -1;
  if (0 != prepareOpcodeMap(map23, opcodeMap_.map23)) return -1;
  if (0 != prepareOpcodeMap(map45, opcodeMap_.map45)) return -1;
  if (0 != prepareOpcodeMap(map67, opcodeMap_.map67)) return -1;

  return 0;
}

int DexCodeSigMgr::parseOpcodeCrcSig(const SIG_ITEM* opcodeCrcSigItem) {
  assert(NULL != opcodeCrcSigItem);
  assert(BASE_FORMAT_DEX_OPCODE_CRC == opcodeCrcSigItem->format);
  assert(NULL != opcodeCrcSigItem->buf);

  if (NULL == opcodeCrcSigItem) return -1;
  if (BASE_FORMAT_DEX_OPCODE_CRC != opcodeCrcSigItem->format) return -1;
  if (0 == opcodeCrcSigItem->sigCount) {
    cout << "warning: opcode crc sig count is zero!" << endl;
    return -1;
  }
  if (NULL == opcodeCrcSigItem->buf) return -1;
  if (0 == opcodeCrcSigItem->bufSize) {
    cout << "warning: opcode crc sig buf size is zero!" << endl;
    return -1;
  }

  DEX_CODE_CRC_SIG* codeCrcSig = (DEX_CODE_CRC_SIG*)opcodeCrcSigItem->buf;
  try {
    opcodeCrcSigArray_.reserve(opcodeCrcSigItem->sigCount);
    for (int i = 0; i < opcodeCrcSigItem->sigCount; i++) {
      DexCodeCrcSig opcodeSig;
      opcodeSig.crc = codeCrcSig->crc;
      assert(codeCrcSig->sig_id_count > 0);
      opcodeSig.sigIDs.reserve(codeCrcSig->sig_id_count);
      for (int j = 0; j < codeCrcSig->sig_id_count; j++)
        opcodeSig.sigIDs.push_back(codeCrcSig->sig_ids[j]);
      opcodeCrcSigArray_.push_back(opcodeSig);

      char* cur = (char*)codeCrcSig;
      cur += (sizeof(DEX_CODE_CRC_SIG) - sizeof(uint32_t) +
              codeCrcSig->sig_id_count * sizeof(uint32_t));
      codeCrcSig = (DEX_CODE_CRC_SIG*)cur;
      assert(cur <= ((char*)opcodeCrcSigItem->buf + opcodeCrcSigItem->bufSize));
    }
  } catch (bad_alloc& e) {
    cerr << "DexCodeSigMgr::parseOpcodeCrcSig bad_alloc caught: " << e.what()
         << endl;
    return -1;
  }
  return 0;
}

int DexCodeSigMgr::parseOperandCrcSig(const SIG_ITEM* operandCrcSigItem) {
  assert(NULL != operandCrcSigItem);
  assert(BASE_FORMAT_DEX_OPERAND_CRC == operandCrcSigItem->format);
  assert(NULL != operandCrcSigItem->buf);

  if (NULL == operandCrcSigItem) return -1;
  if (BASE_FORMAT_DEX_OPERAND_CRC != operandCrcSigItem->format) return -1;
  if (0 == operandCrcSigItem->sigCount) {
    cout << "warning: operand crc sig count is zero!" << endl;
    return -1;
  }
  if (NULL == operandCrcSigItem->buf) return -1;
  if (0 == operandCrcSigItem->bufSize) {
    cout << "warning: operand crc sig buf size is zero!" << endl;
    return -1;
  }

  DEX_CODE_CRC_SIG* codeCrcSig = (DEX_CODE_CRC_SIG*)operandCrcSigItem->buf;
  try {
    operandCrcSigArray_.reserve(operandCrcSigItem->sigCount);
    for (int i = 0; i < operandCrcSigItem->sigCount; i++) {
      DexCodeCrcSig operandSig;
      operandSig.crc = codeCrcSig->crc;
      assert(codeCrcSig->sig_id_count > 0);
      operandSig.sigIDs.reserve(codeCrcSig->sig_id_count);
      for (int j = 0; j < codeCrcSig->sig_id_count; j++)
        operandSig.sigIDs.push_back(codeCrcSig->sig_ids[j]);
      operandCrcSigArray_.push_back(operandSig);

      char* cur = (char*)codeCrcSig;
      cur += (sizeof(DEX_CODE_CRC_SIG) - sizeof(uint32_t) +
              codeCrcSig->sig_id_count * sizeof(uint32_t));
      codeCrcSig = (DEX_CODE_CRC_SIG*)cur;
      assert(cur <=
             ((char*)operandCrcSigItem->buf + operandCrcSigItem->bufSize));
    }
  } catch (bad_alloc& e) {
    cerr << "DexCodeSigMgr::parseOperandCrcSig bad_alloc caught: " << e.what()
         << endl;
    return -1;
  }
  return 0;
}

int DexCodeSigMgr::parseCodeLogicSig(const SIG_ITEM* codeLogicSigItem) {
  assert(NULL != codeLogicSigItem);
  assert(BASE_FORMAT_DEX_CODE_LOGIC == codeLogicSigItem->format);
  assert(NULL != codeLogicSigItem->buf);

  if (NULL == codeLogicSigItem) return -1;
  if (BASE_FORMAT_DEX_CODE_LOGIC != codeLogicSigItem->format) return -1;
  if (0 == codeLogicSigItem->sigCount) {
    cout << "warning: code logic sig count is zero!" << endl;
    return -1;
  }
  if (NULL == codeLogicSigItem->buf) return -1;
  if (0 == codeLogicSigItem->bufSize) {
    cout << "warning: code logic sig buf size is zero!" << endl;
    return -1;
  }

  DEX_CODE_LOGIC_SIG* codeLogicSig = (DEX_CODE_LOGIC_SIG*)codeLogicSigItem->buf;
  try {
    codeLogicSigArray_.reserve(codeLogicSigItem->sigCount);
    for (int i = 0; i < codeLogicSigItem->sigCount; i++) {
      char* cur = (char*)codeLogicSig;
      DexCodeLogicSig logicSig;

      logicSig.sigID = codeLogicSig->sig_id;
      cur += sizeof(uint32_t);

      LOGIC_CRCS* notCrcs = (LOGIC_CRCS*)cur;
      assert(notCrcs->crc_count >= 0 && notCrcs->crc_count <= 4);
      logicSig.notCrcs.reserve(notCrcs->crc_count);
      for (int j = 0; j < notCrcs->crc_count; j++)
        logicSig.notCrcs.push_back(notCrcs->crcs[j]);
      cur += (sizeof(LOGIC_CRCS) - sizeof(uint32_t) +
              notCrcs->crc_count * sizeof(uint32_t));

      LOGIC_CRCS* xorCrcs = (LOGIC_CRCS*)cur;
      assert(xorCrcs->crc_count >= 0 && xorCrcs->crc_count <= 4);
      logicSig.xorCrcs.reserve(xorCrcs->crc_count);
      for (int j = 0; j < xorCrcs->crc_count; j++)
        logicSig.xorCrcs.push_back(xorCrcs->crcs[j]);
      cur += (sizeof(LOGIC_CRCS) - sizeof(uint32_t) +
              xorCrcs->crc_count * sizeof(uint32_t));

      LOGIC_CRCS* andCrcs = (LOGIC_CRCS*)cur;
      assert(andCrcs->crc_count != 1 &&
             (andCrcs->crc_count >= 0 && andCrcs->crc_count <= 4));
      logicSig.andCrcs.reserve(andCrcs->crc_count);
      for (int j = 0; j < andCrcs->crc_count; j++)
        logicSig.andCrcs.push_back(andCrcs->crcs[j]);
      cur += (sizeof(LOGIC_CRCS) - sizeof(uint32_t) +
              andCrcs->crc_count * sizeof(uint32_t));

      LOGIC_CRCS* orCrcs = (LOGIC_CRCS*)cur;
      assert(orCrcs->crc_count >= 0 && orCrcs->crc_count <= 4);
      logicSig.orCrcs.reserve(orCrcs->crc_count);
      for (int j = 0; j < orCrcs->crc_count; j++)
        logicSig.orCrcs.push_back(orCrcs->crcs[j]);
      cur += (sizeof(LOGIC_CRCS) - sizeof(uint32_t) +
              orCrcs->crc_count * sizeof(uint32_t));

      codeLogicSigArray_.push_back(logicSig);
      codeLogicSig = (DEX_CODE_LOGIC_SIG*)cur;
      assert(cur <= ((char*)codeLogicSigItem->buf + codeLogicSigItem->bufSize));
    }
  } catch (bad_alloc& e) {
    cerr << "DexCodeSigMgr::parseCodeLogicSig bad_alloc caught: " << e.what()
         << endl;
    return -1;
  }
  return 0;
}

int DexCodeSigMgr::prepareOpcodeMap(const uint8_t* mapInFile,
                                    bitset<BIT_MAP_SIZE>& mapInMem) {
  assert(NULL != mapInFile);

  uint32_t* start = (uint32_t*)mapInFile;
  for (int i = 0; i < BIT_MAP_SIZE / (8 * 4); i++) {
    uint32_t base = 8 * 4 * i;
    uint32_t value = start[i];
    uint32_t mask = 0x01;
    for (int j = 0; j < 8 * 4; j++) {
      if (0 != (value & mask)) {
        int pos = base + j;
        mapInMem.set(pos);
      }
      mask <<= 1;
    }
  }

  return 0;
}
