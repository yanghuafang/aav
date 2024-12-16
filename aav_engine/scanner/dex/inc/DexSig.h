#ifndef _DEXSIG_H_
#define _DEXSIG_H_

#include <stdint.h>

#include <vector>
using namespace std;

#define BIT_MAP_SIZE 65536
#define ALIGN_SIZE4(s) (((s) + 3) & ~3)

enum STR_MATCH_TYPE {
  STR_MATCH_TYPE_UNKNOWN = 0,
  STR_MATCH_TYPE_EQUAL,
  STR_MATCH_TYPE_START_WITH,
  STR_MATCH_TYPE_END_WITH,
  STR_MATCH_TYPE_CONTAIN,
  STR_MATCH_TYPE_END_UNKNOWN,
};

enum LOGIC_MATCH_TYPE {
  LOGIC_MATCH_TYPE_UNKNOWN = 0,
  LOGIC_MATCH_TYPE_AND,
  LOGIC_MATCH_TYPE_OR,
  LOGIC_MATCH_TYPE_XOR,
  LOGIC_MATCH_TYPE_NOT,
  LOGIC_MATCH_TYPE_END_UNKNOWN,
};

#pragma pack(push, 1)

struct DEX_PATH_SIG {
  uint32_t sig_id;
  uint8_t str_match_type;    // enum STR_MATCH_TYPE
  uint8_t logic_match_type;  // enum LOGIC_MATCH_TYPE
  uint16_t path_max_layer;   // count of CRC
  uint32_t path_crcs[1];
};

struct DEX_OPCODE_MAP {
  uint8_t map01[BIT_MAP_SIZE / 8];
  uint8_t map23[BIT_MAP_SIZE / 8];
  uint8_t map45[BIT_MAP_SIZE / 8];
  uint8_t map67[BIT_MAP_SIZE / 8];
};

struct DEX_CODE_CRC_SIG {
  uint32_t crc;
  uint32_t sig_id_count;
  uint32_t sig_ids[1];
};

struct LOGIC_CRCS {
  uint32_t crc_count;
  uint32_t crcs[1];
};

struct DEX_CODE_LOGIC_SIG {
  uint32_t sig_id;
  struct LOGIC_CRCS not_crcs;
  struct LOGIC_CRCS xor_crcs;
  struct LOGIC_CRCS and_crcs;
  struct LOGIC_CRCS or_crcs;
};

#pragma pack(pop)

#endif
