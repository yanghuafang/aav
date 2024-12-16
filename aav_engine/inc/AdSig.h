#ifndef _ADSIG_H_
#define _ADSIG_H_

#include <stdint.h>

enum AD_TYPE {
  AD_TYPE_UNKNOWN = 0,
  AD_TYPE_BANNER,
  AD_TYPE_FULL_SCREEN,
  AD_TYPE_INTERSTITIAL_SCREEN,
  AD_TYPE_VIDEO,
  AD_TYPE_RICH_MEDIA,
  AD_TYPE_WALL,
  AD_TYPE_NOTIFY,
};

enum RISK_LEVEL {
  RISK_LEVEL_UNKNOWN = 0,
  RISK_LEVEL_NO_AD,
  RISK_LEVEL_SAFE_AD,
  RISK_LEVEL_RISK_AD,
  RISK_LEVEL_MALWARE_AD,
};

#pragma pack(push, 1)

struct AD_INFO {
  uint32_t sig_id;
  uint8_t ad_type_count;
  uint8_t ad_types[1];
  uint8_t ad_action_count;
  uint8_t ad_actions[1];
  uint8_t risk_level;
  uint8_t ad_id[1];
  uint8_t ad_en_name[1];
  uint8_t ad_zh_name[1];
};

#pragma pack(pop)

#endif
