#include "keysight_para.h"

namespace ns3 {
	uint32_t KeysightPara::g_BF_ALG = BSBF;
	uint32_t KeysightPara::g_BF_SIZE = MAX_BF_SIZE;
	uint32_t KeysightPara::g_BF_NUM = MAX_BF_NUM;
	uint32_t KeysightPara::g_BF_MAX = DEFAULT_BF_MAX;
	uint32_t KeysightPara::g_PACKET_PER_WINDOW = DEFAULT_PACKET_PER_WINDOW;
	uint32_t KeysightPara::g_WINDOW_NUM = DEFAULT_WINDOW_NUM;
	uint32_t KeysightPara::g_BUCKET_NUM = DEFAULT_BUCKET_NUM;
}
