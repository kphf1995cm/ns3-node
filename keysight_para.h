#ifndef KEYSIGHT_PARA_H
#define KEYSIGHT_PARA_H
#include <iostream>
#include "keysight.h"

namespace ns3 {
	class KeysightPara {
	public:
		static uint32_t g_BF_ALG;
		static uint32_t g_BF_SIZE;
		static uint32_t g_BF_NUM;
		static uint32_t g_BF_MAX;
		static uint32_t g_PACKET_PER_WINDOW;
		static uint32_t g_WINDOW_NUM;
		static uint32_t g_BUCKET_NUM;
	};

}

#endif

