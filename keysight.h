/*
* Created by Kuang Peng on 2018/4/8
*/

#ifndef KEYSIGHT_H
#define KEYSIGHT_H

#include <stdint.h>
#include "ns3/object.h"
#include "ns3/ptr.h"
#include "ns3/net-device.h"
#include "ns3/packet.h"

#define MAX_BF_NUM 3
#define MAX_BF_SIZE 16*1024*1024
#define DEFAULT_BF_MAX 1
#define BF_KEY_CONTAINER_SIZE 100000
//#define BF_KEY_POOL_SIZE  100000000
#define BF_KEY_POOL_SIZE  1000000

#define DEFAULT_PACKET_PER_WINDOW 100000
#define DEFAULT_WINDOW_NUM 4
#define DEFAULT_BUCKET_NUM 4

#define P4_ID 1

#if P4_ID == 0
#define KEYSIGHT_KEY switch_key_t
#define KEYSIGHT_KEY_EXTRACTOR keysight_extract_switch_key
#elif P4_ID == 1
#define KEYSIGHT_KEY router_key_t
#define KEYSIGHT_KEY_EXTRACTOR keysight_extract_router_key
#elif P4_ID == 2
#define KEYSIGHT_KEY nat_key_t
#define KEYSIGHT_KEY_EXTRACTOR keysight_extract_nat_key
#else
#define KEYSIGHT_KEY stateful_firewall_key_t
#define KEYSIGHT_KEY_EXTRACTOR keysight_extract_stateful_firewall_key
#endif

namespace ns3 {

	enum update_alg {
		BSBF = 0,
		BSBFSD,
		RLBSBF,
		STABLE_BF,
		IDEAL_BF,
		KEYSIGHT_SBF,
		KEYSIGHT_BSBF,
		KEYSIGHT_BSBFSD,
		KEYSIGHT_RLBSBF,
		KEYSIGHT_NEG_BSBF,
		KEYSIGHT_NEG_BSBFSD,
		KEYSIGHT_NEG_RLBSBF,
		UPDATE_ALG_NUM
	};

	extern char* BF_ALG_NAMES[];

	typedef struct switch_key_t {
		uint8_t eth_src_mac[6];
		uint8_t eth_dst_mac[6];
	} switch_key_t;

	typedef struct router_key_t {

		// ethertype
		uint8_t eth_src_mac[6];
		uint8_t eth_dst_mac[6];
		uint8_t eth_type[2];
		// ipv4
		uint8_t dst_addr[4];

	} router_key_t;

	typedef struct nat_key_t {
		uint8_t src_addr[4];
		uint8_t dst_addr[4];
		uint8_t proto[1];
		uint8_t src_port[2];
		uint8_t dst_port[2];

	} nat_key_t;

	typedef struct stateful_firewall_key_t {
		// ipv4
		uint8_t src_addr[4];
		uint8_t dst_addr[4];
		uint8_t proto[1];
		uint8_t tcp_ctrl[1];
		uint8_t src_port[2];
		uint8_t dst_port[2];
		// dependency here

	} stateful_firewall_key_t;

	typedef struct bf_key_t {
		KEYSIGHT_KEY key;
	} bf_key_t;

	typedef struct keysight_key_container_t {
		bf_key_t key;
		uint32_t packet_count;
		struct keysight_key_container_t * next;
	public:
		keysight_key_container_t() :packet_count(0), next(NULL) {}
	} keysight_key_container_t;

	typedef struct keysight_t {
		uint32_t packet_count;
		uint32_t postcard_count;
		uint32_t false_positive;
		uint32_t false_negative;
		uint32_t distinct_behavior_count;
		uint32_t random_seed;
		uint64_t bf[MAX_BF_NUM][MAX_BF_SIZE];
		uint32_t bf_len[MAX_BF_NUM];
		keysight_key_container_t key_container[BF_KEY_CONTAINER_SIZE];

		int enable;
		uint32_t bf_alg;
		uint32_t bf_size;
		uint32_t bf_num;
		uint32_t bf_max;
		uint32_t packet_per_window;
		uint32_t window_num;
		uint32_t bucket_num;

	public:
		keysight_t() :packet_count(0), postcard_count(0), false_positive(0),
			false_negative(0), distinct_behavior_count(0), random_seed(0) 
		{}
		keysight_t(uint32_t wbf_alg,uint32_t wbf_size,uint32_t wbf_num,uint32_t wbf_max,uint32_t wpacket_per_window,uint32_t wwindow_num,uint32_t wbucket_num)
			:packet_count(0), postcard_count(0), false_positive(0),
			false_negative(0), distinct_behavior_count(0), random_seed(0),
			bf_alg(wbf_alg),
			bf_size(wbf_size),bf_num(wbf_num),bf_max(wbf_max),
			packet_per_window(wpacket_per_window),window_num(wwindow_num),bucket_num(wbucket_num)
		{}
	} keysight_t;

#define BF_KEY_SIZE sizeof(struct bf_key_t)

	void keysight_count(keysight_t* ks, keysight_key_container_t* key_pool, int& pool_ptr, Ptr<const Packet> packet, uint16_t protocol, const Address &from, const Address &to);

}
#endif // !KEYSIGHT_H



