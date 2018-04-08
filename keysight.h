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

#define BF_NUM 3
#define BF_SIZE 64000
#define BF_STATE 1
#define BF_KEY_CONTAINER_SIZE 100000
#define BF_KEY_POOL_SIZE  100000000

#define WINDOW_SIZE 100000
#define WINDOW_NUM 8
#define WINDOW_DEL 1

#define P4_ID 2

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

#define UPDATE_ALG KEYSIGHT_BSBFSD

namespace ns3 {

	enum update_alg {
		BSBF = 0,
		BSBFSD,
		RLBSBF,
		KEYSIGHT_BSBF,
		KEYSIGHT_BSBFSD,
		KEYSIGHT_RLBSBF,
		KEYSIGHT_NEG_BSBF,
		KEYSIGHT_NEG_BSBFSD,
		KEYSIGHT_NEG_RLBSBF,
		UPDATE_ALG_NUM
	};

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

	typedef struct stateful_firewall_key {
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
	} keysight_key_container_t;

	typedef struct keysight_t {
		uint32_t packet_count;
		uint32_t postcard_count;
		uint32_t false_positive;
		uint32_t false_negative;
		uint32_t distinct_behavior_count;
		uint32_t random_seed;
		int bf[BF_NUM][BF_SIZE];
		uint32_t bf_len[BF_NUM];
		keysight_key_container_t key_container[BF_KEY_CONTAINER_SIZE];
	} keysight_t;

#define BF_KEY_SIZE sizeof(struct bf_key_t)

	void keysight_count(keysight_t* ks, keysight_key_container_t* key_pool,int& pool_ptr,Ptr<const Packet> packet, uint16_t protocol,const Address &from, const Address &to);

	void keysight_sbf_count(keysight_t* ks,keysight_key_container_t* key_pool, int& pool_ptr,Ptr<const Packet> packet, uint16_t protocol, const Address &from, const Address &to);

}
#endif // !KEYSIGHT_H


