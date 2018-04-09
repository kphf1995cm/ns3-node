/*
* Created by Kuang Peng on 2018/4/9
*/

#ifndef TUPLE_H
#define TUPLE_H

#include <stdint.h>
#include "ns3/object.h"
#include "ns3/ptr.h"
#include "ns3/net-device.h"
#include "ns3/packet.h"

#define TP_KEY_CONTAINER_SIZE 100000
#define TP_KEY_POOL_SIZE  100000000

namespace ns3 {

	typedef struct tuple_key_t {

		uint8_t src_addr[4];
		uint8_t dst_addr[4];
		uint8_t proto[1];
		uint8_t src_port[2];
		uint8_t dst_port[2];

	} tuple_key_t;

#define TP_KEY_SIZE sizeof(struct tuple_key_t)

	typedef struct tuple_key_container_t {
		tuple_key_t key;
		uint32_t packet_count;
		struct tuple_key_container_t * next;
	} tuple_key_container_t;

	typedef struct tuple_t {
		uint32_t packet_count;
		tuple_key_container_t key_container[TP_KEY_CONTAINER_SIZE];
	} tuple_t;

	void tuple_count(tuple_t* tp, tuple_key_container_t* key_pool, int& pool_ptr, Ptr<const Packet> packet, uint16_t protocol, const Address &from, const Address &to);

}

#endif // !TUPLE_H



