/*
* Created by Kuang Peng on 2018/4/8
*/

#include <memory.h>
#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
#include <time.h>
#include <iostream>
#include "tuple.h"
#include "ns3/key-hash.h"
#include "net-device.h"

namespace ns3 {

	/*
	static int
		tuple_lookup(tuple_t* tp, tuple_key_t* key) {
		int idx = hash_crc32(key, TP_KEY_SIZE, CRC32) % TP_KEY_CONTAINER_SIZE;
		tuple_key_container_t * tc = &tp->key_container[idx];
		while (tc->next != NULL) {
			tc = tc->next;
			if (key_compare((uint8_t*)&tc->key, (uint8_t*)key, TP_KEY_SIZE) == 0) {
				return 1;
			}
		}
		return 0;
	}
	*/

	static void
		tuple_insert(tuple_t* tp, tuple_key_t* key, tuple_key_container_t* key_pool, int& pool_ptr) {
		int idx = hash_crc32(key, TP_KEY_SIZE, CRC32) % TP_KEY_CONTAINER_SIZE;
		tuple_key_container_t * tc = &tp->key_container[idx];
		while (tc->next != NULL) {
			tc = tc->next;
			if (key_compare((uint8_t*)&tc->key, (uint8_t*)key, TP_KEY_SIZE) == 0) {
				tc->packet_count++;
				return;
			}
		}

		if (tc->next == NULL) {
			tc->next = &key_pool[pool_ptr++];
			tc = tc->next;
			tc->key = *key;
			tc->packet_count=1;
			tc->next = NULL;
			tp->distinct_flow_count++;
		}
	}

	static tuple_key_t
		tuple_extract_key(Ptr<const Packet> packet, uint16_t protocol, const Address &from, const Address &to) {

		tuple_key_t key = {};

		memset(key.src_port, 0, 2);
		memset(key.dst_port, 0, 2);

		uint32_t pkt_size = packet->GetSize();
		uint8_t* pkt = new uint8_t[pkt_size];
		packet->CopyData(pkt, pkt_size);

		memcpy(key.proto, &pkt[9], 1);
		memcpy(key.src_addr, &pkt[12], 4);
		memcpy(key.dst_addr, &pkt[16], 4);

		if (key.proto[0] == 0x06) {//tcp
			memcpy(key.src_port, &pkt[20], 2);
			memcpy(key.dst_port, &pkt[22], 2);
		}
		else if (key.proto[0] == 0x11) {//udp
			memcpy(key.src_port, &pkt[20], 2);
			memcpy(key.dst_port, &pkt[22], 2);
		}

		delete pkt;
		return key;
	}


	void tuple_count(tuple_t* tp, tuple_key_container_t* key_pool, int& pool_ptr, Ptr<const Packet> packet, uint16_t protocol, const Address &from, const Address &to)
	{
		tuple_key_t key = tuple_extract_key(packet, protocol, from, to);
		tp->packet_count++;
		tuple_insert(tp, &key, key_pool, pool_ptr);
	}

	static uint32_t get_key_value(const uint8_t* key, int size)
	{
		uint32_t res = 0;
		for (int i = 0; i < size; i++)
		{
			res = (res << 8) + key[i];
		}
		return res;
	}

	std::ostream & operator<< (std::ostream&os, const tuple_key_t& tk)
	{
		os << "src_addr:" << get_key_value(tk.src_addr, 4) << " dst_addr:" << get_key_value(tk.dst_addr, 4);
		os << " src_port:" << get_key_value(tk.src_port, 2) << " dst_port:" << get_key_value(tk.dst_port, 2);
		os << " protocol:" << get_key_value(tk.proto, 1);
		return os;
	}

}
