/*
 * Created by Kuang Peng on 2018/4/8
 */

#include <memory.h>
#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
#include <time.h>
#include <iostream>
#include "ns3/keysight.h"
#include "ns3/key-hash.h"
#include "net-device.h"

namespace ns3 {

	static int
		keysight_lookup(keysight_t* ks, bf_key_t* key) {
		int idx = hash_crc32(key, BF_KEY_SIZE, CRC32) % BF_KEY_CONTAINER_SIZE;
		keysight_key_container_t * kc = &ks->key_container[idx];
		while (kc->next != NULL) {
			kc = kc->next;
			if (key_compare((uint8_t*)&kc->key, (uint8_t*)key, BF_KEY_SIZE) == 0) {
				return 1;
			}
		}
		return 0;
	}

	static void
		keysight_insert(keysight_t* ks, bf_key_t* key, int count_flag, keysight_key_container_t* key_pool, int& pool_ptr) {
		int idx = hash_crc32(key, BF_KEY_SIZE, CRC32) % BF_KEY_CONTAINER_SIZE;
		keysight_key_container_t * kc = &ks->key_container[idx];
		while (kc->next != NULL) {
			kc = kc->next;
			if (key_compare((uint8_t*)&kc->key, (uint8_t*)key, BF_KEY_SIZE) == 0) {
				kc->packet_count++;
				if (count_flag == 1) {
					ks->false_negative++;
				}
				return;
			}
		}

		if (kc->next == NULL) {
			kc->next = &key_pool[pool_ptr++];
			kc = kc->next;
			kc->key = *key;
			kc->next = NULL;
			ks->distinct_behavior_count++;
		}
	}

#if P4_ID==0
	static switch_key_t
		keysight_extract_switch_key(Ptr<const Packet> packet, uint16_t protocol, const Address &from, const Address &to) {

		switch_key_t key = {};

		Mac48Address eth_src_mac = Mac48Address::ConvertFrom(from);
		Mac48Address eth_dst_mac = Mac48Address::ConvertFrom(to);
		
		memcpy(key.eth_src_mac, eth_src_mac.m_address, 6);
		memcpy(key.eth_dst_mac, eth_dst_mac.m_address, 6);

		return key;
	}
#endif
#if P4_ID==1
	static router_key_t
		keysight_extract_router_key(Ptr<const Packet> packet, uint16_t protocol, const Address &from, const Address &to) {

		router_key_t key = {};

		Mac48Address eth_src_mac = Mac48Address::ConvertFrom(from);
		Mac48Address eth_dst_mac = Mac48Address::ConvertFrom(to);

		memcpy(key.eth_src_mac, eth_src_mac.m_address, 6);
		memcpy(key.eth_dst_mac, eth_dst_mac.m_address, 6);

		memcpy(key.eth_type, &protocol, 2);

		//TO DO: find a better way to get packet data
		uint32_t pkt_size = packet->GetSize();
		uint8_t* pkt = new uint8_t[pkt_size];
		packet->CopyData(pkt, pkt_size);

		memcpy(key.dst_addr, &pkt[16], 4);
		delete pkt;

		return key;
	}
#endif
#if P4_ID==3
	static stateful_firewall_key_t
		keysight_extract_stateful_firewall_key(Ptr<const Packet> packet, uint16_t protocol, const Address &from, const Address &to) {

		stateful_firewall_key_t key = {};

		memset(key.tcp_ctrl,0,1);
		memset(key.src_port,0,2);
		memset(key.dst_port,0,2);

		uint32_t pkt_size = packet->GetSize();
		uint8_t* pkt = new uint8_t[pkt_size];
		packet->CopyData(pkt, pkt_size);

		memcpy(key.proto, &pkt[9], 1);
		memcpy(key.src_addr, &pkt[12], 4);
		memcpy(key.dst_addr, &pkt[16], 4);

		if (key.proto[0]==0x06) {//tcp
			memcpy(key.src_port, &pkt[20], 2);
			memcpy(key.dst_port, &pkt[22], 2);
			memcpy(key.tcp_ctrl, &pkt[33], 1);//ctrl 6b
			key.tcp_ctrl[0] = key.tcp_ctrl[0] & 0x3f;// set zero for first two bits
		}
		else if (key.proto[0]==0x11) {//udp
			memcpy(key.src_port, &pkt[20], 2);
			memcpy(key.dst_port, &pkt[22], 2);
		}

		delete pkt;
		return key;
	}
#endif
#if P4_ID==2
	static nat_key_t
		keysight_extract_nat_key(Ptr<const Packet> packet, uint16_t protocol, const Address &from, const Address &to) {

		nat_key_t key = {};

		memset(key.src_port,0,2);
                memset(key.dst_port,0,2);

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
#endif
	static void
		bsbf_update(keysight_t* ks, int count_flag) {
		if (count_flag != 1) {
			return;
		}
		srand(ks->random_seed);
		int i;
		for (i = 0; i < BF_NUM; i++) {
			ks->bf[i][rand() % BF_SIZE] = 0;
		}
		ks->random_seed = (uint32_t)rand() + time(NULL);
	}

	static void
		bsbfsd_update(keysight_t* ks, int count_flag) {
		srand(ks->random_seed);
		ks->bf[rand() % BF_NUM][rand() % BF_SIZE] = 0;
		ks->random_seed = (uint32_t)rand() + time(NULL);
	}

	static void
		rlbsbf_update(keysight_t* ks, int count_flag) {
		if (count_flag != 1) {
			return;
		}
		srand(ks->random_seed);
		int i;
		for (i = 0; i < BF_NUM; i++) {
			if (ks->bf_len[i] > (uint32_t)(rand() % BF_SIZE)) {
				ks->bf[i][rand() % BF_SIZE] = 0;
			}
		}
		ks->random_seed = (uint32_t)rand() + time(NULL);
	}

	static void
		keysight_bsbfsd_update(keysight_t* ks, int count_flag) {
		if (count_flag != 1) {
			return;
		}
		srand(ks->random_seed);
		if (count_flag == 1) {
			ks->bf[rand() % BF_NUM][rand() % BF_SIZE] = 0;
		}
		else if (count_flag == 2) {
			if (rand() % 100 < 100) {
				ks->bf[rand() % BF_NUM][rand() % BF_SIZE] = 0;
			}
		}
		ks->random_seed = (uint32_t)rand() + time(NULL);
	}


	static void
		keysight_bsbf_update(keysight_t* ks, int count_flag) {
		srand(ks->random_seed);
		int i;
		if (count_flag == 1) {
			for (i = 0; i < BF_NUM; i++) {
				ks->bf[i][rand() % BF_SIZE] = 0;
			}
		}
		else if (count_flag == 2) {
			for (i = 0; i < BF_NUM; i++) {
				ks->bf[i][rand() % BF_SIZE] = 0;
			}
		}

		ks->random_seed = (uint32_t)rand() + time(NULL);
	}

	static void
		keysight_rlbsbf_update(keysight_t* ks, int count_flag) {
		srand(ks->random_seed);
		int i;
		if (count_flag == 1) {
			for (i = 0; i < BF_NUM; i++) {
				if (ks->bf_len[i] > (uint32_t)(rand() % BF_SIZE)) {
					ks->bf[i][rand() % BF_SIZE] = 0;
				}
			}
		}
		else if (count_flag == 2) {
			if (rand() % 100 < 100) {
				for (i = 0; i < BF_NUM; i++) {
					if (ks->bf_len[i] > (uint32_t)(rand() % BF_SIZE)) {
						ks->bf[i][rand() % BF_SIZE] = 0;
					}
				}
			}
		}

		ks->random_seed = (uint32_t)rand() + time(NULL);
	}

	static void
		keysight_neg_bsbfsd_update(keysight_t* ks, int count_flag) {
		srand(ks->random_seed);
		if (count_flag == 1) {
			ks->bf[rand() % BF_NUM][rand() % BF_SIZE] = 0;
		}
		else if (count_flag == 2) {
			if (rand() % 100 < 100) {
				ks->bf[rand() % BF_NUM][rand() % BF_SIZE] = 0;
			}
		}
		else if (ks->false_negative * 100.0 / ks->distinct_behavior_count < 20) {
			ks->bf[rand() % BF_NUM][rand() % BF_SIZE] = 0;
		}
		ks->random_seed = (uint32_t)rand() + time(NULL);
	}


	static void
		keysight_neg_bsbf_update(keysight_t* ks, int count_flag) {
		srand(ks->random_seed);
		int i;
		if (count_flag == 1) {
			for (i = 0; i < BF_NUM; i++) {
				ks->bf[i][rand() % BF_SIZE] = 0;
			}
		}
		else if (count_flag == 2) {
			for (i = 0; i < BF_NUM; i++) {
				ks->bf[i][rand() % BF_SIZE] = 0;
			}
		}
		else if (ks->false_negative * 100.0 / ks->distinct_behavior_count < 20) {
			for (i = 0; i < BF_NUM; i++) {
				ks->bf[i][rand() % BF_SIZE] = 0;
			}
		}

		ks->random_seed = (uint32_t)rand() + time(NULL);
	}

	static void
		keysight_neg_rlbsbf_update(keysight_t* ks, int count_flag) {
		srand(ks->random_seed);
		int i;
		if (count_flag == 1) {
			for (i = 0; i < BF_NUM; i++) {
				if (ks->bf_len[i] > (uint32_t)(rand() % BF_SIZE)) {
					ks->bf[i][rand() % BF_SIZE] = 0;
				}
			}
		}
		else if (count_flag == 2) {
			if (rand() % 100 < 100) {
				for (i = 0; i < BF_NUM; i++) {
					if (ks->bf_len[i] > (uint32_t)(rand() % BF_SIZE)) {
						ks->bf[i][rand() % BF_SIZE] = 0;
					}
				}
			}
		}
		else if (ks->false_negative * 100.0 / ks->distinct_behavior_count < 20) {
			for (i = 0; i < BF_NUM; i++) {
				ks->bf[i][rand() % BF_SIZE] = 0;
			}
		}

		ks->random_seed = (uint32_t)rand() + time(NULL);
	}

	typedef void(*update_func_t)(keysight_t *, int);

	update_func_t update_funcs[UPDATE_ALG_NUM] = {
		bsbf_update,
		bsbfsd_update,
		rlbsbf_update,
		keysight_bsbf_update,
		keysight_bsbfsd_update,
		keysight_rlbsbf_update,
		keysight_neg_bsbf_update,
		keysight_neg_bsbfsd_update,
		keysight_neg_rlbsbf_update
	};

	bf_key_t
		keysight_extract_key(Ptr<const Packet> packet, uint16_t protocol, const Address &from, const Address &to) {
		bf_key_t key = {
			.key = KEYSIGHT_KEY_EXTRACTOR(packet,protocol,from,to),
		};
		return key;
	}

	
	void keysight_count(keysight_t* ks,keysight_key_container_t* key_pool, int& pool_ptr, Ptr<const Packet> packet, uint16_t protocol, const Address &from, const Address &to)
	{
		int count_flag = 0;
		int i;
		bf_key_t key = keysight_extract_key(packet, protocol, from, to);
		ks->packet_count++;

		for (i = 0; i < BF_NUM; i++) {
			uint32_t idx = hash_crc32(&key, BF_KEY_SIZE, i) % BF_SIZE;
			if (ks->bf[i][idx] < BF_STATE) {
				ks->bf[i][idx]++;
				ks->bf_len[i]++;
				count_flag = 1;
			}
		}

		if (count_flag == 1) {
			ks->postcard_count++;
		}

		if (count_flag == 0) {
			if (keysight_lookup(ks, &key) == 0) {
				ks->false_positive++;
				count_flag = 2;
			}
		}
		update_funcs[UPDATE_ALG](ks, count_flag);
		keysight_insert(ks, &key, count_flag, key_pool,pool_ptr);

	}

	void keysight_sbf_count(keysight_t* ks, keysight_key_container_t* key_pool, int& pool_ptr, Ptr<const Packet> packet, uint16_t protocol, const Address &from, const Address &to)
	{
		int count_flag = 0;
		int i;
		bf_key_t key = keysight_extract_key(packet,protocol,from,to);
		ks->packet_count++;
		int window = (ks->packet_count / WINDOW_SIZE) % WINDOW_NUM;

		for (i = 0; i < BF_NUM; i++) {
			uint32_t idx = hash_crc32(&key, BF_KEY_SIZE, i) % BF_SIZE;
			if (ks->bf[i][idx] == 0) {
				count_flag = 1;
			}
			ks->bf[i][idx] = 1 << window;
			int j;
			for (j = 1; j <= WINDOW_DEL; j++) {
				int offset = (j + window) % WINDOW_NUM;
				int mask = ~(1 << offset);
				ks->bf[i][idx] = ks->bf[i][idx] & mask;
			}
		}

		if (count_flag == 1) {
			ks->postcard_count++;
		}

		if (count_flag == 0) {
			if (keysight_lookup(ks, &key) == 0) {
				ks->false_positive++;
			}
		}
		keysight_insert(ks, &key, count_flag,key_pool,pool_ptr);
	}


}

