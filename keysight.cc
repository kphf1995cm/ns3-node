/*
* Created by Kuang Peng on 2018/4/8
*/

#include <memory.h>
#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
#include <time.h>
#include <iostream>
#include "keysight.h"
#include "key-hash.h"
#include "net-device.h"

namespace ns3 {

	static inline int
		keysight_lookup(keysight_t* ks, bf_key_t* key) {
		int idx = hash_crc32(key, BF_KEY_SIZE, CRC32) % BF_KEY_CONTAINER_SIZE;
		keysight_key_container_t * kc = &ks->key_container[idx];
		//while (kc->next != NULL) {
		while (likely(kc->next != NULL)) {
			kc = kc->next;
			//if (key_compare((uint8_t*)&kc->key, (uint8_t*)key, BF_KEY_SIZE) == 0) {
			if (key_compare(&kc->key,key, BF_KEY_SIZE) == 0) {
				return 1;
			}
		}
		return 0;
	}

	static inline void
		keysight_insert(keysight_t* ks, bf_key_t* key, int count_flag, keysight_key_container_t* key_pool, int& pool_ptr) {
		int idx = hash_crc32(key, BF_KEY_SIZE, CRC32) % BF_KEY_CONTAINER_SIZE;
		keysight_key_container_t * kc = &ks->key_container[idx];
		//while (kc->next != NULL) {
		while (likely(kc->next != NULL)) {
			kc = kc->next;
			//if (key_compare((uint8_t*)&kc->key, (uint8_t*)key, BF_KEY_SIZE) == 0) {
			if (key_compare(&kc->key, key, BF_KEY_SIZE) == 0) {
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
			kc->packet_count = 1;
			ks->distinct_behavior_count++;
		}
	}

#if P4_ID==0
	static inline void
		keysight_extract_switch_key(Ptr<const Packet> packet, uint16_t protocol, const Address &from, const Address &to,switch_key_t* key) {

		Mac48Address eth_src_mac = Mac48Address::ConvertFrom(from);
		Mac48Address eth_dst_mac = Mac48Address::ConvertFrom(to);

		memcpy(key.eth_src_mac, eth_src_mac.m_address, 6);
		memcpy(key.eth_dst_mac, eth_dst_mac.m_address, 6);

	}
#endif
#if P4_ID==1
	static inline void
		keysight_extract_router_key(Ptr<const Packet> packet, uint16_t protocol, const Address &from, const Address &to, router_key_t* key) {

		
		Mac48Address eth_src_mac = Mac48Address::ConvertFrom(from);
		Mac48Address eth_dst_mac = Mac48Address::ConvertFrom(to);

		memcpy(key->eth_src_mac, eth_src_mac.m_address, 6);
		memcpy(key->eth_dst_mac, eth_dst_mac.m_address, 6);

		memcpy(key->eth_type, &protocol, 2);

		//TO DO: find a better way to get packet data
		uint32_t pkt_size = packet->GetSize();
		uint8_t* pkt = new uint8_t[pkt_size];
		packet->CopyData(pkt, pkt_size);

		memcpy(key->dst_addr, &pkt[16], 4);
		delete pkt;

	}
#endif
#if P4_ID==3
	static inline void
		keysight_extract_stateful_firewall_key(Ptr<const Packet> packet, uint16_t protocol, const Address &from, const Address &to, stateful_firewall_key_t* key) {

		memset(key.tcp_ctrl, 0, 1);
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
			memcpy(key.tcp_ctrl, &pkt[33], 1);//ctrl 6b
			key.tcp_ctrl[0] = key.tcp_ctrl[0] & 0x3f;// set zero for first two bits
		}
		else if (key.proto[0] == 0x11) {//udp
			memcpy(key.src_port, &pkt[20], 2);
			memcpy(key.dst_port, &pkt[22], 2);
		}

		delete pkt;
	}
#endif
#if P4_ID==2
	static inline void
		keysight_extract_nat_key(Ptr<const Packet> packet, uint16_t protocol, const Address &from, const Address &to, nat_key_t* key) {

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
	}
#endif
	static void
		bsbf_update(keysight_t* ks, int count_flag) {
		if (count_flag != 1) {
			return;
		}
		srand(ks->random_seed);
		uint32_t i;
		for (i = 0; i < ks->bf_num; i++) {
			ks->bf[i][rand() % ks->bf_size] = 0;
		}
		ks->random_seed = (uint32_t)rand() + time(NULL);
	}

	static void
		bsbfsd_update(keysight_t* ks, int count_flag) {
		srand(ks->random_seed);
		ks->bf[rand() % ks->bf_num][rand() % ks->bf_size] = 0;
		ks->random_seed = (uint32_t)rand() + time(NULL);
	}

	static void
		rlbsbf_update(keysight_t* ks, int count_flag) {
		if (count_flag != 1) {
			return;
		}
		srand(ks->random_seed);
		uint32_t i;
		for (i = 0; i < ks->bf_num; i++) {
			if (ks->bf_len[i] >(uint32_t)(rand() % ks->bf_size)) {
				ks->bf[i][rand() % ks->bf_size] = 0;
			}
		}
		ks->random_seed = (uint32_t)rand() + time(NULL);
	}

	static void
		keysight_bsbfsd_update(keysight_t* ks, int count_flag) {
		srand(ks->random_seed);
		if (count_flag == 1) {
			ks->bf[rand() % ks->bf_num][rand() % ks->bf_size] = 0;
		}
		else if (count_flag == 2) {
			if (rand() % 100 < 100) {
				ks->bf[rand() % ks->bf_num][rand() % ks->bf_size] = 0;
			}
		}
		ks->random_seed = (uint32_t)rand() + time(NULL);
	}


	static void
		keysight_bsbf_update(keysight_t* ks, int count_flag) {
		srand(ks->random_seed);
		uint32_t i;
		if (count_flag == 1) {
			for (i = 0; i < ks->bf_num; i++) {
				ks->bf[i][rand() % ks->bf_size] = 0;
			}
		}
		else if (count_flag == 2) {
			for (i = 0; i < ks->bf_num; i++) {
				ks->bf[i][rand() % ks->bf_size] = 0;
			}
		}

		ks->random_seed = (uint32_t)rand() + time(NULL);
	}

	static void
		keysight_rlbsbf_update(keysight_t* ks, int count_flag) {
		srand(ks->random_seed);
		uint32_t i;
		if (count_flag == 1) {
			for (i = 0; i < ks->bf_num; i++) {
				if (ks->bf_len[i] >(uint32_t)(rand() % ks->bf_size)) {
					ks->bf[i][rand() % ks->bf_size] = 0;
				}
			}
		}
		else if (count_flag == 2) {
			if (rand() % 100 < 100) {
				for (i = 0; i < ks->bf_num; i++) {
					if (ks->bf_len[i] >(uint32_t)(rand() % ks->bf_size)) {
						ks->bf[i][rand() % ks->bf_size] = 0;
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
			ks->bf[rand() % ks->bf_num][rand() % ks->bf_size] = 0;
		}
		else if (count_flag == 2) {
			if (rand() % 100 < 100) {
				ks->bf[rand() % ks->bf_num][rand() % ks->bf_size] = 0;
			}
		}
		else if (ks->false_negative * 100.0 / ks->distinct_behavior_count < 20) {
			ks->bf[rand() % ks->bf_num][rand() % ks->bf_size] = 0;
		}
		ks->random_seed = (uint32_t)rand() + time(NULL);
	}


	static void
		keysight_neg_bsbf_update(keysight_t* ks, int count_flag) {
		srand(ks->random_seed);
		uint32_t i;
		if (count_flag == 1) {
			for (i = 0; i < ks->bf_num; i++) {
				ks->bf[i][rand() % ks->bf_size] = 0;
			}
		}
		else if (count_flag == 2) {
			for (i = 0; i < ks->bf_num; i++) {
				ks->bf[i][rand() % ks->bf_size] = 0;
			}
		}
		else if (ks->false_negative * 100.0 / ks->distinct_behavior_count < 20) {
			for (i = 0; i < ks->bf_num; i++) {
				ks->bf[i][rand() % ks->bf_size] = 0;
			}
		}

		ks->random_seed = (uint32_t)rand() + time(NULL);
	}

	static void
		keysight_neg_rlbsbf_update(keysight_t* ks, int count_flag) {
		srand(ks->random_seed);
		uint32_t i;
		if (count_flag == 1) {
			for (i = 0; i < ks->bf_num; i++) {
				if (ks->bf_len[i] >(uint32_t)(rand() % ks->bf_size)) {
					ks->bf[i][rand() % ks->bf_size] = 0;
				}
			}
		}
		else if (count_flag == 2) {
			if (rand() % 100 < 100) {
				for (i = 0; i < ks->bf_num; i++) {
					if (ks->bf_len[i] >(uint32_t)(rand() % ks->bf_size)) {
						ks->bf[i][rand() % ks->bf_size] = 0;
					}
				}
			}
		}
		else if (ks->false_negative * 100.0 / ks->distinct_behavior_count < 20) {
			for (i = 0; i < ks->bf_num; i++) {
				ks->bf[i][rand() % ks->bf_size] = 0;
			}
		}

		ks->random_seed = (uint32_t)rand() + time(NULL);
	}

	static void
		stable_bf_update(keysight_t* ks, int count_flag) { // TODO
		srand(ks->random_seed);
		uint32_t i;

		for (i = 0; i < ks->bf_num; i++) {
			if (ks->bf_len[i] > rand() % ks->bf_size) {
				int tmp = rand() % ks->bf_size;
				if (ks->bf[i][tmp] > 0) {
					ks->bf[i][tmp] --;
				}
			}
		}

		ks->random_seed = (uint32_t)rand() + time(NULL);
	}

	typedef void(*update_func_t)(keysight_t*, int);
	typedef int(*count_func_t)(keysight_t*, keysight_key_container_t*, int&, Ptr<const Packet>, uint16_t, const Address &, const Address &);

	update_func_t update_funcs[UPDATE_ALG_NUM] = {
		[BSBF] = bsbf_update,
		[BSBFSD] = bsbfsd_update,
		[RLBSBF] = rlbsbf_update,
		[STABLE_BF] = stable_bf_update,
		[IDEAL_BF] = NULL,
                [KEYSIGHT_SBF] = NULL,
		[KEYSIGHT_BSBF] = keysight_bsbf_update,
		[KEYSIGHT_BSBFSD] = keysight_bsbfsd_update,
		[KEYSIGHT_RLBSBF] = keysight_rlbsbf_update,
		[KEYSIGHT_NEG_BSBF] = keysight_neg_bsbf_update,
		[KEYSIGHT_NEG_BSBFSD] = keysight_neg_bsbfsd_update,
		[KEYSIGHT_NEG_RLBSBF] = keysight_neg_rlbsbf_update,
	};

	/*update_func_t update_funcs[UPDATE_ALG_NUM] = { 
                bsbf_update,
                bsbfsd_update,
                rlbsbf_update,
                stable_bf_update,
		NULL,
		NULL,
                keysight_bsbf_update,
                keysight_bsbfsd_update,
                keysight_rlbsbf_update,
                keysight_neg_bsbf_update,
                keysight_neg_bsbfsd_update,
                keysight_neg_rlbsbf_update
        };*/


	static inline void
		keysight_extract_key(Ptr<const Packet> packet, uint16_t protocol, const Address &from, const Address &to, bf_key_t* bf_key) {
		KEYSIGHT_KEY_EXTRACTOR(packet,protocol,from,to,&bf_key->key);
	}

	static int keysight_sbf_count(keysight_t* ks, keysight_key_container_t* key_pool, int& pool_ptr, Ptr<const Packet> packet, uint16_t protocol, const Address &from, const Address &to)
	{
		int count_flag = 0;
		uint32_t i;
		bf_key_t key;
		keysight_extract_key(packet, protocol, from, to, &key);
		ks->packet_count++;
		int window_idx = (ks->packet_count / ks->packet_per_window) % ks->window_num;

		for (i = 0; i < ks->bf_num; i++) {
			uint32_t idx = hash_crc32(&key, BF_KEY_SIZE, i);
			uint32_t bucket_idx = idx%ks->bucket_num;
			idx = idx / ks->bucket_num%ks->bf_size;
			uint64_t mask = ((uint64_t)((1 << ks->window_num) - 1)) << (bucket_idx * ks->window_num);
			mask = mask ^ ((uint64_t)(1 << ((window_idx + 1) % ks->window_num))) << (bucket_idx * ks->window_num);
			if ((ks->bf[i][idx] & mask) == 0) {
				count_flag = 1;
			}

			ks->bf[i][idx] |= 1 << (window_idx + bucket_idx * ks->window_num);
			uint32_t j;
			for (j = 0; j < ks->bucket_num; j++) {
				int offset = (window_idx + 1) % ks->window_num + j * ks->window_num;
				ks->bf[i][idx] &= ~(uint64_t)(1 << offset);
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
		keysight_insert(ks, &key, count_flag, key_pool, pool_ptr);
		return count_flag;
	}

	static int ideal_sbf_count(keysight_t* ks, keysight_key_container_t* key_pool, int& pool_ptr, Ptr<const Packet> packet, uint16_t protocol, const Address &from, const Address &to)
	{
		int count_flag = 0;
		uint32_t i, j, b;
		bf_key_t key;
		keysight_extract_key(packet, protocol, from, to, &key);
		ks->packet_count++;
		int window_idx = (ks->packet_count / ks->packet_per_window) % ks->window_num;

		for (i = 0; i < ks->bf_num; i++) {
			uint32_t idx = hash_crc32(&key, BF_KEY_SIZE, i);
			uint32_t bucket_idx = idx % ks->bucket_num;
			idx = idx / ks->bucket_num % ks->bf_size;
			uint64_t mask = ((uint64_t)((1 << ks->window_num) - 1)) << (bucket_idx * ks->window_num);
			mask = mask ^ ((uint64_t)(1 << ((window_idx + 1) % ks->window_num))) << (bucket_idx * ks->window_num);
			if ((ks->bf[i][idx] & mask) == 0) {
				count_flag = 1;
			}

			ks->bf[i][idx] |= 1 << (window_idx + bucket_idx * ks->window_num);
		}

		if (unlikely(ks->packet_count % ks->packet_per_window == 0)) {
			for (b = 0; b < ks->bf_num; b++) {
				for (i = 0; i < ks->bf_size; i++) {
					for (j = 0; j < ks->bucket_num; j++) {
						int offset = (window_idx + 1) % ks->window_num + j * ks->window_num;
						ks->bf[b][i] &= ~(uint64_t)(1 << offset);
					}
				}
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

		keysight_insert(ks, &key, count_flag, key_pool, pool_ptr);
		return count_flag;
	}

	static int bf_count(keysight_t* ks, keysight_key_container_t* key_pool, int& pool_ptr, Ptr<const Packet> packet, uint16_t protocol, const Address &from, const Address &to)
	{
		int count_flag = 0;
		uint32_t i;
		bf_key_t key;
		keysight_extract_key(packet, protocol, from, to, &key);
		ks->packet_count++;

		for (i = 0; i < ks->bf_num; i++) {
			uint32_t idx = hash_crc32(&key, BF_KEY_SIZE, i) % ks->bf_size;
			if (ks->bf[i][idx] == 0) {
				ks->bf_len[i] ++;
				count_flag = 1;
			}
			ks->bf[i][idx] = ks->bf_max;
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
		keysight_insert(ks, &key, count_flag, key_pool, pool_ptr);
		return count_flag;
	}
	
	count_func_t count_funcs[UPDATE_ALG_NUM] = {
		[BSBF] = bf_count,
		[BSBFSD] = bf_count,
		[RLBSBF] = bf_count,
		[STABLE_BF] = bf_count,
		[IDEAL_BF] = ideal_sbf_count,
		[KEYSIGHT_SBF] = keysight_sbf_count
	};

	void
		keysight_count(keysight_t* ks, keysight_key_container_t* key_pool, int& pool_ptr, Ptr<const Packet> packet, uint16_t protocol, const Address &from, const Address &to) {
		int count_flag = count_funcs[ks->bf_alg](ks,key_pool,pool_ptr,packet,protocol,from,to);
		if (update_funcs[ks->bf_alg] != NULL) {
			update_funcs[ks->bf_alg](ks, count_flag);
		}
	}

}


