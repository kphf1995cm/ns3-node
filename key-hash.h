//
// Created by Zhou Yu on 2018/3/14.
//

#ifndef KEY_HASH_H
#define KEY_HASH_H

#include <stdint.h>

namespace ns3{
#define  likely(x)        __builtin_expect(!!(x), 1)
#define  unlikely(x)      __builtin_expect(!!(x), 0)

enum CRC8_ALG {
    CRC8 = 0,
    CRC8_DARC,
    CRC8_I_CODE,
    CRC8_ITU,
    CRC8_MAXIM,
    CRC8_ROHC,
    CRC8_WCDMA,
    CRC8_ALG_NUM
};

enum CRC16_ALG {
    CRC16 = 0,
    CRC16_BUYPASS,
    CRC16_DDS_110,
    CRC16_DECT,
    CRC16_DNP,
    CRC16_EN_13757,
    CRC16_GENIBUS,
    CRC16_MAXIM,
    CRC16_MCRF4XX,
    CRC16_RIELLO,
    CRC16_T10_DIF,
    CRC16_TELEDISK,
    CRC16_USB,
    X_25,
    XMODEM,
    MODBUS,
    KERMIT,
    CRC_CCITT,
    CRC_AUG_CCITT,
    CRC16_ALG_NUM
};

enum CRC32_ALG {
    CRC32 = 0,
    CRC32_BZIP2,
    CRC32C,
    CRC32D,
    CRC32_MPEG,
    POSIX,
    CRC32Q,
    JAMCRC,
    XFER,
    CRC32_ALG_NUM
};

static inline int
key_compare(const void * key1, const void * key2, int length) {
    int i;
    for(i = 0; i <= length / 8; i ++) {
        if (((const uint64_t* )key1)[i] != ((const uint64_t* )key2)[i]) {
            return 1;
        }
    }
    i--;
    length -= (i << 3);
    for (i = 0; i < length/4; i++) {
        if (((const uint32_t* )key1)[i] != ((const uint32_t* )key2)[i]) {
            return 1;
        }
    }

    i--;
    length -= (i << 2);
    for (i = 0; i < length; i++) {
        if (((const uint8_t* )key1)[i] != ((const uint8_t* )key2)[i]) {
            return 1;
        }
    }
    return 0;
}

uint32_t hash_crc32(const void* buf, int length, int alg);
uint16_t hash_crc16(const void* buf, int length, int alg);
uint8_t hash_crc8(const void* buf, int length, int alg);
}
#endif

