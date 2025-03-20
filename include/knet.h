#ifndef KNET_H
#define KNET_H

#include <iostream>
#include <cstdint>
#include <cstring>
#include <openssl/evp.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>

#define AES_KEY_SIZE 32
#define AES_BLOCK_SIZE 16
#define KALA_UDP_PORT 1337  // Custom UDP Port

// Kala Time Packet Structure
struct KalaPacket {
    uint64_t timeStamp;
    uint8_t data[256];
    uint32_t hash;
    uint32_t checksum;
};

// K-Net Library
class KNet {
private:
    static constexpr uint8_t encryptionKey[AES_KEY_SIZE] = { 
        0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
        0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4 
    };

    static constexpr uint8_t encryptionIV[AES_BLOCK_SIZE] = { 
        0x12, 0x34, 0x56, 0x78, 0x90, 0xAB, 0xCD, 0xEF, 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF 
    };

    static uint32_t calculateChecksum(const KalaPacket& packet);

public:
    static uint32_t generateTemporalHash(uint64_t timeStamp);
    static void encryptPacket(KalaPacket& packet);
    static void decryptPacket(KalaPacket& packet);
    static bool  sendKalaPacket(const char* destIP, const char* customData);
    static void sniffKalaPackets();
};

#endif // KNET_H
