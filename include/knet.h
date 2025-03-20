/***
MIT License

Copyright (c) 2025 Kalasaikamesh944

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
***/    
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
