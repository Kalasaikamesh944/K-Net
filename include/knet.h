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

#include <cstdint>
#include <string>

#define AES_KEY_SIZE 32  // AES-256 Key size
#define AES_IV_SIZE 16   // AES IV size
#define MAX_PACKET_SIZE 1024  // Max packet size
#define SPECIAL_PORT 8000  // Special port for Kala Protocol

struct KalaPacket {
    uint32_t timeStamp;      // Packet timestamp
    uint32_t hash;           // Integrity hash
    uint32_t checksum;       // Checksum
    uint8_t encryptedData[MAX_PACKET_SIZE];  // Encrypted payload
    uint32_t encryptedLen;   // Length of encrypted data
};

// Kala Protocol Class
class KNet {
public:
    static bool encryptData(const uint8_t* plaintext, uint32_t length, uint8_t* ciphertext, uint32_t& cipherLen);
    static bool decryptData(const uint8_t* ciphertext, uint32_t length, uint8_t* plaintext, uint32_t& plainLen);
    static uint32_t computeHash(const uint8_t* data, uint32_t length);
    static uint32_t computeChecksum(const KalaPacket& packet);

    static bool sendPacket(const char* serverIP, int port, const KalaPacket& packet);
    static bool receivePacket(int port, KalaPacket& packet);
};

#endif
