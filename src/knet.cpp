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

#include "knet.h"
#include <iostream>
#include <cstring>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>
#include <iomanip>

// ANSI color codes
#define COLOR_RESET   "\033[0m"
#define COLOR_RED     "\033[31m"
#define COLOR_GREEN   "\033[32m"
#define COLOR_YELLOW  "\033[33m"
#define COLOR_BLUE    "\033[34m"
#define COLOR_MAGENTA "\033[35m"
#define COLOR_CYAN    "\033[36m"

// Global AES Key & IV (Shared between sender and receiver)
static uint8_t aesKey[AES_KEY_SIZE] = {
    0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
    0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4
};

static uint8_t aesIV[AES_IV_SIZE] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
};

// Function to print data in xxd-style with colors
void printXXDStyleHexDump(const uint8_t* data, size_t size) {
    for (size_t i = 0; i < size; i += 16) {
        // Print offset
        std::cout << COLOR_CYAN << std::setw(8) << std::setfill('0') << std::hex << i << ": " << COLOR_RESET;
        
        // Print hex values
        for (size_t j = 0; j < 16; j++) {
            if (i + j < size)
                std::cout << COLOR_GREEN << std::setw(2) << std::setfill('0') << std::hex << (int)data[i + j] << " " << COLOR_RESET;
            else
                std::cout << "   "; // Padding for alignment
        }

        std::cout << " ";

        // Print ASCII representation
        for (size_t j = 0; j < 16; j++) {
            if (i + j < size) {
                char c = data[i + j];
                std::cout << (std::isprint(c) ? COLOR_YELLOW + std::string(1, c) + COLOR_RESET : COLOR_RED + std::string(".") + COLOR_RESET);
            }
        }
        
        std::cout << std::endl;
    }
    std::cout << std::dec; // Reset output format
}

// Encrypts data using AES-256-CBC
bool KNet::encryptData(const uint8_t* plaintext, uint32_t length, uint8_t* ciphertext, uint32_t& cipherLen) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return false;

    int len;
    EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, aesKey, aesIV);
    EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, length);
    cipherLen = len;

    EVP_EncryptFinal_ex(ctx, ciphertext + len, &len);
    cipherLen += len;
    EVP_CIPHER_CTX_free(ctx);
    return true;
}

// Decrypts data using AES-256-CBC
bool KNet::decryptData(const uint8_t* ciphertext, uint32_t length, uint8_t* plaintext, uint32_t& plainLen) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return false;

    int len;
    EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, aesKey, aesIV);
    EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, length);
    plainLen = len;

    EVP_DecryptFinal_ex(ctx, plaintext + len, &len);
    plainLen += len;
    EVP_CIPHER_CTX_free(ctx);
    return true;
}

// Computes SHA-256 hash for integrity check
uint32_t KNet::computeHash(const uint8_t* data, uint32_t length) {
    uint8_t hash[SHA256_DIGEST_LENGTH];
    SHA256(data, length, hash);
    return *(uint32_t*)hash;
}

// Computes a checksum over the packet
uint32_t KNet::computeChecksum(const KalaPacket& packet) {
    uint32_t sum = 0;
    for (size_t i = 0; i < sizeof(packet.encryptedData); i++)
        sum += packet.encryptedData[i];
    return sum;
}

// Sends encrypted packet
bool KNet::sendPacket(const char* serverIP, int port, const KalaPacket& packet) {
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        std::cerr << COLOR_RED << "[ERROR] Socket creation failed!" << COLOR_RESET << std::endl;
        return false;
    }

    struct sockaddr_in serverAddr{};
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(port);
    inet_pton(AF_INET, serverIP, &serverAddr.sin_addr);

    if (sendto(sock, &packet, sizeof(packet), 0, (struct sockaddr*)&serverAddr, sizeof(serverAddr)) < 0) {
        std::cerr << COLOR_RED << "[ERROR] Packet send failed!" << COLOR_RESET << std::endl;
        close(sock);
        return false;
    }

    std::cout << COLOR_GREEN << "[INFO] Packet sent successfully to " << serverIP << ":" << port << COLOR_RESET << std::endl;
    close(sock);
    return true;
}

// Receives encrypted packet
bool KNet::receivePacket(int port, KalaPacket& packet) {
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        std::cerr << COLOR_RED << "[ERROR] Socket creation failed!" << COLOR_RESET << std::endl;
        return false;
    }

    struct sockaddr_in serverAddr{};
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(port);
    serverAddr.sin_addr.s_addr = INADDR_ANY;
    bind(sock, (struct sockaddr*)&serverAddr, sizeof(serverAddr));

    std::cout << COLOR_CYAN << "[INFO] Waiting for packets on port " << port << "..." << COLOR_RESET << std::endl;
    recv(sock, &packet, sizeof(packet), 0);

    std::cout << COLOR_MAGENTA << "[INFO] Received packet From Kala Protocal :" << COLOR_RESET << std::endl;
    printXXDStyleHexDump(reinterpret_cast<const uint8_t*>(&packet), sizeof(packet));

    close(sock);
    return true;
}
