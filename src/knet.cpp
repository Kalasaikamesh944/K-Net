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
#include <openssl/err.h>
#include <chrono>
#include <cstring>
#include <netinet/in.h>
#include <cerrno>
#include <iomanip> 
#include <sys/sysinfo.h>  // For system uptime
#include <fstream>        // For reading CPU and memory usage
#include <cstring>
#include <openssl/sha.h>

uint32_t calculateSimpleHash(const char* data) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const unsigned char*>(data), strlen(data), hash);

    // Convert first 4 bytes of hash to a uint32_t
    uint32_t result;
    memcpy(&result, hash, sizeof(result));

    return result;
}


void printReceivedData(const uint8_t* data, size_t length) {
    std::cout << "  Decoded Data : ";
    for (size_t i = 0; i < length; i++) {
        if (data[i] == 0) break; // Stop at null terminator
        std::cout << (char)data[i];
    }
    std::cout << "\n";
}


uint32_t KNet::calculateChecksum(const KalaPacket& packet) {
    uint32_t checksum = 0;
    const uint8_t* ptr = reinterpret_cast<const uint8_t*>(&packet);
    
    for (size_t i = 0; i < sizeof(packet) - sizeof(packet.checksum); i++) {
        checksum += ptr[i];
    }

    return checksum;
}

void printPacket(const KalaPacket& packet) {
    std::cout << "========================================\n";
    std::cout << "[INFO] Packet Details:\n";
    std::cout << "  Timestamp  : " << packet.timeStamp << "\n";
    std::cout << "  Hash       : " << std::hex << std::setw(8) << std::setfill('0') << packet.hash << "\n";
    std::cout << "  Checksum   : " << std::hex << std::setw(8) << std::setfill('0') << packet.checksum << "\n";
    std::cout << "  Data       : ";
    for (int i = 0; i < sizeof(packet.data); i++) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)packet.data[i] << " ";
        if ((i + 1) % 16 == 0) std::cout << "\n               ";
    }
    std::cout << "\n========================================\n";
}

std::string getCPUUsage() {
    std::ifstream file("/proc/stat");
    std::string line;
    std::getline(file, line);
    std::istringstream iss(line);
    std::string cpu;
    uint64_t user, nice, system, idle;
    iss >> cpu >> user >> nice >> system >> idle;
    return "CPU: " + std::to_string(user + nice + system) + " Idle: " + std::to_string(idle);
}

std::string getMemoryUsage() {
    std::ifstream file("/proc/meminfo");
    std::string key;
    uint64_t value;
    std::string unit;
    std::ostringstream memInfo;
    
    for (int i = 0; i < 2 && file >> key >> value >> unit; ++i) {
        memInfo << key << " " << value / 1024 << " MB ";
    }
    return memInfo.str();
}

std::string getSystemUptime() {
    struct sysinfo info;
    if (sysinfo(&info) == 0) {
        std::ostringstream uptimeStr;
        uptimeStr << "Uptime: " << info.uptime / 3600 << "h " << (info.uptime % 3600) / 60 << "m";
        return uptimeStr.str();
    }
    return "Uptime: Unknown";
}

bool KNet::sendKalaPacket(const char* destIP, const char* customData) {
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        std::cerr << "[ERROR] Socket creation failed: " << strerror(errno) << std::endl;
        return false;
    }

    struct sockaddr_in destAddr;
    memset(&destAddr, 0, sizeof(destAddr));
    destAddr.sin_family = AF_INET;
    destAddr.sin_port = htons(KALA_UDP_PORT);
    inet_pton(AF_INET, destIP, &destAddr.sin_addr);

    KalaPacket packet;
    memset(&packet, 0, sizeof(packet));

    // Get timestamp
    packet.timeStamp = static_cast<uint32_t>(time(nullptr));

    // Copy custom data into packet
    strncpy(reinterpret_cast<char*>(packet.data), customData, sizeof(packet.data) - 1);
    
    // Generate hash (example hash function)
    packet.hash = calculateSimpleHash(reinterpret_cast<const char*>(packet.data));


    // Calculate checksum
    packet.checksum = calculateChecksum(packet);

    // Send packet
    ssize_t sentBytes = sendto(sockfd, &packet, sizeof(packet), 0,
                               (struct sockaddr*)&destAddr, sizeof(destAddr));
    if (sentBytes < 0) {
        std::cerr << "[ERROR] Packet send failed: " << strerror(errno) << std::endl;
        close(sockfd);
        return false;
    }

    std::cout << "[INFO] Sent packet to " << destIP << "\n";
    std::cout << "  Data: " << customData << "\n";

    close(sockfd);
    return true;
}


uint32_t KNet::generateTemporalHash(uint64_t timeStamp) {
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hashLen;
    
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (!mdctx) {
        std::cerr << "[ERROR] Failed to create EVP_MD_CTX" << std::endl;
        return 0;
    }

    if (EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL) != 1 ||
        EVP_DigestUpdate(mdctx, &timeStamp, sizeof(timeStamp)) != 1 ||
        EVP_DigestFinal_ex(mdctx, hash, &hashLen) != 1) {
        ERR_print_errors_fp(stderr);
        EVP_MD_CTX_free(mdctx);
        return 0;
    }

    EVP_MD_CTX_free(mdctx);
    
    return *reinterpret_cast<uint32_t*>(hash);  // Convert first 4 bytes to uint32_t
}

void KNet::encryptPacket(KalaPacket &packet) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        std::cerr << "[ERROR] Failed to create EVP_CIPHER_CTX" << std::endl;
        return;
    }

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, encryptionKey, encryptionIV) != 1) {
        ERR_print_errors_fp(stderr);
        EVP_CIPHER_CTX_free(ctx);
        return;
    }

    int len;
    uint8_t encryptedData[sizeof(packet.data)];
    if (EVP_EncryptUpdate(ctx, encryptedData, &len, packet.data, sizeof(packet.data)) != 1) {
        ERR_print_errors_fp(stderr);
        EVP_CIPHER_CTX_free(ctx);
        return;
    }

    int final_len;
    if (EVP_EncryptFinal_ex(ctx, encryptedData + len, &final_len) != 1) {
        ERR_print_errors_fp(stderr);
        EVP_CIPHER_CTX_free(ctx);
        return;
    }

    std::memcpy(packet.data, encryptedData, sizeof(packet.data));
    EVP_CIPHER_CTX_free(ctx);
}

void KNet::decryptPacket(KalaPacket &packet) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        std::cerr << "[ERROR] Failed to create EVP_CIPHER_CTX" << std::endl;
        return;
    }

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, encryptionKey, encryptionIV) != 1) {
        ERR_print_errors_fp(stderr);
        EVP_CIPHER_CTX_free(ctx);
        return;
    }

    int len;
    uint8_t decryptedData[sizeof(packet.data)];
    if (EVP_DecryptUpdate(ctx, decryptedData, &len, packet.data, sizeof(packet.data)) != 1) {
        ERR_print_errors_fp(stderr);
        EVP_CIPHER_CTX_free(ctx);
        return;
    }

    int final_len;
    if (EVP_DecryptFinal_ex(ctx, decryptedData + len, &final_len) != 1) {
        ERR_print_errors_fp(stderr);
        EVP_CIPHER_CTX_free(ctx);
        return;
    }

    std::memcpy(packet.data, decryptedData, sizeof(packet.data));
    EVP_CIPHER_CTX_free(ctx);
}


void KNet::sniffKalaPackets() {
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        std::cerr << "[ERROR] Failed to create socket: " << strerror(errno) << std::endl;
        return;
    }

    struct sockaddr_in serverAddr;
    memset(&serverAddr, 0, sizeof(serverAddr));
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(KALA_UDP_PORT);
    serverAddr.sin_addr.s_addr = INADDR_ANY;

    if (bind(sockfd, (struct sockaddr*)&serverAddr, sizeof(serverAddr)) < 0) {
        std::cerr << "[ERROR] Bind failed: " << strerror(errno) << std::endl;
        close(sockfd);
        return;
    }

    KalaPacket packet;
    struct sockaddr_in senderAddr;
    socklen_t senderAddrLen = sizeof(senderAddr);

    std::cout << "[INFO] Listening for incoming packets...\n";
    
    while (true) {
        ssize_t receivedBytes = recvfrom(sockfd, &packet, sizeof(packet), 0,
                                         (struct sockaddr*)&senderAddr, &senderAddrLen);
        if (receivedBytes < 0) {
            std::cerr << "[ERROR] Packet receive failed: " << strerror(errno) << std::endl;
            continue;
        }

        char senderIP[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &senderAddr.sin_addr, senderIP, INET_ADDRSTRLEN);

        std::cout << "========================================\n";
        std::cout << "[RECEIVED] Packet from " << senderIP << "\n";
        std::cout << "========================================\n";
        std::cout << "[INFO] Packet Details:\n";
        std::cout << "  Timestamp  : " << std::hex << packet.timeStamp << "\n";
        std::cout << "  Hash       : " << std::hex << packet.hash << "\n";
        std::cout << "  Checksum   : " << std::hex << packet.checksum << "\n";

        // Print raw hex data
        std::cout << "  Data (Hex) : ";
        for (size_t i = 0; i < sizeof(packet.data); i++) {
            if (i % 16 == 0) std::cout << "\n               ";
            std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)packet.data[i] << " ";
        }
        std::cout << "\n";

        // Print decoded text
        printReceivedData(packet.data, sizeof(packet.data));

        std::cout << "========================================\n";
    }

    close(sockfd);
}
