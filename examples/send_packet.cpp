#include "knet.h"
#include <iostream>
#include <cstring>
#include <thread>
#include <unistd.h>

// ANSI color codes
#define RED     "\033[31m"
#define GREEN   "\033[32m"
#define BLUE    "\033[34m"
#define YELLOW  "\033[33m"
#define RESET   "\033[0m"

void printBanner() {
    std::cout << YELLOW;
    std::cout << "=====================================\n";
    std::cout << "      🚀 K-Net Secure Messenger      \n";
    std::cout << "=====================================\n";
    std::cout << RESET;
}

void receiveMessages() {
    std::cout << BLUE << "Listening for messages...\n" << RESET;

    while (true) {
        KalaPacket receivedPacket;

        if (!KNet::receivePacket(SPECIAL_PORT, receivedPacket)) {
            std::cerr << RED << "Failed to receive packet!" << RESET << std::endl;
            continue;
        }

        uint8_t decryptedData[MAX_PACKET_SIZE];
        uint32_t decryptedLen;

        if (!KNet::decryptData(receivedPacket.encryptedData, receivedPacket.encryptedLen, decryptedData, decryptedLen)) {
            std::cerr << RED << "Decryption failed!" << RESET << std::endl;
            continue;
        }

        std::cout << GREEN << "\n📩 Received: " << std::string((char*)decryptedData, decryptedLen) << RESET << std::endl;
    }
}

void sendMessage(const std::string& ip) {
    std::string message;

    while (true) {
        std::cout << YELLOW << "✍ Enter message: " << RESET;
        std::getline(std::cin, message);

        if (message.empty()) continue;

        uint8_t encryptedData[MAX_PACKET_SIZE];
        uint32_t encryptedLen;

        if (!KNet::encryptData((uint8_t*)message.c_str(), message.length(), encryptedData, encryptedLen)) {
            std::cerr << RED << "Encryption failed!" << RESET << std::endl;
            continue;
        }

        KalaPacket packet;
        packet.timeStamp = time(NULL);
        packet.encryptedLen = encryptedLen;
        memcpy(packet.encryptedData, encryptedData, encryptedLen);
        packet.hash = KNet::computeHash(encryptedData, encryptedLen);
        packet.checksum = KNet::computeChecksum(packet);

        if (!KNet::sendPacket(ip, SPECIAL_PORT, packet)) {
            std::cerr << RED << "Failed to send packet!" << RESET << std::endl;
            continue;
        }

        std::cout << GREEN << "✅ Message Sent!\n" << RESET;
    }
}

int main() {
    printBanner();

    std::string ip;
    std::cout << BLUE << "🌐 Enter recipient IP address: " << RESET;
    std::getline(std::cin, ip);

    std::thread receiveThread(receiveMessages);
    sendMessage(ip);
    receiveThread.join();

    return 0;
}
