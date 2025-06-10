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
#include <thread>
#include <unistd.h>



void receiveMessages() {
    std::cout << "Listening for messages...\n";

    while (true) {
        KalaPacket receivedPacket;

        if (!KNet::receivePacket(SPECIAL_PORT, receivedPacket)) {
            std::cerr << "Failed to receive packet!" << std::endl;
            continue;
        }

        uint8_t decryptedData[MAX_PACKET_SIZE];
        uint32_t decryptedLen;

        if (!KNet::decryptData(receivedPacket.encryptedData, receivedPacket.encryptedLen, decryptedData, decryptedLen)) {
            std::cerr << "Decryption failed!" << std::endl;
            continue;
        }

        std::cout << "\n📩 Received: " << std::string((char*)decryptedData, decryptedLen) << std::endl;
    }
}

void sendMessage() {
    std::string message;

    while (true) {
        std::cout << "✍ Enter message: ";
        std::getline(std::cin, message);

        if (message.empty()) continue;

        uint8_t encryptedData[MAX_PACKET_SIZE];
        uint32_t encryptedLen;

        if (!KNet::encryptData((uint8_t*)message.c_str(), message.length(), encryptedData, encryptedLen)) {
            std::cerr << "Encryption failed!" << std::endl;
            continue;
        }

        KalaPacket packet;
        packet.timeStamp = time(NULL);
        packet.encryptedLen = encryptedLen;
        memcpy(packet.encryptedData, encryptedData, encryptedLen);
        packet.hash = KNet::computeHash(encryptedData, encryptedLen);
        packet.checksum = KNet::computeChecksum(packet);

        if (!KNet::sendPacket("172.19.63.121", SPECIAL_PORT, packet)) {
            std::cerr << "Failed to send packet!" << std::endl;
            continue;
        }

        std::cout << "✅ Message Sent!\n";
    }
}

int main() {
    std::thread receiveThread(receiveMessages);
    sendMessage();
    receiveThread.join();

    return 0;
}
