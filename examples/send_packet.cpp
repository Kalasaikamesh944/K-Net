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
int main() {
    const char* message = "Hello from Kala Protocol! this is encripted message lets make private talk .................";
    uint8_t encryptedData[MAX_PACKET_SIZE];
    uint32_t encryptedLen;

    if (!KNet::encryptData((uint8_t*)message, strlen(message), encryptedData, encryptedLen)) {
        std::cerr << "Encryption failed!" << std::endl;
        return -1;
    }

    KalaPacket packet;
    packet.timeStamp = time(NULL);
    packet.encryptedLen = encryptedLen;
    memcpy(packet.encryptedData, encryptedData, encryptedLen);
    packet.hash = KNet::computeHash(encryptedData, encryptedLen);
    packet.checksum = KNet::computeChecksum(packet);

   while (true){
      if (!KNet::sendPacket("192.168.55.16", SPECIAL_PORT, packet)) {
         std::cerr << "Failed to send packet!" << std::endl;
         return -1;
      }

      std::cout << "Packet sent successfully!" << std::endl;
  }
}
