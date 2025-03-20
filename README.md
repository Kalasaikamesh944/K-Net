# K-Net

## Overview
K-Net is a lightweight network packet transmission framework designed to send custom and system data over a network securely. It provides functionality for structured packet creation, checksum verification, and real-time system monitoring data transmission.

## Features
- Send and receive structured packets over a network.
- Includes real-time system data (CPU, Memory, Uptime, etc.).
- Implements checksum and hashing for data integrity.
- Uses OpenSSL for cryptographic operations.

## Installation
### Prerequisites
- **Linux-based system**
- **g++ compiler** (GCC)
- **OpenSSL library** (libcrypto)

### Build Instructions
```bash
make clean && make
```

## Usage
### Sending a Packet
```bash
sudo ./send_packet
```
### Receiving a Packet
```bash
sudo ./receive_packet
```

## Packet Structure
Each packet includes:
- **Timestamp**: Packet creation time.
- **Hash**: Simple hash of the packet data.
- **Checksum**: Ensures data integrity.
- **Data**: Custom or system-generated data.

# Examples and usage 
```c
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
    const char* message = "Hello from Kala Protocol!";
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

    if (!KNet::sendPacket("127.0.0.1", SPECIAL_PORT, packet)) {
        std::cerr << "Failed to send packet!" << std::endl;
        return -1;
    }

    std::cout << "Packet sent successfully!" << std::endl;
}

```
```c
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

int main() {
    KalaPacket packet;
    if (!KNet::receivePacket(SPECIAL_PORT, packet)) {
        std::cerr << "Failed to receive packet!" << std::endl;
        return -1;
    }

    uint8_t decryptedData[MAX_PACKET_SIZE];
    uint32_t decryptedLen;

    if (!KNet::decryptData(packet.encryptedData, packet.encryptedLen, decryptedData, decryptedLen)) {
        std::cerr << "Decryption failed!" << std::endl;
        return -1;
    }

    std::cout << "Received Message: " << std::string((char*)decryptedData, decryptedLen) << std::endl;
}


'''
