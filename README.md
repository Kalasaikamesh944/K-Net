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

## Custom Data Transmission
You can modify `sendKalaPacket()` to send specific data:
```cpp
bool KNet::sendKalaPacket(const char* destIP, const char* customData);
```


## Example Output
```bash
[INFO] Sent packet to 192.168.55.16
```

## License
This project is open-source under the MIT License.

