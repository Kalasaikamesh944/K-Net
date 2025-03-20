#include <iostream>
#include <sstream>
#include <cstdlib>
#include <unistd.h>
#include "knet.h"

std::string getSystemStats() {
    std::ostringstream systemData;
    
    // Get system uptime
    systemData << "Uptime: ";
    systemData << system("awk '{print $1}' /proc/uptime") << " sec | ";

    // Get CPU usage
    systemData << "CPU: ";
    systemData << system("awk -v CONVFMT='%.2f' '{print $1+$2+$3+$4+$5+$6+$7+$8}' /proc/stat") << "% | ";

    // Get Memory usage
    systemData << "MemTotal: ";
    systemData << system("grep MemTotal /proc/meminfo | awk '{print $2}'") << " kB | ";
    
    systemData << "MemFree: ";
    systemData << system("grep MemFree /proc/meminfo | awk '{print $2}'") << " kB";
    
    return systemData.str();
}

int main() {
    KNet knet;
    const char* destIP = "192.168.55.16";

    while (true) {
        std::string data = getSystemStats();
        knet.sendKalaPacket(destIP,"This is kala Packet");
        sleep(5); // Send every 5 seconds
    }

    return 0;
}
