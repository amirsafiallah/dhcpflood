//
// Created by root on 5/6/18.
//

#ifndef DHCPFLOOD_DHCPFLOOD_H
#define DHCPFLOOD_DHCPFLOOD_H

#include <iostream>
#include <tins/dhcp.h>
#include <tins/network_interface.h>
#include <tins/utils.h>
#include <tins/ethernetII.h>
#include <tins/packet_sender.h>
#include <tins/ip.h>
#include <tins/udp.h>
#include <tins/rawpdu.h>
#include <tins/sniffer.h>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <atomic>
#include <chrono>
#include <random>

using namespace Tins;
using namespace std::chrono;

class DHCPFlood {
    std::string ifname;

    std::default_random_engine generator;
    std::uniform_int_distribution<uint8_t> distribution8; //unsigned 8 bit number generator for MAC
    std::uniform_int_distribution<uint32_t> distribution32; //unsigned 32 bit number generator for xid

    std::mutex m;
    std::condition_variable cv;
    std::atomic<bool> received = false; //true if ack or nack received
    std::atomic<bool> finished = false; //true if latest IP DHCP generated

    std::thread sniffer;
private:
    SnifferConfiguration getSnifferConfig();

    HWAddress<6> generateRandomMAC();

    /* http://www.tcpipguide.com/free/t_DHCPMessageFormat.htm */
    DHCP generateRandomDHCP(const IPv4Address &ip);

    void startSnifferThread();

public:
    DHCPFlood(const std::string& ifname); //ifname is interface name

    void start(unsigned int startIP, unsigned int endIP);
};


#endif //DHCPFLOOD_DHCPFLOOD_H
