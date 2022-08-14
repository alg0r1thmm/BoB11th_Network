#include <cstdio>
#include <pcap.h>
#include <sys/ioctl.h>
#include <fstream>
#include <net/if.h>
#include <arpa/inet.h>
#include <string.h>
#include <iostream>
#include <sys/ioctl.h>
#include <net/if.h> 
#include <unistd.h>
#include <netinet/in.h>
#include <string.h>
#include "ethhdr.h"
#include "arphdr.h"

#pragma pack(push, 1)
struct EthArpPacket final {
	EthHdr eth_;
	ArpHdr arp_;
};
#pragma pack(pop)

void usage() {
	printf("syntax : send-arp <interface> <sender ip> <target ip> [<sender ip 2> <target ip 2> ...]\n");
	printf("sample : send-arp wlan0 192.168.10.2 192.168.10.1\n");
}
/* https://technote.kr/176 */
void getMyIP(char* dev, char* m_ip){
    struct ifreq ifr;
	char ipstr[40];
	int s;

	s = socket(AF_INET, SOCK_DGRAM, 0);
	strncpy(ifr.ifr_name, dev, IFNAMSIZ);

	if (ioctl(s, SIOCGIFADDR, &ifr) < 0) {
		printf("Error");
	} else {
		inet_ntop(AF_INET, ifr.ifr_addr.sa_data+2,
				m_ip,sizeof(struct sockaddr));
		printf("myOwn IP Address is %s\n", m_ip);
	}
}

/* https://www.faqcode4u.com/faq/14355/how-to-get-mac-address-of-your-machine-using-a-c-program */
void get_myMAC(char* dev) {
	struct ifreq ifr;
     struct ifconf ifc;
     char buf[1024];
     int success = 0;
     int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
     if (sock == -1) { /* handle error*/ };
     ifc.ifc_len = sizeof(buf);
     ifc.ifc_buf = buf;
     if (ioctl(sock, SIOCGIFCONF, &ifc) == -1) { /* handle error */ }
     struct ifreq* it = ifc.ifc_req;
     const struct ifreq* const end = it + (ifc.ifc_len / sizeof(struct ifreq));
     for (; it != end; ++it) {
         strcpy(ifr.ifr_name, it->ifr_name);
         if (ioctl(sock, SIOCGIFFLAGS, &ifr) == 0) {
             if (! (ifr.ifr_flags & IFF_LOOPBACK)) { // don't count loopback
                 if (ioctl(sock, SIOCGIFHWADDR, &ifr) == 0) {
                     success = 1;
                     break;
                 }
             }
         }
         else { /* handle error */ }
     }
     unsigned char my_mac[6];
     if (success) memcpy(my_mac, ifr.ifr_hwaddr.sa_data, 6);
}

int main(int argc, char* argv[]) {
	if (argc != 2) {
		usage();
		return -1;
	}

	char* dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(dev, 0, 0, 0, errbuf);
	if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return -1;
	}

	EthArpPacket packet;

	packet.eth_.dmac_ = Mac("00:00:00:00:00:00");
	packet.eth_.smac_ = Mac("00:00:00:00:00:00");
	packet.eth_.type_ = htons(EthHdr::Arp);

	packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	packet.arp_.pro_ = htons(EthHdr::Ip4);
	packet.arp_.hln_ = Mac::SIZE;
	packet.arp_.pln_ = Ip::SIZE;
	packet.arp_.op_ = htons(ArpHdr::Request);
	packet.arp_.smac_ = Mac("00:00:00:00:00:00");
	packet.arp_.sip_ = htonl(Ip("0.0.0.0"));
	packet.arp_.tmac_ = Mac("00:00:00:00:00:00");
	packet.arp_.tip_ = htonl(Ip("0.0.0.0"));

	int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
	if (res != 0) {
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
	}

	pcap_close(handle);
}
