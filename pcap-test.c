#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdint.h>
#include <netinet/in.h>
//#include <libnet.h>	// libnet

#define ETHER_ADDR_LEN 6
#define IP_ADDR_LEN 4
#define ETHERTYPE_IP 0x0800
#define IPTYPE_TCP 0x0006



struct libnet_ethernet_hdr
{
    u_int8_t  ether_dhost[ETHER_ADDR_LEN];/* destination ethernet address */
    u_int8_t  ether_shost[ETHER_ADDR_LEN];/* source ethernet address */
    u_int16_t ether_type;                 /* protocol */
};

void print_Ethernet_Header(struct libnet_ethernet_hdr* eth_hdr)
{
	printf("\nEthernet Header\n");

	printf("src Mac : ");
	for (int i = 0; i < ETHER_ADDR_LEN; i++){
		printf("%02x : ", eth_hdr->ether_shost[i]);}
	printf("\n");
	printf("dst Mac : ");
	for(int i = 0; i < ETHER_ADDR_LEN; i++){
		printf("%02x : ", eth_hdr->ether_dhost[i]);}
	printf("\n");
};

struct libnet_ipv4_hdr
{
	uint8_t ip_hl:4, ip_v:4;
	uint16_t ip_tos;
	uint16_t ip_len;
	uint16_t ip_id;
	uint16_t ip_off;
	uint8_t ip_ttl;
	uint8_t ip_p;
	uint16_t ip_sum;
	struct in_addr ip_src;
	struct in_addr ip_dst;
};

void print_IP_Header(struct libnet_ipv4_hdr* ip_hdr){
	printf("\nIP Header\n");
    u_int32_t src = ntohl(ip_hdr->ip_src.s_addr);
    u_int32_t dst = ntohl(ip_hdr->ip_dst.s_addr);

    	printf("src ip : ");
	printf("%d.%d.%d.%d\n", src>>24, (u_char)(src>>16),(u_char)(src>>8),(u_char)(src));
	printf("dst ip : ");
	printf("%d.%d.%d.%d\n", dst>>24, (u_char)(dst>>16),(u_char)(dst>>8),(u_char)(dst));
	printf("\n");
};


void printMac(u_int8_t* m) {
	printf("%02x:%02x:%02x:%02x:%02x:%02x", m[0], m[1], m[2], m[3], m[4], m[5]);
}

struct libnet_tcp_hdr
{
	uint16_t th_sport;
	uint16_t th_dport;
	uint32_t th_seq;
	uint32_t th_ack;
	uint8_t th_x2:4, th_off:4;
	uint8_t th_flags;
	uint16_t th_win;
	uint16_t th_sum;
	uint16_t th_urp;
};


void print_TCP_Header(struct libnet_tcp_hdr* tcp_hdr){
	printf("\nTCP Header\n");
	
	printf("src port : %d\n", ntohs(tcp_hdr->th_sport));
	printf("dst port : %d\n", ntohs(tcp_hdr->th_dport));
};


void usage() {
	printf("syntax: pcap-test <interface>\n");
	printf("sample: pcap-test wlan0\n");
}

typedef struct {
	char* dev_;
} Param;

Param param = {
	.dev_ = NULL
};

bool parse(Param* param, int argc, char* argv[]) {
	if (argc != 2) {
		usage();
		return false;
	}
	param->dev_ = argv[1];
	return true;
}

int main(int argc, char* argv[]) {
	if (!parse(&param, argc, argv))
		return -1;

	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
	if (pcap == NULL) {
		fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
		return -1;
	}

	while (true) {
		struct pcap_pkthdr* header;
		const u_char* packet;
		int res = pcap_next_ex(pcap, &header, &packet);
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
			break;
		}
		//printf("%u bytes captured\n", header->caplen);
		struct libnet_ethernet_hdr* eth_hdr = (struct libnet_ethernet_hdr *)packet;
		struct libnet_ipv4_hdr* ip_hdr = (struct libnet_ipv4_hdr*)(packet + 14);
		struct libnet_tcp_hdr* tcp_hdr = (struct libnet_tcp_hdr*)(packet + 14 + (ip_hdr->ip_hl) * 4);
		printMac(eth_hdr->ether_shost);
		printf(" ");
		printMac(eth_hdr->ether_dhost);
		printf("\n");

		if(ntohs(eth_hdr->ether_type) != ETHERTYPE_IP)
			continue;
		if((ip_hdr->ip_v) != IPTYPE_TCP)
			continue;
		

		print_Ethernet_Header(eth_hdr);
		print_IP_Header(ip_hdr);
		print_TCP_Header(tcp_hdr);
		uint32_t offset = 14 + (ip_hdr->ip_hl) * 4 + (tcp_hdr->th_off) * 4;

	}

	pcap_close(pcap);
}
