#include "vrrp.h"
#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <strings.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <time.h>
#include <sys/ioctl.h>

unsigned short checksum(void* b, int len) {
	unsigned short* buf = b;
	unsigned int sum = 0;
	unsigned short result;

	for (sum = 0; len > 1; len -= 2)
		sum += *buf++;
	if (len == 1)
		sum += *(unsigned char*)buf;
	sum = (sum >> 16) + (sum & 0xFFFF);
	sum += (sum >> 16);
	result = ~sum;
	return result;
}

void init_state(vrrp_state* state, pcap_if_t* pInterface, int sock, struct sockaddr_in* detected_ipv4) {

	if (state->priority == 255)
	{
		send_arp_packet(pInterface, sock, state->vrid, state);

		state->advertisement_timer = state->advertisement_interval;
		state->state = VRRP_STATE_MASTER;

		printf("VRRP initialized with VRID %d, priority %d, interval %d\n", state->vrid, state->priority, state->advertisement_interval);

	}
	else {
		state->master_down_timer = state->master_down_interval;
		state->state = VRRP_STATE_BACKUP;
	}
}

void backup_state(vrrp_state* state, pcap_if_t* pInterface, int sock, struct sockaddr_in* detected_ipv4) {

}

int verify_vrrp_packet(vrrp_state state, struct iphdr ipHeader, struct vrrp_header vrrpHeader) {

	if (ipHeader.protocol != 112
		|| ipHeader.ttl != 255
		|| vrrpHeader.checksum != checksum((unsigned short*)&vrrpHeader, sizeof(struct vrrp_header))
		|| vrrpHeader.version_type != (VRRP_VERSION << 4) | VRRP_TYPE_ADVERTISEMENT
		|| vrrpHeader.auth_type != state.authentication_type
		|| vrrpHeader.vrid != state.vrid
		|| ipHeader.daddr != state.ip_address) {
		return -1;
	}

	return 0;
}

int send_vrrp_packet(vrrp_state* state, pcap_if_t* pInterface, int sock, struct sockaddr_in* detected_ipv4) {
	int sockfd;
	struct ifreq if_idx;
	struct sockaddr_ll socket_address;

	char* ifName = pInterface->name;
	uint8_t packet[1500];

	if ((sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) == -1) {
		perror("socket");
		return -1;
	}

	memset(&if_idx, 0, sizeof(struct ifreq));
	strncpy(if_idx.ifr_name, ifName, IFNAMSIZ - 1);
	if (ioctl(sockfd, SIOCGIFINDEX, &if_idx) < 0) {
		perror("SIOCGIFINDEX");
		return -1;
	}


	struct ethhdr* eth = (struct ethhdr*)packet;
	pcap_addr_t* address = pInterface->addresses;
	while (address) {
		if (address->addr && address->addr->sa_family == AF_PACKET) {

			struct sockaddr_ll* sll = (struct sockaddr_ll*)address->addr;
			memcpy(eth->h_source, sll->sll_addr, 6);
			break;
		}
		address = address->next;
	}
	eth->h_dest[0] = 0x01;
	eth->h_dest[1] = 0x00;
	eth->h_dest[2] = 0x5E;
	eth->h_dest[3] = 0x00;
	eth->h_dest[4] = 0x00;
	eth->h_dest[5] = state->vrid;
	eth->h_proto = htons(ETH_P_IP);


	struct iphdr* iph = (struct iphdr*)(packet + sizeof(struct ethhdr));
	iph->ihl = 5;
	iph->version = 4;
	iph->tos = 0;
	iph->tot_len = htons(sizeof(struct iphdr) + sizeof(struct vrrp_header));
	iph->id = htonl(54321);
	iph->frag_off = 0;
	iph->ttl = 255;
	iph->protocol = 112; // VRRP protocol number
	iph->check = 0;
	iph->saddr = state->ip_address; // Source IP address
	iph->daddr = inet_addr(VRRP_MULTICAST_IPV4); // VRRP multicast address
	iph->check = checksum((unsigned short*)iph, sizeof(struct iphdr));

	struct vrrp_header* vrrp = (struct vrrp_header*)(packet + sizeof(struct ethhdr) + sizeof(struct iphdr));
	vrrp->version_type = (VRRP_VERSION << 4) | VRRP_TYPE_ADVERTISEMENT;
	vrrp->vrid = state->vrid;
	vrrp->priority = state->priority;
	vrrp->count_ip = 1;
	vrrp->auth_type = state->authentication_type;
	vrrp->advertisement_interval = state->advertisement_interval;
	vrrp->ip_addresses[0] = state->ip_address; // Virtual Router IP address
	vrrp->checksum = checksum((unsigned short*)vrrp, sizeof(struct vrrp_header));


	memset(&socket_address, 0, sizeof(struct sockaddr_ll));
	socket_address.sll_ifindex = if_idx.ifr_ifindex;
	socket_address.sll_halen = ETH_ALEN;


	if (sendto(sockfd, packet, sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct vrrp_header), 0, (struct sockaddr*)&socket_address, sizeof(struct sockaddr_ll)) < 0) {
		perror("sendto");
		return -1;
	}

	close(sockfd);

}

int send_arp_packet(pcap_if_t* interface, int sockClient, uint8_t vrid, struct vrrp_state* state) {

	unsigned int msgLen = sizeof(struct ethhdr) + sizeof(struct arpHdr);
	uint8_t* msg = (uint8_t*)malloc(msgLen);
	if (msg == NULL) {
		perror("malloc()");
		close(sockClient);
		return -1;
	}

	memset(msg, 0, msgLen);
	struct ethhdr* eth;
	eth = (struct ethhdr*)msg;
	pcap_addr_t* address = interface->addresses;
	while (address) {
		if (address->addr && address->addr->sa_family == AF_PACKET) {

			struct sockaddr_ll* sll = (struct sockaddr_ll*)address->addr;
			memcpy(eth->h_source, sll->sll_addr, 6);
			break;
		}
		address = address->next;
	}

	eth->h_dest[0] = 0x01; // Multicast OUI
	eth->h_dest[1] = 0x00;
	eth->h_dest[2] = 0x5E;
	eth->h_dest[3] = 0x00;
	eth->h_dest[4] = 0x00;
	eth->h_dest[5] = vrid; // VRID

	eth->h_proto = htons(ARP_ETHER_TYPE);

	struct arpHdr* arp;
	arp = (struct arpHdr*)(msg + sizeof(struct ethhdr));
	arp->hwType = htons(HW_TYPE);
	arp->protoType = htons(IP_PROTO);
	arp->hwLen = HW_LEN;
	arp->protoLen = IP_LEN;
	arp->opcode = htons(GRATUITOUS_ARP_OPCODE); // ARP opcode 

	for (int i = 5; i >= 0; i--) {
		arp->srcMAC[i] = eth->h_source[i];
	}
	for (int i = 5; i >= 0; i--) {
		arp->targetMAC[i] = 0x00;
	}

	arp->srcIP = state->ip_address;
	arp->targetIP = state->ip_address;

	if (write(sockClient, msg, msgLen) == -1) {
		perror("write()");
		close(sockClient);
		free((void*)msg);
		return -1;
	}
}
void receive_vrrp_packet(vrrp_state* state) {

}