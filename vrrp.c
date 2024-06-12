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




// Function to calculate VRRP checksum
uint16_t calculate_checksum(uint16_t* buffer, int size) {
	uint32_t sum = 0;
	for (int i = 0; i < size; ++i) {
		sum += ntohs(buffer[i]);
	}
	while (sum >> 16) {
		sum = (sum & 0xFFFF) + (sum >> 16);
	}
	return htons(~sum);
}

void init_state(vrrp_state_t* state, pcap_if_t* pInterface, int sock, struct sockaddr_in* detected_ipv4) {
	if (state->priority == 255)
	{
		send_arp_packet(pInterface, sock, state->vrid, detected_ipv4);

		state->advertisement_timer = state->advertisement_interval;
		state->state = VRRP_STATE_MASTER;

		printf("VRRP initialized with VRID %d, priority %d, interval %d\n", state->vrid, state->priority, state->advertisement_interval);

	}
	else {
		state->master_down_timer = state->master_down_interval;
		state->state = VRRP_STATE_BACKUP;
	}
}

void backup_state(vrrp_state_t* state, pcap_if_t* pInterface, int sock, struct sockaddr_in* detected_ipv4) {

}

int send_vrrp_packet(vrrp_state_t* state, pcap_if_t* pInterface, int sock, struct sockaddr_in* detected_ipv4) {
	int vrrpSocket;
	if ((vrrpSocket = socket(AF_INET, SOCK_RAW, 112)) < 0)
	{
		perror("SOCKET:");
		exit(EXIT_FAILURE);
	}
	int ttl = 255;
	socklen_t len = sizeof(ttl);
	if (getsockopt(vrrpSocket, IPPROTO_IP, IP_MINTTL, &ttl, &len) < 0) {
		perror("Get TTL failed");
		exit(EXIT_FAILURE);
	}
	printf("TTL value: %d", ttl);
	int mojmin = 255;
	socklen_t lenMojMin = sizeof(mojmin);
	setsockopt(vrrpSocket, IPPROTO_IP, IP_TTL, &mojmin, &lenMojMin);
	// Prepare the VRRP packet
	struct vrrp_packet_t vrrp;
	memset(&vrrp, 0, sizeof(struct vrrp_packet_t) + sizeof(uint32_t));
	vrrp.version_type = (VRRP_VERSION << 4) | VRRP_TYPE_ADVERTISEMENT;
	vrrp.vrid = state->vrid;
	vrrp.priority = state->priority;
	vrrp.count_ip = 1;
	vrrp.auth_type = state->authentication_type;
	vrrp.advertisement_interval = state->advertisement_interval;
	vrrp.ip_addresses[0] = state->ip_address;
	vrrp.authentication_data = state->authentication_data;
	vrrp.checksum = calculate_checksum((uint16_t*)&vrrp, (sizeof(struct vrrp_packet_t) + sizeof(uint32_t)) / 2);

	char* target_ip = "224.0.0.18";
	struct sockaddr_in dest_addr;
	memset(&dest_addr, 0, sizeof(dest_addr));
	dest_addr.sin_family = AF_INET;
	dest_addr.sin_port = htons(1985);
	dest_addr.sin_addr.s_addr = inet_addr(target_ip);

	struct ipHdr ip_header;

	// Initialize the ip_header structure here
	// For example:
	ip_header.ip_hl = 5;
	ip_header.ip_v = 4;
	ip_header.ip_tos = 0;
	ip_header.ip_len = sizeof(ip_header); // Example length
	ip_header.ip_id = 54321; // Example identifier
	ip_header.ip_off = 0;
	ip_header.ip_ttl = 255; // Example TTL
	ip_header.ip_p = IPPROTO_TCP; // Example protocol
	ip_header.ip_sum = 0; // Will be calculated later
	ip_header.ip_src.s_addr = htonl(state->ip_address); // Example source IP
	ip_header.ip_dst.s_addr = inet_addr("224.0.0.18"); // Example destination IP

	if (sendto(vrrpSocket, &vrrp, sizeof(vrrp), state->state, (struct sockaddr*)&dest_addr, sizeof(dest_addr)) == -1) {
		perror("sendto");
		exit(EXIT_FAILURE);
	}
}

int send_arp_packet(pcap_if_t* interface, int sockClient, uint8_t vrid, struct sockaddr_in* detected_ipv4) {

	unsigned int msgLen = sizeof(struct eth_hdr_t) + sizeof(struct arpHdr);

	if (msgLen < 60) {
		msgLen = 60;
	}

	uint8_t* msg = (uint8_t*)malloc(msgLen);
	if (msg == NULL) {
		perror("malloc()");
		close(sockClient);
		return -1;
	}

	memset(msg, 0, msgLen);
	struct ethHdr* eth;
	eth = (struct ethHdr*)msg;
	pcap_addr_t* address = interface->addresses;
	while (address) {
		if (address->addr && address->addr->sa_family == AF_PACKET) {

			struct sockaddr_ll* sll = (struct sockaddr_ll*)address->addr;
			memcpy(eth->srcMAC, sll->sll_addr, 6);
			break;
		}
		address = address->next;
	}

	eth->dstMAC[0] = 0x00; // Multicast OUI
	eth->dstMAC[1] = 0x00;
	eth->dstMAC[2] = 0x5E;
	eth->dstMAC[3] = 0x00;
	eth->dstMAC[4] = 0x00;
	eth->dstMAC[5] = vrid; // VRID

	eth->ethertype = htons(ARP_ETHER_TYPE);

	struct arpHdr* arp;
	arp = (struct arpHdr*)eth->payload;
	arp->hwType = htons(HW_TYPE);
	arp->protoType = htons(ARP_ETHER_TYPE);
	arp->hwLen = HW_LEN;
	arp->protoLen = IP_LEN;
	arp->opcode = htons(GRATUITOUS_ARP_OPCODE); // ARP opcode 

	for (int i = 5; i >= 0; i--) {
		arp->srcMAC[i] = eth->srcMAC[i];
	}

	arp->srcIP = detected_ipv4->sin_addr.s_addr;

	char vrrpBroadcast[] = "224.0.0.18";
	struct in_addr vrrpBroadcastBinary;
	arp->targetIP = arp->srcIP;

	if (write(sockClient, msg, msgLen) == -1) {
		perror("write()");
		close(sockClient);
		free((void*)msg);
		return -1;
	}
}
void receive_vrrp_packet(vrrp_state_t* state) {

}