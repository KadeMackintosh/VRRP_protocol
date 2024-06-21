// vrrp.h
#ifndef VRRP_H
#define VRRP_H

#include <stdint.h>
#include <pcap.h>

#define VRRP_STATE_INIT 0
#define VRRP_STATE_BACKUP 1
#define VRRP_STATE_MASTER 2

#define VRRP_VERSION 2
#define VRRP_TYPE_ADVERTISEMENT 1
#define VRRP_MULTICAST_IPV4 "224.0.0.18"

#define ARP_ETHER_TYPE  (0x0806) //EtherType hodnota pre ARP
#define GRATUITOUS_ARP_OPCODE (2) // Gratuitous ARP opcode - dva
#define HW_LEN	    (6) // MAC adresa = 6B
#define IP_LEN      (4) // IP adresa = 4B
#define IP_PROTO    (0x0800) // IP
#define HW_TYPE     (0x0001) // Ethernet

typedef struct vrrp_header {
    uint8_t version_type;
    uint8_t vrid;
    uint8_t priority;
    uint8_t count_ip;
    uint8_t auth_type;
    uint8_t advertisement_interval;
    uint16_t checksum;
    uint32_t ip_addresses[1]; // Flexible array member for IP addresses
    uint32_t authentication_data;
} __attribute__((packed)) vrrp_packet_t;

struct arpHdr{
	uint16_t hwType;
	uint16_t protoType;
	uint8_t  hwLen;
	uint8_t  protoLen;
	uint16_t opcode;
	uint8_t  srcMAC[6];
	uint32_t srcIP;
	uint8_t  targetMAC[6];
	uint32_t targetIP;
} __attribute__ ((packed));

typedef struct vrrp_state {
    uint8_t state; // INIT, BACKUP, MASTER
    uint8_t priority;
    uint8_t vrid;
    uint8_t advertisement_interval;
    uint16_t master_down_interval; 
    uint16_t advertisement_timer;
    uint16_t master_down_timer; 
    uint8_t authentication_type;
    unsigned char authentication_data[100];
    uint16_t skew_time;
    uint32_t ip_address;
} __attribute__((packed)) vrrp_state;

struct thread_creation_arguments {
    int sock;
    vrrp_state* state;
    pcap_if_t* pInterface;
    struct sockaddr_in* detected_ipv4;
};

void init_state(vrrp_state *state, pcap_if_t *interface, int sock, struct sockaddr_in* detected_ipv4);
int send_vrrp_packet(vrrp_state* state, pcap_if_t* pInterface, int sock, struct sockaddr_in* detected_ipv4);
void receive_vrrp_packet(vrrp_state *state);
int send_arp_packet(pcap_if_t* interface, int sockClient, uint8_t vrid, struct vrrp_state* state);
#endif // VRRP_H
