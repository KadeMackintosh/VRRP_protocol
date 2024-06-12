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

#define ARP_ETHER_TYPE  (0x0806) //EtherType hodnota pre ARP
#define GRATUITOUS_ARP_OPCODE (2) // Gratuitous ARP opcode - dva
#define HW_LEN	    (6) // MAC adresa = 6B
#define IP_LEN      (4) // IP adresa = 4B
#define IP_PROTO    (0x0800) // IP
#define HW_TYPE     (0x0001) // Ethernet

typedef struct vrrp_packet_t {
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

struct ipHdr
  {
#if __BYTE_ORDER == __LITTLE_ENDIAN
    unsigned int ip_hl:4;		/* header length */
    unsigned int ip_v:4;		/* version */
#endif
#if __BYTE_ORDER == __BIG_ENDIAN
    unsigned int ip_v:4;		/* version */
    unsigned int ip_hl:4;		/* header length */
#endif
    uint8_t ip_tos;			/* type of service */
    unsigned short ip_len;		/* total length */
    unsigned short ip_id;		/* identification */
    unsigned short ip_off;		/* fragment offset field */
#define	IP_RF 0x8000			/* reserved fragment flag */
#define	IP_DF 0x4000			/* dont fragment flag */
#define	IP_MF 0x2000			/* more fragments flag */
#define	IP_OFFMASK 0x1fff		/* mask for fragmenting bits */
    uint8_t ip_ttl;			/* time to live */
    uint8_t ip_p;			/* protocol */
    unsigned short ip_sum;		/* checksum */
    struct in_addr ip_src, ip_dst;	/* source and dest address */
  };

struct ethHdr{
	uint8_t  dstMAC[6];
	uint8_t  srcMAC[6];
	uint16_t ethertype;
	uint8_t  payload[0]; // len formalne s 0-velkostou
} __attribute__ ((packed));

typedef struct eth_hdr_t {
    uint8_t dst_mac[6];    
    uint8_t src_mac[6];
    uint16_t ethertype;
    struct vrrp_packet_t vrrp;

} __attribute__((packed)) eth_hdr_t;

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

typedef struct vrrp_state_t {
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
} vrrp_state_t;


void init_state(vrrp_state_t *state, pcap_if_t *interface, int sock, struct sockaddr_in* detected_ipv4);
int send_vrrp_packet(vrrp_state_t* state, pcap_if_t* pInterface, int sock, struct sockaddr_in* detected_ipv4);
void receive_vrrp_packet(vrrp_state_t *state);
int send_arp_packet(pcap_if_t* interface, int sockClient, uint8_t vrid, struct sockaddr_in* detected_ipv4);
#endif // VRRP_H
