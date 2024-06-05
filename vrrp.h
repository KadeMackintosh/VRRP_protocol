// vrrp.h
#ifndef VRRP_H
#define VRRP_H

#include <stdint.h>
#include <pcap.h>

#define VRRP_VERSION 2
#define VRRP_TYPE_ADVERTISEMENT 1

typedef struct vrrp_packet_t {
    uint8_t version_type;
    uint8_t vrid;
    uint8_t priority;
    uint8_t count_ip;
    uint16_t auth_type;
    uint16_t advertisement_interval;
    uint16_t checksum;
    uint32_t ip_addresses[1]; // Flexible array member for IP addresses
} __attribute__((packed)) vrrp_packet_t;

typedef struct eth_hdr_t {
    uint8_t dst_mac[6];    
    uint8_t src_mac[6];
    uint16_t ethertype;
    struct vrrp_packet_t vrrp;
} __attribute__((packed)) eth_hdr_t;

typedef struct {
    uint8_t state; // INIT, BACKUP, MASTER
    uint8_t priority;
    uint8_t vrid;
    uint16_t advertisement_interval;
    uint32_t ip_address;
    pcap_t *pcap_handle;
} vrrp_state_t;

void init_vrrp(vrrp_state_t *state, pcap_if_t *interface, int sock, uint8_t vrid, uint8_t priority, uint16_t interval, uint32_t ip_address);
void send_vrrp_packet(vrrp_state_t *state);
void receive_vrrp_packet(vrrp_state_t *state);

#endif // VRRP_H
