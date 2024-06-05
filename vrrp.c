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

// Function to calculate VRRP checksum
uint16_t calculate_checksum(uint16_t *buffer, int size) {
    uint32_t sum = 0;
    for (int i = 0; i < size; ++i) {
        sum += ntohs(buffer[i]);
    }
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    return htons(~sum);
}

void init_vrrp(vrrp_state_t *state, pcap_if_t *interface, int sock, uint8_t vrid, uint8_t priority, uint16_t interval, uint32_t ip_address) {
    // Initialize VRRP state
    state->state = 0; // INIT state
    state->priority = priority;
    state->vrid = vrid;
    state->advertisement_interval = interval;
    state->ip_address = ip_address;

    // Initialize libpcap
    char errbuf[PCAP_ERRBUF_SIZE];
    state->pcap_handle = pcap_open_live(interface->name, BUFSIZ, 1, 1000, errbuf);
    if (state->pcap_handle == NULL) {
        fprintf(stderr, "Could not open device %s: %s\n", interface->name, errbuf);
        exit(EXIT_FAILURE);
    }

    // Prepare the VRRP packet
    struct vrrp_packet_t vrrp;
    memset(&vrrp, 0, sizeof(struct vrrp_packet_t) + sizeof(uint32_t));
    vrrp.version_type = (VRRP_VERSION << 4) | VRRP_TYPE_ADVERTISEMENT;
    vrrp.vrid = vrid;
    vrrp.priority = priority;
    vrrp.count_ip = 1;
    vrrp.advertisement_interval = htons(interval);
    vrrp.ip_addresses[0] = ip_address;
    vrrp.checksum = calculate_checksum((uint16_t *)&vrrp, (sizeof(struct vrrp_packet_t) + sizeof(uint32_t)) / 2);

    // Allocate memory for the Ethernet frame
    struct eth_hdr_t frame;
    memset(&frame, 0, sizeof(frame));

    // Set the destination MAC address to the VRRP multicast MAC address
    frame.dst_mac[0] = 0x01; // Multicast OUI
    frame.dst_mac[1] = 0x00;
    frame.dst_mac[2] = 0x5E;
    frame.dst_mac[3] = 0x00;
    frame.dst_mac[4] = 0x00;
    frame.dst_mac[5] = vrid; // VRID

    // Get source MAC address
    pcap_addr_t *address = interface->addresses;
    while (address) {
        if (address->addr && address->addr->sa_family == AF_PACKET) {
            struct sockaddr_ll *sll = (struct sockaddr_ll *)address->addr;
            memcpy(frame.src_mac, sll->sll_addr, 6);
            break;
        }
        address = address->next;
    }

    frame.ethertype = htons(0x0800); 

    // Copy the VRRP packet into the Ethernet frame
    memcpy(&frame.vrrp, &vrrp, sizeof(vrrp_packet_t) + sizeof(uint32_t));

    // Send the Ethernet frame
    struct sockaddr_ll addr;
    memset(&addr, 0, sizeof(addr));
    addr.sll_family = AF_PACKET;
    addr.sll_protocol = htons(ETH_P_ALL);
    addr.sll_ifindex = if_nametoindex(interface->name);
    addr.sll_halen = ETH_ALEN;
    memcpy(addr.sll_addr, frame.dst_mac, ETH_ALEN);

    if (sendto(sock, &frame, sizeof(frame), 0, (struct sockaddr*)&addr, sizeof(addr)) == -1) {
        perror("sendto");
        exit(EXIT_FAILURE);
    }

    // Transition to BACKUP state
    state->state = 1; // BACKUP state

    printf("VRRP initialized with VRID %d, priority %d, interval %d\n", vrid, priority, interval);
}

void receive_vrrp_packet(vrrp_state_t *state) {

}