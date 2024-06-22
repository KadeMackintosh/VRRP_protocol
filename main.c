// main.c
#include "vrrp.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h> // for sleep()
#include <arpa/inet.h> // for inet_pton
#include <netinet/ip.h>
#include <netpacket/packet.h>
#include <net/ethernet.h>
#include <netinet/if_ether.h>
#include <net/if_arp.h>
#include <errno.h>
#include <asm-generic/socket.h>

#include "vrrptimers.h"

void print_mac_address(uint8_t* mac) {
    for (int i = 0; i < 6; i++) {
        printf("%02x", mac[i]);
        if (i < 5) printf(":");
    }
    printf("\n");
}

// Function to print buffer in hexadecimal format
void print_buffer(uint8_t* buffer, int length) {
    for (int i = 0; i < length; i++) {
        printf("%02x ", buffer[i]);
        if ((i + 1) % 16 == 0) {
            printf("\n");
        }
    }
    printf("\n");
}

void* vrrpListenerThreadFunction(void* vargp)
{
    struct thread_creation_arguments* threadArgs = (struct thread_creation_arguments*)vargp;
    uint8_t buffer[ETH_FRAME_LEN];

    int sock2;
    if ((sock2 = socket(AF_PACKET, SOCK_RAW, 0)) == -1)
    {
        perror("SOCKET:");
        exit(EXIT_FAILURE);
    }
    struct sockaddr_ll cAddr;
    memset(&cAddr, 0, sizeof(cAddr));
    cAddr.sll_family = AF_PACKET;
    cAddr.sll_protocol = htons(ETH_P_ALL);
    if (bind(sock2, (struct sockaddr*)&cAddr, sizeof(cAddr)) == -1) {
        perror("bind()");
        close(sock2);
        exit(EXIT_FAILURE);
    }
    struct sockaddr_ll* sll = (struct sockaddr_ll*)threadArgs->pInterface->addresses->addr;
    uint8_t routerMacAddress[6];
    memcpy(routerMacAddress, sll->sll_addr, 6);
    while (1) {
        memset(&buffer, 0, ETH_FRAME_LEN);

        read(sock2, buffer, ETH_FRAME_LEN);
        struct ethhdr* eth = (struct ethhdr*)buffer;
        struct iphdr* ipHeader = (struct iphdr*)(buffer + sizeof(struct ethhdr));
        struct vrrp_header* vrrpHeader = (struct vrrp_header*)(buffer + sizeof(struct ethhdr) + sizeof(struct iphdr));

        if (ipHeader->protocol == 112) {
            if (verify_vrrp_packet(threadArgs->state, ipHeader, vrrpHeader) == -1) {
                continue;
            }

            if (threadArgs->state->state == VRRP_STATE_BACKUP) {
                if (vrrpHeader->ip_addresses == threadArgs->detected_ipv4 ||
                    eth->h_dest == routerMacAddress) {
                    continue;
                }

                if (vrrpHeader->priority == 0) {
                    threadArgs->state->master_down_timer = threadArgs->state->skew_time;
                }
                else {
                    if (threadArgs->state->preempt_mode == 0 || vrrpHeader->priority >= threadArgs->state->priority) {
                        threadArgs->state->master_down_timer = threadArgs->state->master_down_interval;
                    }
                    else {
                        continue;
                    }
                }
            }
            printf("%d", vrrpHeader->priority);
        }
    }
    return NULL;
    }

void* arpListenerThreadFunction(void* vargp) {
    struct thread_creation_arguments* threadArgs = (struct thread_creation_arguments*) vargp;
    pcap_if_t* interface = threadArgs->pInterface;
    int sockfd;
    uint8_t buffer[ETH_FRAME_LEN];
    
    struct sockaddr saddr;
    socklen_t saddr_len = sizeof(struct sockaddr);

    // Create raw socket
    if ((sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP))) < 0) {
        perror("Socket creation failed");
        return NULL;
    }

    // Bind to the specified interface
    if (setsockopt(sockfd, SOL_SOCKET, SO_BINDTODEVICE, interface->name, strlen(interface->name)) < 0) {
        perror("arpListenerThreadFunction: Binding to interface failed");
        close(sockfd);
        return NULL;
    }

    while (1) {
        // Receive packet
        memset(buffer, 0, ETH_FRAME_LEN);
        int data_size = read(sockfd, buffer, ETH_FRAME_LEN);
        if (data_size < 0) {
            perror("Recvfrom error");
            close(sockfd);
            return NULL;
        }

        // Get Ethernet header
        struct ethhdr* eth = (struct ethhdr*) buffer;

        // Check if it's an ARP packet addressed to the VRRP multicast mac address:
        unsigned char vrrp_multicast_mac[6] = {0x01, 0x00, 0x5e, 0x00, 0x00, 0x01};
        unsigned char my_mac[6] = {0x08,0x00,0x27,0x9c,0xc5,0x88}; 
        //ToDo: use dynamic my_mac from interface, and make sure I don't listen and respond to my own arp requests!

        if ((ntohs(eth->h_proto) == ETH_P_ARP) && 
        (memcmp(eth->h_dest, vrrp_multicast_mac, 6) == 0)) {

            printf("\nReceived ARP packet --->\n");
            printf("Raw buffer data:\n");
            print_buffer(buffer, data_size);

            struct arpHdr* arp = (struct arpHdr*) (buffer + sizeof(struct ethhdr));
            printf("ETH_DST_MAC: ");
            print_mac_address(eth->h_dest);
            // printf("\nSender IP: %s\n", arp->srcIP);
            // printf("\nTarget IP: %s\n", arp->targetIP);
            printf("ETH_SRC_MAC: ");
            print_mac_address(eth->h_source);
            printf("\n\n");

            
            //TODO: treba akceptovat init ARP a asi nan odpovedat alebo co...

        }
    }

    close(sockfd);
    return NULL;
}


int main() {

    setbuf(stdout, NULL);
    char errbuf[PCAP_ERRBUF_SIZE];
    struct sockaddr_in* detected_ipv4;
    pcap_if_t *interfaces;
    if (pcap_findalldevs(&interfaces, errbuf) == -1) {
        fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
        return 1;
    }


    int i = 1;
    pcap_if_t *interface = interfaces;
    while (interface) {
        pcap_addr_t *address = interface->addresses;
        
        // Iterate through all addresses of the interface
        while (address) {
            // Check if the address is valid and is of type IPv4
            if (address->addr && address->addr->sa_family == AF_INET) {
                // Check the interface flags
                if ((interface->flags & PCAP_IF_UP) &&  // Interface is up
                    (interface->flags & PCAP_IF_RUNNING) &&  // Interface is running
                    !(interface->flags & PCAP_IF_LOOPBACK))  // Interface is not loopback
                {
                    printf("%d.) %s \n", i, interface->name);
                    detected_ipv4 = (struct sockaddr_in*)address->addr;
                    char ip_str[INET_ADDRSTRLEN];
                    inet_ntop(AF_INET, &(detected_ipv4->sin_addr), ip_str, INET_ADDRSTRLEN);
                    printf("IP address: %s\n", ip_str);
                    i++;
                    break;  // Move to the next interface after printing
                }
            }
            address = address->next;
        }
        interface = interface->next;
    }

    if (i > 2) {
        char input[5];
        int chosen_interface;
        
        printf("Please enter the interface number from the list above, or just press Enter for 1.) %s: \n", interfaces->name);
        fgets(input, sizeof(input), stdin);

        // Check if the input is empty (only contains newline)
        if (strlen(input) <= 1) {
            chosen_interface = 1;  // Set default to 1
        } else {
            chosen_interface = atoi(input);  // Convert string to integer
        }
        
        printf("You entered: %d\n", chosen_interface);

        // Validate chosen_interface
        if (chosen_interface >= 1 && chosen_interface < i) {
            pcap_if_t *chosen_interface_ptr = interfaces;
            for (int j = 1; j < chosen_interface; j++) {
                chosen_interface_ptr = chosen_interface_ptr->next;
            }
            printf("You chose the interface: %s\n", chosen_interface_ptr->name);
        } else {
            fprintf(stderr, "Invalid interface number.\n");
        }
    } else {
        printf("The interface %s was automatically detected and selected.\n", interfaces->name);
    }

    // CREATE SOCKET
    int sock;
    struct sockaddr_ll addr;

    if((sock = socket(AF_PACKET, SOCK_RAW, 0)) == -1)
    {
        perror("SOCKET:");
        exit(EXIT_FAILURE);
    }

    printf("ACTIVE INTERFACE - TO BE USED: %s \n", interfaces->name);

    bzero(&addr, sizeof(addr));
    addr.sll_family = AF_PACKET;
    addr.sll_protocol = htons(ETH_P_ALL);
    if((addr.sll_ifindex = if_nametoindex(interfaces->name)) == 0)
    {
        close(sock);
        perror("if_nametoindex");
        exit(EXIT_FAILURE);
    }

    if(bind(sock, (struct sockaddr *)&addr, sizeof(addr)) == -1)
    {
        close(sock);
        perror("BIND:");
        exit(EXIT_FAILURE);
    }

    vrrp_state state;
    state.state = VRRP_STATE_INIT;
    state.priority = 255;
    state.skew_time = ( (256 - state.priority) / 256 );
    state.advertisement_interval = 1;
    state.master_down_interval = (3 * state.advertisement_interval) + state.skew_time;
    state.ip_address = detected_ipv4->sin_addr.s_addr;
    state.vrid = 1;
    state.authentication_type = 0;
    state.preempt_mode = 1;


    struct thread_creation_arguments threadArgs = {sock, &state, interfaces, detected_ipv4 };
    pthread_t arpListenerThread, vrrpListenerThread, advertisementTimerThread, masterTimerThread;

    init_state(&state, interfaces, sock, detected_ipv4);

    pthread_create(&arpListenerThread, NULL, arpListenerThreadFunction, (void*)&threadArgs);
    printf("Init ARP thread listener\n");


     pthread_create(&vrrpListenerThread, NULL, vrrpListenerThreadFunction, (void*)&threadArgs);
    // printf("Init VRRP thread listener\n");
    
    pthread_create(&advertisementTimerThread, NULL, advertisementTimerThreadFunction, (void*)&threadArgs);
    pthread_create(&masterTimerThread, NULL, masterTimerThreadFunction, (void*)&threadArgs);
    // todo test
    //send_vrrp_packet(&state, interfaces, sock, detected_ipv4);
    // printf("poslali sme veci");

    pthread_join(&arpListenerThread);
    pthread_join(&vrrpListenerThread);
    // Free the list of interfaces
    pcap_freealldevs(interfaces);

    return EXIT_SUCCESS;
}

