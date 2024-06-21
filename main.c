// main.c
#include "vrrp.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h> // for sleep()
#include <arpa/inet.h> // for inet_pton

#include <netpacket/packet.h>
#include <net/ethernet.h>
#include <netinet/if_ether.h>
#include <net/if_arp.h>
#include <errno.h>
#include <asm-generic/socket.h>

struct thread_creation_arguments {
    int sock;
    vrrp_state* state;
	pcap_if_t* pInterface;
    struct sockaddr_in* detected_ipv4;
}args;
#include "vrrptimers.h"

void print_mac_address(uint8_t* mac) {
    for (int i = 0; i < 6; i++) {
        printf("%02x", mac[i]);
        if (i < 5) printf(":");
    }
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
    struct ethhdr* response = (struct ethHdr*) malloc (sizeof(struct ethhdr));
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
    while (1) {
        memset(response, 0, 1500);

        char buffer[1024] = { 0 };
        read(sock2, response, 1500);
        int velkostEthHdr =  sizeof(struct ethhdr);
        char* testik = response + 14;
        struct ipHdr* ipHdrValue = response + 1;

        if (response->h_proto != htons(112)) {
            continue;
        }

        printf("%s", ipHdrValue);
        // Print to the console
        fprintf(stdout, "Instant print, vrrpListenerThreadFunction\n");

        // Flush stdout to ensure immediate display
        fflush(stdout);
        continue;
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
        int data_size = recvfrom(sockfd, buffer, ETH_FRAME_LEN, 0, &saddr, &saddr_len);
        if (data_size < 0) {
            perror("Recvfrom error");
            close(sockfd);
            return NULL;
        }

        // Get Ethernet header
        struct ethhdr* eth = (struct ethhdr*) buffer;

        printf("Raw buffer data:\n");
        print_buffer(buffer, data_size);

        // Check if it's an ARP packet
        if (ntohs(eth->h_proto) == ETH_P_ARP) {
            struct arpHdr* arp = (struct arpHdr*) (buffer + sizeof(struct ethhdr));
            printf("Received ARP packet:\n");
            printf("Sender MAC: ");
            print_mac_address(eth->h_source);
            //ToDO!!!
           // printf("\nSender IP: %s\n", inet_ntoa(*(struct in_addr*)arp->srcIP));
            printf("Target MAC: ");
            print_mac_address(eth->h_dest);
            //ToDO!!!
            //printf("\nTarget IP: %s\n", inet_ntoa(*(struct in_addr*)arp->targetIP));
            printf("\n\n");
        }
    }

    close(sockfd);
    return NULL;
}


int main() {

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



    struct thread_creation_arguments threadArgs = {sock, &state, interfaces, detected_ipv4 };
    pthread_t arpListenerThread, vrrpListenerThread, advertisementTimerThread, masterTimerThread;

    init_state(&state, interfaces, sock, detected_ipv4);

    pthread_create(&arpListenerThread, NULL, arpListenerThreadFunction, (void*)&threadArgs);
    printf("Init ARP thread listener\n");


    // pthread_create(&vrrpListenerThread, NULL, vrrpListenerThreadFunction, (void*)&threadArgs);
    // printf("Init VRRP thread listener\n");
    
    pthread_create(&advertisementTimerThread, NULL, advertisementTimerThreadFunction, (void*)&threadArgs);
    pthread_create(&masterTimerThread, NULL, masterTimerThreadFunction, (void*)&threadArgs);
    // todo test
    //send_vrrp_packet(&state, interfaces, sock, detected_ipv4);
    // printf("poslali sme veci");
    while (1) {
        //send_vrrp_packet(&state);
        //receive_vrrp_packet(&state);
        sleep(5); // Sleep for the advertisement interval
    }

    pthread_join(&arpListenerThread);
    pthread_join(&vrrpListenerThread);
    // Free the list of interfaces
    pcap_freealldevs(interfaces);

    return EXIT_SUCCESS;
}

