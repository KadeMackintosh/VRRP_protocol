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

struct thread_creation_arguments {
    int sock;
    vrrp_state* state;
	pcap_if_t* pInterface;
    struct sockaddr_in* detected_ipv4;
}args;

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

void* arpListenerThreadFunction(void* vargp)
{
    struct thread_creation_arguments* threadArgs = (struct thread_creation_arguments *) vargp;
    
    //ToDo:
    struct ethhdr* response = (struct ethhdr*) malloc(sizeof(struct ethhdr) + sizeof(struct arpHdr));

    char buff[1500];
    int sock2;
    if ((sock2 = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP))) == -1)
    {
        perror("SOCKET:");
        exit(EXIT_FAILURE);
    }
    struct sockaddr_ll cAddr;
    memset(&cAddr, 0, sizeof(cAddr));
    cAddr.sll_family = AF_PACKET;
    cAddr.sll_protocol = htons(ETH_P_ARP);
    // cAddr.sll_halen = ETH_ALEN;
    // char mac_addr[ETH_ALEN] = "\0x00\0x5E\0x00\0x00\0x01";
    // memcpy(cAddr.sll_addr, mac_addr, ETH_ALEN);
    cAddr.sll_ifindex = 2; // poradie interface
    if (bind(sock2, (struct sockaddr*) &cAddr, sizeof(cAddr)) == -1) {
        perror("bind()");
        close(sock2);
        exit(EXIT_FAILURE);
    }
    while (1) {
        //struct arpHdr* arp_resp = (struct arpHdr*)response + 1;
// _source 
        memset(buff, 0, 1500);

        
        //read(sock2, response, sizeof(struct ethhdr) + sizeof(struct arpHdr));
        //recvfrom(sock2, buff, 1500, 0, (struct sockaddr*) &cAddr, sizeof(cAddr)
        if (recvfrom(sock2, buff, 1500, 0, NULL, NULL) < 0)
        {
            close(sock2);
            fprintf(stderr, "%s: nejde recv v arp\n", strerror(errno));
            exit(1);
        }
        

        for(int i = 0; i < ETH_ALEN; ++i) {
            printf("%02x", buff[i]);
            if(i < ETH_ALEN - 1) printf(":");
        }
        // struct ethhdr* eth = (struct ethhdr*)buff;
        // struct arpHdr *arp;


        // printf("Ethernet Header:\n");
        // printf("Destination MAC: ");
        // for(int i = 0; i < ETH_ALEN; ++i) {
        //     printf("%02x", eth->h_dest[i]);
        //     if(i < ETH_ALEN - 1) printf(":");
        // }
        // printf("\nSource MAC: ");
        // for(int i = 0; i < ETH_ALEN; ++i) {
        //     printf("%02x", eth->h_source[i]);
        //     if(i < ETH_ALEN - 1) printf(":");
        // }
        // printf("\nType: %04x\n", ntohs(eth->h_proto));

        // // Print ARP header
        // printf("ARP Header:\n");
        // printf("Hardware Type: %d\n", ntohs(arp->htype));
        // printf("Protocol Type: %d\n", ntohs(arp->ptype));
        // printf("Hardware Address Length: %d\n", arp->hlen);
        // printf("Protocol Address Length: %d\n", arp->plen);
        // printf("Operation: %d\n", ntohs(arp->opcode));
        // printf("Sender Hardware Address: ");
        // for(int i = 0; i < ETH_ALEN; ++i) {
        //     printf("%02x", arp->sha[i]);
        //     if(i < ETH_ALEN - 1) printf(":");
        // }
        // printf("\nSender Protocol Address: %s\n", inet_ntoa(*(struct in_addr *)&arp->spa));
        // printf("Target Hardware Address: ");
        // for(int i = 0; i < ETH_ALEN; ++i) {
        //     printf("%02x", arp->tha[i]);
        //     if(i < ETH_ALEN - 1) printf(":");
        // }
        // printf("\nTarget Protocol Address: %s\n", inet_ntoa(*(struct in_addr *)&arp->tpa));

        // // Check for gratuitous ARP packet
        // if(ntohs(arp->opcode) == ARPOP_REQUEST && memcmp(arp->sha, arp->tha, 6) == 0) {
        //     printf("Gratuitous ARP packet detected.\n");
        // }

        // fflush(stdout);
        
        // // // Flush stdout to ensure immediate display
        // fflush(stdout);
        
        // if (ntohs(eth->h_proto) == ETH_P_ARP) {
        //     arp = (struct arpHdr *)(buff + sizeof(struct ethhdr));

        //     // Check if it's a gratuitous ARP packet
        //     if (ntohs(arp->opcode) == ARPOP_REQUEST &&
        //         memcmp(arp->srcMAC, arp->targetMAC, 6) == 0) {
        //         fprintf(stdout, "Gratuitous ARP packet detected:\n");
        //         fflush(stdout);
        //         //printf("\nSender IP: %s\n", inet_ntoa(*(struct in_addr *)&arp->srcIP));
        //     }
        // }

        // if (response->h_source != htons(ARP_ETHER_TYPE)) {
        //     continue;
        // }
        //     // Print to the console
        // fprintf(stdout, "Instant print, connection made\n");
        
        // // Flush stdout to ensure immediate display
        // fflush(stdout);
        // if (arp_resp->opcode == htons(GRATUITOUS_ARP_OPCODE)) {
        //     struct in_addr src_ip;
        //     src_ip.s_addr = arp_resp->srcIP;

        //     fprintf(stdout, "Response from %s at %02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx\n",
        //         inet_ntoa(src_ip),
        //         arp_resp->srcMAC[0],
        //         arp_resp->srcMAC[1],
        //         arp_resp->srcMAC[2],
        //         arp_resp->srcMAC[3],
        //         arp_resp->srcMAC[4],
        //         arp_resp->srcMAC[5]);
            
        //     fflush(stdout);
        //     continue;
        // }
    }
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
    pthread_t arpListenerThread, vrrpListenerThread;

    init_state(&state, interfaces, sock, detected_ipv4);

    pthread_create(&arpListenerThread, NULL, arpListenerThreadFunction, (void*)&threadArgs);
    printf("Init ARP thread listener\n");


    // pthread_create(&vrrpListenerThread, NULL, vrrpListenerThreadFunction, (void*)&threadArgs);
    // printf("Init VRRP thread listener\n");
    
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

