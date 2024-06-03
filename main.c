// main.c
#include "vrrp.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h> // for sleep()
#include <arpa/inet.h> // for inet_pton

int main() {

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *interfaces;
    if (pcap_findalldevs(&interfaces, errbuf) == -1) {
        fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
        return 1;
    }

    printf("Please select an interface: \n");
    int i = 1;
    pcap_if_t *interface = interfaces;
    while (interface) {
        pcap_addr_t *address = interface->addresses;
        // Check if the interface has an IP address and is not a loopback
        if (address && !(address->addr->sa_family == AF_INET && !(interface->flags & PCAP_IF_LOOPBACK))) {
            printf("%i.) %s \n", i, interface->name);
            i++;
        }
        interface = interface->next;
    }


    char input[100];
    int chosen_interface;

    printf("Enter the interface number - press Enter for 1.) %s: \n", interfaces[0].name);
    fgets(input, sizeof(input), stdin);

    // Check if the input is empty (only contains newline)
    if (strlen(input) <= 1) {
        chosen_interface = 1;  // Set default to 1
    } else {
        chosen_interface = atoi(input);  // Convert string to integer
    }
    
    printf("You entered: %d\n", chosen_interface);
    printf("You chose the interface: %s\n", interfaces[chosen_interface-1].name);

    // Free the list of interfaces
    pcap_freealldevs(interfaces);

    // Initialize VRRP state structure
    uint8_t vrid = 1;                // Virtual Router ID
    uint8_t priority = 100;          // VRRP priority
    uint16_t interval = 3;           // Advertisement interval in seconds
    uint32_t ip_address;             // IP address in network byte order

    // Convert IP address from string to network byte order
    if (inet_pton(AF_INET, "192.168.1.1", &ip_address) != 1) {
        perror("inet_pton");
        exit(EXIT_FAILURE);
    }

    // // Call the init_vrrp function to initialize the state
    // init_vrrp(&state, interface->name, vrid, priority, interval, ip_address);

    // // Main event loop to send and receive VRRP packets
    // while (1) {
    //     send_vrrp_packet(&state);
    //     receive_vrrp_packet(&state);
    //     sleep(interval); // Sleep for the advertisement interval
    // }

    return 0;
}
