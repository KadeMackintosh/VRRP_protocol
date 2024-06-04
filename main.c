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
                    i++;
                    break;  // Move to the next interface after printing
                }
            }
            address = address->next;
        }
        interface = interface->next;
    }

    if (i > 2) {
        char input[100];
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

    // Free the list of interfaces
    pcap_freealldevs(interfaces);

    // // Initialize VRRP state structure
    // uint8_t vrid = 1;                // Virtual Router ID
    // uint8_t priority = 100;          // VRRP priority
    // uint16_t interval = 3;           // Advertisement interval in seconds
    // uint32_t ip_address;             // IP address in network byte order

    // // Convert IP address from string to network byte order
    // if (inet_pton(AF_INET, "192.168.1.1", &ip_address) != 1) {
    //     perror("inet_pton");
    //     exit(EXIT_FAILURE);
    // }

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
