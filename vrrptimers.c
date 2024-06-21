#include "vrrp.h"
#include "vrrptimers.h"

void* advertisementTimerThreadFunction(void* vargp) {
    struct thread_creation_arguments* threadArgs = (struct thread_creation_arguments*)vargp;

    while (threadArgs->state->advertisement_interval > 0) {
        if (threadArgs->state->advertisement_timer <= -1) {
            sleep(1);
            continue;
        }
        if (threadArgs->state->advertisement_timer > 0) {
            threadArgs->state->advertisement_timer = threadArgs->state->advertisement_timer - 1;
            continue;
        }

        if (threadArgs->state->state == VRRP_STATE_MASTER) {
            send_vrrp_packet(threadArgs->state, threadArgs->pInterface, threadArgs->sock, threadArgs->detected_ipv4);
            threadArgs->state->advertisement_timer = threadArgs->state->advertisement_interval;
        }

        sleep(1);

    }
}

void* masterTimerThreadFunction(void* vargp) {
    struct thread_creation_arguments* threadArgs = (struct thread_creation_arguments*)vargp;
    
    while (threadArgs->state->master_down_interval > 0) {
        
        if (threadArgs->state->master_down_timer <= -1) {
            sleep(1);
            continue;
        }
        if (threadArgs->state->master_down_timer > 0) {
            threadArgs->state->master_down_timer = threadArgs->state->master_down_timer - 1;
            continue;
        }

        if (threadArgs->state->state == VRRP_STATE_BACKUP && threadArgs->state->master_down_timer == 0) {
            send_vrrp_packet(threadArgs->state, threadArgs->pInterface, threadArgs->sock, threadArgs->detected_ipv4);
            send_arp_packet(threadArgs->pInterface, threadArgs->sock, threadArgs->state->vrid, threadArgs->detected_ipv4);
            threadArgs->state->advertisement_timer = threadArgs->state->advertisement_interval;
            threadArgs->state->state = VRRP_STATE_MASTER;
        }

        
        sleep(1);
    }
}