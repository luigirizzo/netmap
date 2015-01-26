#ifndef __BUILD__PACKET__HH
#define __BUILD__PACKET__HH

#define _BSD_SOURCE


#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <stdint.h>



/* An UDP packet. */
struct pkt {
    struct ether_header eh;
    struct ip ip;
    struct udphdr udp;
    uint8_t body[2048];
} __attribute__((__packed__));


void build_packet_from_args(int argc, char *argv[], struct pkt * p,
				uint32_t seed, int checksum);

#endif
