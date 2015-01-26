#include "buildpkt.h"


#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/wait.h>
#include <sys/time.h>
#include <time.h>

#include <net/if.h>		/* if_nametoindex() */
#include <netinet/in.h>

#include <arpa/inet.h>

#include <unistd.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <netdb.h>
#include <fcntl.h>
#include <signal.h>

#include <errno.h>



/* Program arguments */
struct arguments {
    u_int8_t dst_mac[6];	/* User specified destination MAC. */
    u_int8_t src_mac[6];	/* User specified source MAC. */
    struct in_addr dst_ip;	/* User specified destination IP. */
    struct in_addr src_ip;	/* User specified source IP. */
    int dst_port;		/* User specified destination port. */
    int src_port;		/* User specified source port. */
    int packet_len;		/* User specified frame length. */
    uint32_t seed;		/* Used to fill the UDP payload. */
    int checksum;        /* Do we calculate the UDP checksum? */
    void *packet;		/* Packet buffer pointer. */
};

/* Compute the checksum of the given ip header. */
static uint16_t checksum(const void *data, uint16_t len, uint32_t sum)
{
    const uint8_t *addr = data;
    uint32_t i;

    /* Checksum all the pairs of bytes first... */
    for (i = 0; i < (len & ~1U); i += 2) {
	sum += (u_int16_t)ntohs(*((u_int16_t *)(addr + i)));
	if (sum > 0xFFFF)
	    sum -= 0xFFFF;
    }
    /*
     * If there's a single byte left over, checksum it, too.
     * Network byte order is big-endian, so the remaining byte is
     * the high byte.
     */
    if (i < len) {
	sum += addr[i] << 8;
	if (sum > 0xFFFF)
	    sum -= 0xFFFF;
    }
    return sum;
}

static u_int16_t wrapsum(u_int32_t sum)
{
    sum = ~sum & 0xFFFF;
    return (htons(sum));
}

static void initialize_packet(struct arguments *a)
{
    struct pkt *pkt = a->packet;
    struct ether_header *eh;
    struct ip *ip;
    struct udphdr *udp;
    uint16_t paylen = a->packet_len - sizeof(*eh) - sizeof(struct ip);
    int i, l, l0 = sizeof(a->seed);

    for (i = 0; i < paylen;) {
	l = l0 < paylen - i ? l0 : paylen - i;
	bcopy(&a->seed, pkt->body + i, l);
	i += l;
    }
    ip = &pkt->ip;

    ip->ip_v = IPVERSION;
    ip->ip_hl = 5;
    ip->ip_id = 0;
    ip->ip_tos = IPTOS_LOWDELAY;
    ip->ip_len = ntohs(a->packet_len - sizeof(*eh));
    ip->ip_id = 0;
    ip->ip_off = htons(IP_DF); /* Don't fragment */
    ip->ip_ttl = IPDEFTTL;
    ip->ip_p = IPPROTO_UDP;
    ip->ip_dst.s_addr = a->dst_ip.s_addr;
    ip->ip_src.s_addr = a->src_ip.s_addr;
    ip->ip_sum = wrapsum(checksum(ip, sizeof(*ip), 0));


    udp = &pkt->udp;
    udp->uh_sport = htons(a->src_port);
    udp->uh_dport = htons(a->dst_port);
    udp->uh_ulen = htons(paylen);
    if (a->checksum) {
        /* Magic: taken from sbin/dhclient/packet.c */
        udp->uh_sum = wrapsum(checksum(udp, sizeof(*udp),
                    checksum(pkt->body,
                        paylen - sizeof(*udp),
                        checksum(&ip->ip_src, 2 * sizeof(ip->ip_src),
                            IPPROTO_UDP + (u_int32_t)ntohs(udp->uh_ulen)
                            )
                        )
                    ));
    } else
        udp->uh_sum = 0;

    eh = &pkt->eh;
    bcopy(a->src_mac, eh->ether_shost, 6);
    bcopy(a->dst_mac, eh->ether_dhost, 6);
    eh->ether_type = htons(ETHERTYPE_IP);
}


static int parse_mac(char *buf, u_int8_t mac[6])
{
    char *p = buf, *q;
    int i = 0;
    long int tmp;

    for (i = 0; i < 6; i++) {
	tmp = strtol(p, &q, 16);
	if ( (i < 5 && *q != ':') || (i == 5 && *q) || tmp < 0 || tmp > 255 ) {
	    return -1;
	}
	mac[i] = tmp;
	p = q + 1;
    }
    return 0;
}

static int fill_arguments(int argc, char *argv[], struct arguments * a)
{
    long payloadsize, srcport, dstport;
    char * dummy;

    /* MAC addresses. */
    if (parse_mac(argv[0], a->dst_mac) < 0) {
	fprintf(stderr, "invalid macaddr: %s\n", argv[0]);
	return -1;
    }

    if (parse_mac(argv[1], a->src_mac) < 0) {
	fprintf(stderr, "invalid macaddr: %s\n", argv[1]);
	return -1;
    }

    /* IP addresses. */
    if (inet_aton(argv[2], &a->dst_ip) == 0) {
	fprintf(stderr, "invalid destination IP: %s\n", argv[2]);
	return -1;
    }

    if (inet_aton(argv[3], &a->src_ip) == 0) {
	fprintf(stderr, "invalid source IP: %s\n", argv[3]);
	return -1;
    }

    /* UDP ports. */
    dstport = strtoul(argv[4], &dummy, 10);
    if (dstport < 0 || dstport > 65536 || *dummy != '\0') {
	fprintf(stderr, "invalid destination port\n");
	return -1;
    }
    a->dst_port = dstport;

    srcport = strtoul(argv[5], &dummy, 10);
    if (srcport < 0 || srcport > 65536 || *dummy != '\0') {
	fprintf(stderr, "invalid source port\n");
	return -1;
    }
    a->src_port = srcport;

    /* Ethernet frame size. */
    payloadsize = strtoul(argv[6], &dummy, 10);
    if (payloadsize < 46 || *dummy != '\0') {
	fprintf(stderr, "payloadsize < 46\n");
	return -1;
    }
    if (payloadsize > 70000) {
	fprintf(stderr, "payloadsize > 1500\n");
	return -1;
    }
    a->packet_len = payloadsize;

    return 0;
}


void build_packet_from_args(int argc, char *argv[], struct pkt * p,
				uint32_t seed, int checksum)
{
    struct arguments a;

    fill_arguments(argc, argv, &a);

    a.packet = p;	/* Memory for *p is allocated from the user. */
    a.seed = seed;
    a.checksum = checksum;

    initialize_packet(&a);
}
