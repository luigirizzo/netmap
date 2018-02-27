#include <net/ethernet.h>
#include <net/if.h>
#include <net/netmap.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/udp.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#define NETMAP_WITH_LIBS
#include <net/netmap_user.h>

#define ETH_ADDR_LEN 6

struct Global {
	struct nm_desc *nmd;
	const char *ifname;
	unsigned wait_secs;
#define MAX_PKT_SIZE 65536
	char pktm[MAX_PKT_SIZE]; /* packet model */
	unsigned pktm_len;       /* packet model len */
	char src_mac[ETH_ADDR_LEN];
	char dst_mac[ETH_ADDR_LEN];
	uint32_t src_ip;
	uint32_t dst_ip;
	uint16_t src_port;
	uint16_t dst_port;
	char filler;
};

static void
fill_packet_field(struct Global *g, unsigned offset, const char *content,
		  unsigned content_len)
{
	if (offset + content_len > sizeof(g->pktm)) {
		printf("Packet layout overflow: %u + %u > %lu\n", offset,
		       content_len, sizeof(g->pktm));
		exit(EXIT_FAILURE);
	}

	memcpy(g->pktm + offset, content, content_len);
}

static void
fill_packet_8bit(struct Global *g, unsigned offset, uint8_t val)
{
	fill_packet_field(g, offset, (const char *)&val, sizeof(val));
}

static void
fill_packet_16bit(struct Global *g, unsigned offset, uint16_t val)
{
	val = htons(val);
	fill_packet_field(g, offset, (const char *)&val, sizeof(val));
}

static void
fill_packet_32bit(struct Global *g, unsigned offset, uint32_t val)
{
	val = htonl(val);
	fill_packet_field(g, offset, (const char *)&val, sizeof(val));
}

static void
build_packet(struct Global *g)
{
	unsigned ofs = 0, hdrofs = 0;

	memset(g->pktm, 0, sizeof(g->pktm));
	printf("%s: starting at ofs %u\n", __func__, ofs);

	hdrofs = ofs;
	/* Ethernet destination and source MAC address plus ethertype. */
	fill_packet_field(g, ofs, g->dst_mac, ETH_ADDR_LEN);
	ofs += ETH_ADDR_LEN;
	fill_packet_field(g, ofs, g->src_mac, ETH_ADDR_LEN);
	ofs += ETH_ADDR_LEN;
	fill_packet_16bit(g, ofs, ETHERTYPE_IP);
	ofs += 2;
	printf("%s: eth done, ofs %u\n", __func__, ofs);

	hdrofs = ofs;
	/* First byte of IP header. */
	fill_packet_8bit(g, ofs,
			 (IPVERSION << 4) | ((sizeof(struct iphdr)) >> 2));
	ofs += 1;
	/* Skip QoS byte. */
	ofs += 1;
	/* Total length. */
	fill_packet_16bit(g, ofs, g->pktm_len - hdrofs);
	ofs += 2;
	/* Skip identification field. */
	ofs += 2;
	/* Offset (and flags) field. */
	fill_packet_16bit(g, ofs, IP_DF);
	ofs += 2;
	/* TTL. */
	fill_packet_8bit(g, ofs, IPDEFTTL);
	ofs += 1;
	/* Protocol. */
	fill_packet_8bit(g, ofs, IPPROTO_UDP);
	ofs += 1;
	/* Skip checksum for now. */
	ofs += 2;
	/* Source IP address. */
	fill_packet_32bit(g, ofs, g->src_ip);
	ofs += 4;
	/* Dst IP address. */
	fill_packet_32bit(g, ofs, g->dst_ip);
	ofs += 4;
	printf("%s: ip done, ofs %u\n", __func__, ofs);

	hdrofs = ofs;
	/* UDP source port. */
	fill_packet_16bit(g, ofs, g->src_port);
	ofs += 2;
	/* UDP source port. */
	fill_packet_16bit(g, ofs, g->dst_port);
	ofs += 2;
	/* UDP length (UDP header + data). */
	fill_packet_16bit(g, ofs, g->pktm_len - hdrofs);
	ofs += 2;
	/* Skip checksum for now. */
	ofs += 2;
	printf("%s: udp done, ofs %u\n", __func__, ofs);

	/* Fill UDP payload. */
	for (; ofs < g->pktm_len; ofs++) {
		fill_packet_8bit(g, ofs, g->filler);
	}
}

static struct Global _g;

static void
usage(void)
{
	printf("usage: ./functional [-h]\n"
	       "-i NETMAP_PORT\n"
	       "[-l PACKET_LEN (=6)]\n"
	       "[-w WAIT_LINK_SECS (=0)]\n");
}

int
main(int argc, char **argv)
{
	struct Global *g = &_g;
	int opt;
	int i;

	g->ifname    = NULL;
	g->nmd       = NULL;
	g->wait_secs = 0;
	g->pktm_len  = 60;
	for (i = 0; i < ETH_ADDR_LEN; i++)
		g->src_mac[i] = 0x00;
	for (i = 0; i < ETH_ADDR_LEN; i++)
		g->dst_mac[i] = 0xFF;
	g->src_ip = 0x0A000005; /* 10.0.0.5 */
	g->dst_ip = 0x0A000007; /* 10.0.0.7 */
	g->filler = 'a';

	while ((opt = getopt(argc, argv, "hi:w:l:")) != -1) {
		switch (opt) {
		case 'h':
			usage();
			return 0;

		case 'i':
			g->ifname = optarg;
			break;

		case 'w':
			g->wait_secs = atoi(optarg);
			break;

		case 'l':
			g->pktm_len = atoi(optarg);
			break;

		default:
			printf("    Unrecognized option %c\n", opt);
			usage();
			return -1;
		}
	}

	if (!g->ifname) {
		printf("Missing ifname\n");
		usage();
		return -1;
	}

	g->nmd = nm_open(g->ifname, NULL, 0, NULL);
	if (g->nmd == NULL) {
		printf("Failed to nm_open(%s)\n", g->ifname);
		return -1;
	}

	build_packet(g);

	nm_close(g->nmd);

	return 0;
}
