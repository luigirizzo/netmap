#ifndef _NETMAP_TEST_USERSPACE_H_


/*
 * Print the ring.
 *
 * @d netmap descriptor pointer.
 * @n netmap_if descriptor pointer.
 * @r netmap_ring descriptor pointer.
 * @t name of the ring field ([tx,rx]_rings).
 * @nd number of descriptors inside the ring.
 * @ds size of each descriptor.
 *
 * Print only the slots containing data.
 * Example:
 *     head: 10
 *     tail: 8
 */ 
#define PRINT_NIF_RING(d, n, r, t, nd, ds)				\
do {									\
	printf("head: %d\n"						\
	       "tail: %d\n"						\
	       "",							\
	       (r)->head,						\
	       (r)->tail						\
	      );							\
} while (0)


/*
 * Print the i-th transmit ring.
 *
 * @d netmap descriptor pointer.
 * @n netmap_if descriptor pointer.
 * @i index of the ring.
 */
#define PRINT_NIF_TX_RING(d, n, i)					\
	PRINT_NIF_RING(d, n, NETMAP_TXRING(n, i),			\
		       tx_rings, (n)->num_tx_descs, (n)->tx_desc_size)


/*
 * Print the i-th receive ring.
 *
 * @d netmap descriptor pointer.
 * @n netmap_if descriptor pointer.
 * @i index of the ring.
 */
#define PRINT_NIF_RX_RING(d, n, i)					\
	PRINT_NIF_RING(d, n, NETMAP_RX_RING(d, n, i),			\
		       rx_rings, (n)->num_rx_descs, (n)->rx_desc_size)


/*
 * Print a netmap interface descriptor.
 *
 * @n netmap_if descriptor.
 *
 * Example:
 *     netmap-interface:
 *     -----------------
 *     Name: em0 # queues: 1
 */
#define PRINT_NIF(n)							\
do  {									\
	printf("netmap-interface:\n"					\
	       "-----------------\n"					\
	       "Name: %s #queues: %d #desc-per-que: %d\n"		\
	       "",							\
	       (n)->ni_name,						\
	       (n)->ni_num_queues,					\
	       NETMAP_TXRING(n, 0)->num_slots			\
	      );							\
} while (0)



/*
 * Print an ethernet address.
 *
 * A colon symbol is added between each character, and a new-line
 * character is put at the end.
 * Example:
 *     08:00:27:3d:43:fd
 */
#define PRINT_ETH_ADDR(addr)						\
do {									\
	int _i;								\
	u_char *_ptr;							\
									\
	_ptr = (addr);							\
	_i = ETHER_ADDR_LEN;						\
	do {								\
		printf("%s%02x",					\
		       (_i == ETHER_ADDR_LEN) ? "" : ":",		\
			*_ptr++);					\
	} while (--_i > 0);						\
	printf("\n");							\
} while (0)

/*
 * Print an Ethernet header.
 *
 * Example:
 *     Ethernet header:
 *     ----------------
 *     Type: 0800
 *     Source: 08:00:27:3d:43:fd
 *     Destination: ff:ff:ff:ff:ff:ff
 */
#define PRINT_ETH_PKT(eh)						\
do {									\
	printf("Ethernet header:\n");					\
	printf("----------------\n");					\
	printf("Type: %04x\n", ntohs((eh)->ether_type));		\
	printf("Source Address: ");					\
	PRINT_ETH_ADDR((eh)->ether_shost);				\
	printf("Destination Address: ");				\
	PRINT_ETH_ADDR((eh)->ether_dhost);				\
} while (0)


/*
 * Print an Arp packet.
 *
 * Example:
 *     Arp header:
 *     -----------
 *     htype: 0001	ptype: 0800
 *     hlen: 6	plen: 4
 *     oper: 1
 *     sha: 52:54:00:12:34:56
 *     spa: 10.0.2.222
 *     tha: 00:00:00:00:00:00
 *     tpa: 10.0.2.15
 */
#define PRINT_ARP_PKT(arp)						\
do {									\
	printf("Arp header:\n");					\
	printf("-----------\n");					\
	printf("htype: %04x\tptype: %04x\n",				\
	       ntohs(arp->htype), ntohs(arp->ptype));			\
	printf("hlen: %u\tplen: %u\n", arp->hlen, arp->plen);		\
	printf("oper: %d\n", ntohs(arp->oper));				\
	printf("sha: ");						\
	PRINT_ETH_ADDR(arp->sha);					\
	printf("spa: %s\n", inet_ntoa(*(struct in_addr *) arp->spa));	\
	printf("tha: ");						\
	PRINT_ETH_ADDR(arp->tha);					\
	printf("tpa: %s\n", inet_ntoa(*(struct in_addr *) arp->tpa));	\
} while (0)


/*
 * Print an IP header.
 *
 * Example:
 *    Ip header:
 *    ----------
 *    Length: 54
 *    Source: 192.168.0.1
 *    Destination: 192.168.0.22
 */
#define PRINT_IP_PKT(ip)						\
do {									\
	printf("Ip header:\n");						\
	printf("----------\n");						\
	printf("Length: %u\n", ntohs((ip)->ip_len));			\
	printf("Source Address: %s\n", inet_ntoa((ip)->ip_src));	\
	printf("Destination Address: %s\n",				\
	       inet_ntoa((ip)->ip_dst));				\
} while (0)


#endif /* _NETMAP_TEST_USERSPACE_H_ */
