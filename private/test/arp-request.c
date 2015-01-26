#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h> /* strcmp */
#include <fcntl.h> /* open */
#include <unistd.h> /* close */
#include <signal.h> /* sigsuspend */

#include <sys/endian.h> /* le64toh */
#include <sys/mman.h> /* PROT_* */
#include <sys/ioctl.h> /* ioctl */
#include <machine/param.h>
#include <sys/poll.h>
#include <sys/socket.h> /* sockaddr.. */
#include <arpa/inet.h> /* ntohs */

#include <net/if.h>	/* ifreq */
#include <net/ethernet.h>
#include <net/netmap.h>
#include <net/netmap_user.h>

#include <netinet/in.h> /* sockaddr_in */

#define MIN(a, b) ((a) < (b) ? (a) : (b))


struct arp {
	u_short htype;
	u_short ptype;
	u_char hlen;
	u_char plen;
	u_short oper;
	u_char sha[6];
	u_char spa[4];
	u_char tha[6];
	u_char tpa[4];
};


static int
get_ip(const char *ifname, struct in_addr *ip)
{
	int s;
	struct ifreq ifreq;

	strcpy(ifreq.ifr_name, ifname);
	if ((s = socket(AF_INET, SOCK_DGRAM, 0)) == -1)
		return (1);

	if (ioctl(s, SIOCGIFADDR, &ifreq) == -1) {
		close(s);
		return (1);
	}

	close(s);

	bcopy(&((struct sockaddr_in *)(&ifreq.ifr_addr))->sin_addr, ip, 4);

	return (0);
}


static void
create_ether(void *pkt, u_char *shost, u_char *dhost)
{
	struct ether_header *eh = (struct ether_header *) pkt;

	memcpy(eh->ether_shost, shost, 6);
	memcpy(eh->ether_dhost, dhost, 6);
	eh->ether_type = htons(ETHERTYPE_ARP);
}


static void
create_arp(void *pkt, u_char *sha, struct in_addr *spa, u_char *tha,
	   struct in_addr *tpa, int oper)
{
	struct arp *arp;

	arp = (struct arp *) pkt;
	arp->htype = htons(1); /* Ethernet */
	arp->ptype = htons(ETHERTYPE_IP);
	arp->hlen = 6;
	arp->plen = 4;
	arp->oper = htons(oper);
	memcpy(arp->sha, sha, 6);
	memcpy(arp->spa, spa, 4);
	if (oper == 2)
		memcpy(arp->tha, tha, 6);
	memcpy(arp->tpa, tpa, 4);
}


static int
send_request(struct netmap_ring *ring, u_char *shost, u_char *dhost,
	     struct in_addr *spa, struct in_addr *tpa, int limit)
{
	struct ether_header *eh;
	struct arp *arp;
	void *pkt;
	int j, m = 0;

	j = ring->nr_cur;
	while(ring->nr_avail > 0 && (m != limit)) {
		pkt = NETMAP_RING_PACKET(ring, j);

		eh = (struct ether_header *) pkt;
		create_ether(pkt, shost, dhost);

		arp = (struct arp *) &eh[1];
		create_arp(arp, shost, spa, dhost, tpa, 1);

		NETMAP_RING_SLOTS(ring)[j].plen = 42;

		ring->nr_avail--;

		j = nm_ring_next(ring, j);
		m++;
	}
	ring->nr_cur = j;

	return (m);
}


static int
receive_reply(struct netmap_ring *ring, struct in_addr *me, int limit,
	      int *received)
{
	struct ether_header *eh;
	struct arp *arp;
	void *pkt;
	int j, m = 0;

	j = ring->nr_cur;
	while (ring->nr_avail > 0 && (m != limit)) {
		pkt = NETMAP_RING_PACKET(ring, j);

		m++;

		eh = (struct ether_header *) pkt;
		if (ntohs(eh->ether_type) != ETHERTYPE_ARP)
			goto next;

		arp = (struct arp *) &eh[1];
		if (ntohs(arp->htype) != 1 ||
		    ntohs(arp->ptype) != ETHERTYPE_IP ||
		    arp->hlen != 6 || arp->plen != 4 ||
		    ntohs(arp->oper) != 2 /* response */ ||
		    memcmp(arp->tpa, me, arp->plen) != 0)
			goto next;

		(*received)++;
next:
		j = NETMAP_RING_NEXT(ring, j);
		ring->nr_cur = j;
	}
	
	return (m);
}


static void
print_output(int received, int sent, double delta)
{

	double pps = received / delta;
	char units[4] = { '\0', 'K', 'M', 'G' };
	int punit = 0;

	while (pps >= 1000) {
		pps /= 1000;
		punit += 1;
	}

	printf("Received %d of %d responses in %.2f seconds.\n",
	       received, sent, delta);
	printf("Speed: %.2f%cpps. Packet loss: %.2f%%.\n",
	       pps, units[punit], (sent - received) * 100.0 / sent);
}


int
main(int arc, char **argv)
{
	int fd, err;
	struct ifreq ifreq;
	struct netmap_if *nifp;
	struct in_addr spa, tpa;
	void *tmp_addr;
	struct pollfd fds[1];
	u_char shost[6], dhost[6] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
	int sent = 0, received = 0, n, burst;
	struct timeval tic, toc;
	double delta;

	if (arc != 5) {
		printf("Usage: %s <ifname> <dest-ip> <n> <burst>\n", argv[0]);
		return (1);
	}

	/* retrieve source ip address. */
	if (get_ip(argv[1], &spa)) {
		printf("Unable to retrieve source IP address.\n");
		return(1);
	}

	/* retrieve destination ip address. */
	if (inet_aton(argv[2], &tpa) == 0) {
		printf("Unable to parse destination IP address.\n");
		return(1);
	}


	/* setup netmap interface. */
	if ((fd = open("/dev/netmap", O_RDWR)) == -1) {
		printf("Unable to open \"/dev/netmap\".\n");
		return (1);
	}

	tmp_addr = (struct netmap_d *) mmap(0, NETMAP_MEMORY_SIZE,
					    PROT_WRITE | PROT_READ,
					    MAP_SHARED, fd, 0);
	if (tmp_addr == MAP_FAILED) {
		printf("Unable to mmap.\n");
		err = 1;
		goto close;
	}

	strcpy(ifreq.ifr_name, argv[1]);
	if ((ioctl(fd, NIOCREGIF, &ifreq)) == -1) {
		printf("Unable to register \"%s\" interface.\n", argv[1]);
		err = 1;
		goto unmap;
	}
	nifp = NETMAP_IF(tmp_addr, ifreq.ifr_data);

	/* retrieve mac address. */
	if ((ioctl(fd, SIOCGIFADDR, &ifreq)) == -1) {
		printf("Unable to retrieve MAC address.\n");
		err = 1;
		goto unmap;
	}
	bcopy(&ifreq.ifr_addr.sa_data, shost, 6);

	/* how many packets. */
	n = atoi(argv[3]);

	/* packets burst size. */
	burst = atoi(argv[4]);

	/* setup poll(2) machanism. */
	memset(fds, 0, sizeof(fds));
	fds[0].fd = fd;
	fds[0].events = (POLLOUT | POLLIN);

	/* Sleep to give the registered interface some to time to
	   bootstrap. */
	printf("Sleeping 5 secs..\n");
	sleep(5);

	/* main loop */
	gettimeofday(&tic, NULL);
	while (1) {
		struct netmap_ring *txring, *rxring;
		int limit, m;

		/* Invoke the poll(2) mechanism.
		   Wait at most 1 second before quitting. */
		if (poll(fds, 1, 1 * 1000) <= 0) {
			gettimeofday(&toc, NULL);
			toc.tv_sec -= 1;
			delta = toc.tv_sec - tic.tv_sec +
				(toc.tv_usec - tic.tv_usec) / 1000000.0;
			print_output(received, sent, delta);
			break;
		}


		/* Process received packets. */
		if (fds[0].revents & POLLIN) {
			limit = MIN(burst, n - received);
			for (int i = 0; i < nifp->ni_num_queues; i++) {
				rxring = NETMAP_RX_RING(nifp, i);
				if (rxring->nr_avail == 0)
					continue;

				m = receive_reply(rxring, &spa,
						  limit, &received);
				limit -= m;
				if (limit == 0)
					break;
			}
			ioctl(fds[0].fd, NIOCSYNCRX, NULL);
		}
		
		if (fds[0].revents & POLLOUT) {
			limit = MIN(burst, n - sent);
			for (int i = 0; i < nifp->ni_num_queues; i++) {
				txring = NETMAP_TX_RING(nifp, i);
				if (txring->nr_avail == 0)
					continue;

				m = send_request(txring, shost, dhost,
						 &spa, &tpa, limit);
				sent += m;
				limit -= m;
				if (limit == 0)
					break;
			}
			ioctl(fds[0].fd, NIOCSYNCTX, NULL);

			/* disable WR polling when done. */
			if (sent == n)
				fds[0].events &= ~POLLOUT;
		}

		/* All the responses have been received correctly. */
		if (received == n) {
			gettimeofday(&toc, NULL);
			delta = toc.tv_sec - tic.tv_sec +
				(toc.tv_usec - tic.tv_usec) / 1000000.0;
			print_output(received, sent, delta);
			break;
		}

	}

	ioctl(fd, NIOCUNREGIF, &ifreq);

unmap:
	munmap(tmp_addr, NETMAP_MEMORY_SIZE);
close:
	close(fd);

	return (err);
}
