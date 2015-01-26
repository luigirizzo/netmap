#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h> /* strcmp */
#include <fcntl.h> /* open */
#include <unistd.h> /* close */

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
process_rings(struct netmap_ring *rxring, struct netmap_ring *txring,
	      struct in_addr *spa, u_char *shost, int limit)
{
	struct ether_header *eh;
	struct arp *arp;
	void *rxpkt, *txpkt;
	int j, k, m = 0;

	j = rxring->nr_cur; /* RX */
	k = txring->nr_cur; /* TX */
	// XXX not sure the condition is correct
	while (rxring->nr_avail > 0 &&
	       txring->nr_avail > 0 &&
	       (m != limit)) {
		rxpkt = NETMAP_RING_PACKET(rxring, j);
		eh = (struct ether_header *) rxpkt;
		if (ntohs(eh->ether_type) != ETHERTYPE_ARP)
			goto next;

		arp = (struct arp *) &eh[1];
		if (ntohs(arp->htype) != 1 ||
		    ntohs(arp->ptype) != ETHERTYPE_IP ||
		    arp->hlen != 6 || arp->plen != 4 ||
		    ntohs(arp->oper) != 1 /* request */ ||
		    memcmp(arp->tpa, spa, arp->plen) != 0)
			goto next;

		txpkt = NETMAP_RING_PACKET(txring, k);
		create_ether(txpkt, shost, arp->sha);
		create_arp(txpkt + sizeof(struct ether_header),
			   shost, (struct in_addr *) arp->tpa,
			   arp->sha, (struct in_addr *) arp->spa,
			   2);
		NETMAP_RING_SLOTS(txring)[j].plen = 42;

		txring->nr_avail--;

		m++;

next:
		j = nm_ring_next(rxring, j);
		rxring->nr_cur = j;

		k = nm_ring_next(txring, k);
		txring->nr_cur = k;
	}

	return (m);
}


static int
process_interface(struct netmap_if *nifp, struct in_addr *spa, u_char *shost,
		  int limit)
{
	struct netmap_ring *rxring, *txring;
	int j, k, m = 0;

	for (int i = 0; i < nifp->ni_num_queues; i++) {
		txring = NETMAP_TX_RING(nifp, i);
		if (txring->nr_avail == 0)
			continue;

		j = k = 0;
		while (j < nifp->ni_num_queues &&
		       k < nifp->ni_num_queues &&
		       (m != limit)) {
			rxring = NETMAP_RX_RING(nifp, j);
			txring = NETMAP_TX_RING(nifp, k);

			if (rxring->nr_avail == 0) {
				j++;
				continue;
			}

			if (txring->nr_avail == 0) {
				k++;
				continue;
			}

			m += process_rings(rxring, txring, spa, shost,
					   limit - m);
		}
	}
	return (m);
}


static void
print_output(int processed, int total, double delta)
{

	double pps = processed / delta;
	char units[4] = { '\0', 'K', 'M', 'G' };
	int punit = 0;

	while (pps >= 1000) {
		pps /= 1000;
		punit += 1;
	}

	printf("Processed %d of %d requests in %.2f seconds.\n",
	       processed, total, delta);
	printf("Speed: %.2f%cpps. Packet loss: %.2f%%.\n",
	       pps, units[punit], (total - processed) * 100.0 / total);
}


int
main(int arc, char **argv)
{
	int fd, err;
	struct nmreq ifreq;
	struct netmap_if *nifp;
	struct in_addr spa;
	void *tmp_addr;
	struct pollfd fds[1];
	u_char shost[6];
	int sent = 0, n, burst;
	struct timeval tic, toc;
	double delta;

	if (arc != 4) {
		printf("Usage: %s <ifname> <n> <burst>\n", argv[0]);
		return (1);
	}


	/* retrieve ip address. */
	if (get_ip(argv[1], &spa)) {
		printf("Unable to retrieve IP address.\n");
		return(1);
	}

	/* setup netmap interface. */
	if ((fd = open("/dev/netmap", O_RDWR)) == -1) {
		printf("Unable to open \"/dev/netmap\".\n");
		return (1);
	}

	strcpy(ifreq.nr_name, argv[1]);
	if ((ioctl(fd, NIOCREGIF, &ifreq)) == -1) {
		printf("Unable to register \"%s\" interface.\n", argv[1]);
		err = 1;
		goto close;
	}

	tmp_addr = (struct netmap_d *) mmap(0, ifreq.nr_memsize,
					    PROT_WRITE | PROT_READ,
					    MAP_SHARED, fd, 0);
	if (tmp_addr == MAP_FAILED) {
		printf("Unable to mmap.\n");
		err = 1;
		goto close;
	}
	nifp = NETMAP_IF(tmp_addr, ifreq.nr_offset);

	/* retrieve mac address. */
   {
	struct ifreq x;
	bzero(&x, sizeof(x));
	strncpy(x.ifr_name, argv[1], sizeof(x.ifr_name));
	if ((ioctl(fd, SIOCGIFADDR, &x)) == -1) {
		printf("Unable to retrieve MAC address.\n");
		err = 1;
		goto unmap;
	}
	bcopy(&x.ifr_addr.sa_data, shost, 6);
   }

	/* how many packets to wait for. */
	n = atoi(argv[2]);

	/* packets burst size. */
	burst = atoi(argv[3]);

	/* setup poll(2) machanism. */
	memset(fds, 0, sizeof(fds));
	fds[0].fd = fd;
	fds[0].events = (POLLIN);

	/* Sleep to give the registered interface some to time to
	   bootstrap. */
	printf("Sleeping 5 secs..\n");
	sleep(5);

	/* wait for the first packet. */
	if (poll(fds, 1, INFTIM) <= 0) {
		printf("poll <= 0\n");
		goto unmap;
	}

	/* main loop */
	gettimeofday(&tic, NULL);
	while (1) {
		struct netmap_ring *txring;
		int limit, m, done;

		/* Invoke the poll(2) mechanism.
		   Wait at most 1 second before quitting. */
		if (poll(fds, 1, 1 * 1000) <= 0) {
			gettimeofday(&toc, NULL);
			toc.tv_sec -= 1;
			delta = toc.tv_sec - tic.tv_sec +
				(toc.tv_usec - tic.tv_usec) / 1000000.0;
			print_output(sent, n, delta);
			break;
		}

		if (fds[0].revents & POLLIN) {
			fds[0].events &= ~POLLIN;
			fds[0].events |= POLLOUT;
		}

		if (fds[0].revents & POLLOUT) {
			limit = MIN(burst, n - sent);

			m = process_interface(nifp, &spa, shost, limit);
			sent += m;

			/* re-enable POLLIN on input. */
			fds[0].events |= POLLIN;
			ioctl(fd, NIOCSYNCRX, NULL);

			/* disable POLLOUT on output. */
			fds[0].events &= ~POLLOUT;
			ioctl(fd, NIOCSYNCTX, NULL);
		}

		/* All the responses have benn sent.
		   Wait all the TX queues to be emtpy. */
		if (sent == n) {
			/* wait all the TX queues to be empty. */
			done = 0;
			while (!done) {
				done = 1;
				for (int i = 0; i < nifp->ni_num_queues; i++) {
					txring = NETMAP_TX_RING(nifp, i);
					if (NETMAP_TX_RING_EMPTY(txring))
						continue;

					done = 0;
					ioctl(fds[0].fd, NIOCSYNCTX, NULL);
					break;
				}
			}
			gettimeofday(&toc, NULL);
			delta = toc.tv_sec - tic.tv_sec +
				(toc.tv_usec - tic.tv_usec) / 1000000.0;
			print_output(sent, n, delta);
			break;
		}
	}

	ioctl(fd, NIOCUNREGIF, &ifreq);

unmap:
	munmap(tmp_addr, ifreq.nr_memsize);
close:
	close(fd);

	return (err);
}
