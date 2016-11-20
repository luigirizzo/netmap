/* simple test program for netmap library */
#include <stdio.h>
#include <stdlib.h>
#define NETMAP_WITH_LIBS
#include <net/netmap_user.h>
#include <poll.h>

static void
usage(const char *progname)
{
	fprintf(stderr, "usage: %s IFNAME [w|r]\n", progname);
	exit(EXIT_FAILURE);
}

static void
my_cb(u_char *arg, const struct nm_pkthdr *h, const u_char *buf)
{
	int *count = (int *)arg;
	(*count)++;
	if (h->flags == 0)
	fprintf(stderr, "received %d bytes at %p count %d slot %p buf_index %d\n",
		h->len, buf, *count, h->slot, h->slot->buf_idx);
}

int
main(int argc, char *argv[])
{
	struct nm_desc *d;
	struct pollfd pfd;
	char buf[2048];
	int count = 0;

	if (argc < 2) {
		usage(argv[0]);
	}

	bzero(&pfd, sizeof(pfd));

	d = nm_open(argv[1], NULL, 0, 0);
	if (d == NULL) {
		fprintf(stderr, "no netmap\n");
		exit(0);
	}
	pfd.fd = d->fd;
	pfd.events = argv[2] && argv[2][0] == 'w' ? POLLOUT : POLLIN;
	fprintf(stderr, "working on %s in %s mode\n", argv[1], pfd.events == POLLIN ? "read" : "write");

	for (;;) {
		if (pfd.events == POLLIN) {
			nm_dispatch(d, -1, my_cb, (void *)&count);
		} else {
			if (nm_inject(d, buf, 60) > 0) {
				count++;
				continue;
			}
			fprintf(stderr, "polling after sending %d\n", count);
			count = 0;
		}
		poll(&pfd, 1, 1000);
	}
	nm_close(d);
	return 0;
}
