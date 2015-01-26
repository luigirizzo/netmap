/* simple test program for netmap library */
#include <stdio.h>
#include <stdlib.h>
#define NETMAP_WITH_LIBS
#include <net/netmap_user.h>
#include <poll.h>

void my_cb(u_char *arg, const struct nm_pkthdr *h, const u_char *buf)
{
	fprintf(stderr, "received %d bytes at %p arg %p\n",
		h->len, buf, arg);
}

int main(int argc, char *argv[])
{
	struct nm_desc *d;
	struct pollfd pfd;
	char buf[2048];
	int sent = 0;
	
	(void)argc;

	bzero(&pfd, sizeof(pfd));

	d = nm_open(argv[1], NULL, 0, 0);
	if (d == NULL) {
		fprintf(stderr, "no netmap\n");
		exit(0);
	}
	pfd.fd = d->fd;
	pfd.events = POLLOUT;

	for (;;) {
		if (nm_inject(d, buf, 60) <= 0) {
			fprintf(stderr, "polling after %d\n", sent);
			sent = 0;
			poll(&pfd, 1, 1000);
			continue;
		}
		sent++;
	}
	nm_close(d);
	return 0;
}
