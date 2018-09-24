#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <net/if.h>
#define NETMAP_WITH_LIBS
#include <net/netmap.h>
#include <net/netmap_user.h>
#include <pthread.h>
#include <string.h>
#include <assert.h>

static void *
kloop_worker(void *opaque)
{
	struct nm_desc *nmd = opaque;
	struct nmreq_sync_kloop_start req;
	struct nmreq_header hdr;
	size_t num_entries;
	size_t csb_size;
	void *csb;
	int ret;

	num_entries = nmd->last_tx_ring - nmd->first_tx_ring + 1 +
	              nmd->last_rx_ring - nmd->first_rx_ring + 1;
	printf("Number of CSB entries = %d\n", (int)num_entries);
	csb_size = (sizeof(struct nm_csb_atok) + sizeof(struct nm_csb_ktoa)) *
	           num_entries;
	assert(csb_size > 0);
	ret = posix_memalign(&csb, sizeof(struct nm_csb_atok), csb_size);
	if (ret) {
		printf("Failed to allocate CSB memory\n");
		return NULL;
	}

	memset(&hdr, 0, sizeof(hdr));
	hdr.nr_version = NETMAP_API;
	hdr.nr_reqtype = NETMAP_REQ_SYNC_KLOOP_START;
	hdr.nr_body    = (uintptr_t)&req;
	hdr.nr_options = (uintptr_t)NULL;
	memset(&req, 0, sizeof(req));
	req.csb_atok = (uintptr_t)csb;
	req.csb_ktoa =
	        (uintptr_t)(csb + sizeof(struct nm_csb_atok) * num_entries);
	ret = ioctl(nmd->fd, NIOCCTRL, &hdr);
	if (ret) {
		perror("ioctl(/dev/netmap, NIOCCTRL, SYNC_KLOOP_START)");
	}
	free(csb);

	return NULL;
}

static void
usage(const char *progname)
{
	printf("%s\n"
	       "[-h (show this help and exit)]\n"
	       "-i NETMAP_PORT\n",
	       progname);
}

int
main(int argc, char **argv)
{
	const char *ifname = NULL;
	struct nm_desc *nmd;
	pthread_t th;
	int opt;
	int ret;

	while ((opt = getopt(argc, argv, "hi:")) != -1) {
		switch (opt) {
		case 'h':
			usage(argv[0]);
			return 0;

		case 'i':
			ifname = optarg;
			break;

		default:
			printf("    Unrecognized option %c\n", opt);
			usage(argv[0]);
			return -1;
		}
	}

	if (ifname == NULL) {
		printf("No netmap port specified\n");
		usage(argv[0]);
		return -1;
	}

	printf("ifname %s\n", ifname);
	nmd = nm_open(ifname, NULL, 0, NULL);
	if (!nmd) {
		printf("nm_open(%s) failed\n", ifname);
		return -1;
	}

	ret = pthread_create(&th, NULL, kloop_worker, nmd);
	if (ret) {
		printf("pthread_create() failed: %s\n", strerror(ret));
		nm_close(nmd);
		return -1;
	}

	{
		struct nmreq_header hdr;
		int ret;

		memset(&hdr, 0, sizeof(hdr));
		hdr.nr_version = NETMAP_API;
		hdr.nr_reqtype = NETMAP_REQ_SYNC_KLOOP_STOP;
		ret            = ioctl(nmd->fd, NIOCCTRL, &hdr);
		if (ret) {
			perror("ioctl(/dev/netmap, NIOCCTRL, SYNC_KLOOP_STOP)");
		}
	}

	ret = pthread_join(th, NULL);
	if (ret) {
		printf("pthread_join() failed: %s\n", strerror(ret));
	}

	nm_close(nmd);

	return 0;
}
