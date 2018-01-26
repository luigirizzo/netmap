#include <errno.h>
#include <fcntl.h>
#include <net/if.h>
#include <net/netmap.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

typedef int (*testfunc_t)(int fd, const char *ifname);

/* Single NETMAP_REQ_PORT_INFO_GET. */
static int
port_info_get(int fd, const char *ifname)
{
	struct nmreq_port_info_get req;
	int ret;

	printf("Testing NETMAP_REQ_PORT_INFO_GET on '%s'\n", ifname);

	memset(&req, 0, sizeof(req));
	req.nr_hdr.nr_version = NETMAP_API;
	req.nr_hdr.nr_reqtype = NETMAP_REQ_PORT_INFO_GET;
	strncpy(req.nr_hdr.nr_name, ifname, sizeof(req.nr_hdr.nr_name));
	ret = ioctl(fd, NIOCCTRL, &req);
	if (ret) {
		perror("ioctl(/dev/netmap, NIOCCTRL)");
		return ret;
	}
	printf("nr_offset %lu\n", req.nr_offset);
	printf("nr_memsize %lu\n", req.nr_memsize);
	printf("nr_tx_slots %u\n", req.nr_tx_slots);
	printf("nr_rx_slots %u\n", req.nr_rx_slots);
	printf("nr_tx_rings %u\n", req.nr_tx_rings);
	printf("nr_rx_rings %u\n", req.nr_rx_rings);
	printf("nr_mem_id %u\n", req.nr_mem_id);

	return req.nr_memsize && req.nr_tx_slots && req.nr_rx_slots &&
			       req.nr_tx_rings && req.nr_rx_rings &&
			       req.nr_tx_rings
		       ? 0
		       : -1;
}

/* Single NETMAP_REQ_REGISTER, no use. */
static int
port_register(int fd, const char *ifname)
{
	struct nmreq_register req;
	int ret;

	printf("Testing NETMAP_REQ_REGISTER on '%s'\n", ifname);

	memset(&req, 0, sizeof(req));
	req.nr_hdr.nr_version = NETMAP_API;
	req.nr_hdr.nr_reqtype = NETMAP_REQ_REGISTER;
	req.nr_mode	   = NR_REG_NIC_SW;
	strncpy(req.nr_hdr.nr_name, ifname, sizeof(req.nr_hdr.nr_name));
	ret = ioctl(fd, NIOCCTRL, &req);
	if (ret) {
		perror("ioctl(/dev/netmap, NIOCCTRL)");
		return ret;
	}
	printf("nr_offset %lu\n", req.nr_offset);
	printf("nr_memsize %lu\n", req.nr_memsize);
	printf("nr_tx_slots %u\n", req.nr_tx_slots);
	printf("nr_rx_slots %u\n", req.nr_rx_slots);
	printf("nr_tx_rings %u\n", req.nr_tx_rings);
	printf("nr_rx_rings %u\n", req.nr_rx_rings);
	printf("nr_mem_id %u\n", req.nr_mem_id);

	return req.nr_memsize && req.nr_tx_slots && req.nr_rx_slots &&
			       req.nr_tx_rings && req.nr_rx_rings &&
			       req.nr_tx_rings && req.nr_pipes == 0 &&
			       req.nr_extra_bufs == 0
		       ? 0
		       : -1;
}

static void
usage(const char *prog)
{
	printf("%s -i IFNAME\n", prog);
}

static testfunc_t tests[] = {port_info_get, port_register};

int
main(int argc, char **argv)
{
	const char *ifname = "ens4";
	unsigned int i;
	int opt;

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

	for (i = 0; i < sizeof(tests) / sizeof(tests[0]); i++) {
		int fd;
		int ret;
		fd = open("/dev/netmap", O_RDWR);
		if (fd < 0) {
			perror("open(/dev/netmap)");
			return fd;
		}
		ret = tests[i](fd, ifname);
		if (ret) {
			printf("Test #%d failed\n", i + 1);
		}
		printf("Test #%d successful\n", i + 1);
	}

	return 0;
}
