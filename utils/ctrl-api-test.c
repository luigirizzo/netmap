#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <net/if.h>
#include <net/netmap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

struct TestContext {
	const char	*ifname;
	const char	*bdgname;
	uint32_t	nr_tx_slots;	/* slots in tx rings */
	uint32_t	nr_rx_slots;	/* slots in rx rings */
	uint16_t	nr_tx_rings;	/* number of tx rings */
	uint16_t	nr_rx_rings;	/* number of rx rings */
	uint16_t	nr_mem_id;	/* id of the memory allocator */
	uint16_t	nr_ringid;	/* ring(s) we care about */
	uint32_t	nr_mode;	/* specify NR_REG_* modes */
	uint64_t	nr_flags;	/* additional flags (see below) */
	uint32_t	nr_pipes;	/* number of pipes to create */
	uint32_t	nr_extra_bufs;	/* number of requested extra buffers */
};

static void
ctx_reset(struct TestContext *ctx)
{
	const char *tmp1 = ctx->ifname;
	const char *tmp2 = ctx->bdgname;
	memset(ctx, 0, sizeof(*ctx));
	ctx->ifname = tmp1;
	ctx->bdgname = tmp2;
}

typedef int (*testfunc_t)(int fd, struct TestContext *ctx);

/* Single NETMAP_REQ_PORT_INFO_GET. */
static int
port_info_get(int fd, struct TestContext *ctx)
{
	struct nmreq_port_info_get req;
	int ret;

	printf("Testing NETMAP_REQ_PORT_INFO_GET on '%s'\n", ctx->ifname);

	memset(&req, 0, sizeof(req));
	req.nr_hdr.nr_version = NETMAP_API;
	req.nr_hdr.nr_reqtype = NETMAP_REQ_PORT_INFO_GET;
	strncpy(req.nr_hdr.nr_name, ctx->ifname, sizeof(req.nr_hdr.nr_name));
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
		req.nr_tx_rings && req.nr_rx_rings && req.nr_tx_rings
		       ? 0 : -1;
}

/* Single NETMAP_REQ_REGISTER, no use. */
static int
port_register(int fd, struct TestContext *ctx)
{
	struct nmreq_register req;
	int ret;

	printf("Testing NETMAP_REQ_REGISTER(mode=%d,ringid=%d,"
		"flags=%lx) on '%s'\n", ctx->nr_mode, ctx->nr_ringid,
		ctx->nr_flags, ctx->ifname);

	memset(&req, 0, sizeof(req));
	req.nr_hdr.nr_version = NETMAP_API;
	req.nr_hdr.nr_reqtype = NETMAP_REQ_REGISTER;
	req.nr_mem_id	   = ctx->nr_mem_id;
	req.nr_mode	   = ctx->nr_mode;
	req.nr_ringid	   = ctx->nr_ringid;
	req.nr_flags	   = ctx->nr_flags;
	req.nr_tx_slots	   = ctx->nr_tx_slots;
	req.nr_rx_slots	   = ctx->nr_rx_slots;
	req.nr_tx_rings	   = ctx->nr_tx_rings;
	req.nr_rx_rings	   = ctx->nr_rx_rings;
	req.nr_pipes	   = ctx->nr_pipes;
	req.nr_extra_bufs  = ctx->nr_extra_bufs;
	strncpy(req.nr_hdr.nr_name, ctx->ifname, sizeof(req.nr_hdr.nr_name));
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

	return req.nr_memsize &&
		(ctx->nr_mode == req.nr_mode) &&
		(ctx->nr_ringid == req.nr_ringid) &&
		(ctx->nr_flags == req.nr_flags) &&
		((!ctx->nr_tx_slots && req.nr_tx_slots) ||
			(ctx->nr_tx_slots == req.nr_tx_slots)) &&
		((!ctx->nr_rx_slots && req.nr_rx_slots) ||
			(ctx->nr_rx_slots == req.nr_rx_slots)) &&
		((!ctx->nr_tx_rings && req.nr_tx_rings) ||
			(ctx->nr_tx_rings == req.nr_tx_rings)) &&
		((!ctx->nr_rx_rings && req.nr_rx_rings) ||
			(ctx->nr_rx_rings == req.nr_rx_rings)) &&
		((!ctx->nr_mem_id && req.nr_mem_id) ||
			(ctx->nr_mem_id == req.nr_mem_id)) &&
		(ctx->nr_pipes == req.nr_pipes) &&
		(ctx->nr_extra_bufs == req.nr_extra_bufs)
		       ? 0 : -1;
}

static int
port_register_hwall_host(int fd, struct TestContext *ctx)
{
	ctx->nr_mode = NR_REG_NIC_SW;
	return port_register(fd, ctx);
}

static int
port_register_host(int fd, struct TestContext *ctx)
{
	ctx->nr_mode = NR_REG_SW;
	return port_register(fd, ctx);
}

static int
port_register_hwall(int fd, struct TestContext *ctx)
{
	ctx->nr_mode = NR_REG_ALL_NIC;
	return port_register(fd, ctx);
}

static int
port_register_single_ring_couple(int fd, struct TestContext *ctx)
{
	ctx->nr_mode = NR_REG_ONE_NIC;
	ctx->nr_ringid = 0;
	return port_register(fd, ctx);
}

/* First NETMAP_REQ_VALE_ATTACH, then NETMAP_REQ_VALE_DETACH. */
static int
vale_attach_detach(int fd, struct TestContext *ctx)
{
	struct nmreq_vale_attach req;
	struct nmreq_vale_detach dreq;
	char vpname[256];
	int result = 0;
	int ret;

	snprintf(vpname, sizeof(vpname), "%s:%s", ctx->bdgname, ctx->ifname);
	printf("Testing NETMAP_REQ_VALE_ATTACH on '%s'\n", vpname);

	memset(&req, 0, sizeof(req));
	req.nr_hdr.nr_version = NETMAP_API;
	req.nr_hdr.nr_reqtype = NETMAP_REQ_VALE_ATTACH;
	strncpy(req.nr_hdr.nr_name, vpname, sizeof(req.nr_hdr.nr_name));
	req.nr_mem_id = ctx->nr_mem_id;
	req.nr_flags = ctx->nr_flags;
	ret = ioctl(fd, NIOCCTRL, &req);
	if (ret) {
		perror("ioctl(/dev/netmap, NIOCCTRL, VALE_ATTACH)");
		return ret;
	}
	printf("nr_mem_id %u\n", req.nr_mem_id);

	result = ((!ctx->nr_mem_id && req.nr_mem_id > 1) ||
			(ctx->nr_mem_id == req.nr_mem_id)) &&
		(ctx->nr_flags == req.nr_flags)
		       ? 0 : -1;

	memset(&dreq, 0, sizeof(dreq));
	memcpy(&dreq, &req, sizeof(dreq.nr_hdr));
	dreq.nr_hdr.nr_reqtype = NETMAP_REQ_VALE_DETACH;
	ret = ioctl(fd, NIOCCTRL, &dreq);
	if (ret) {
		perror("ioctl(/dev/netmap, NIOCCTRL, VALE_DETACH)");
		if (result == 0) {
			result = ret;
		}
	}

	return result;
}

static int
vale_attach_detach_host_rings(int fd, struct TestContext *ctx)
{
	ctx->nr_flags = NETMAP_BDG_HOST;
	return vale_attach_detach(fd, ctx);
}

static void
usage(const char *prog)
{
	printf("%s -i IFNAME\n", prog);
}

static testfunc_t tests[] = {
		port_info_get,
		port_register_hwall_host,
		port_register_hwall,
		port_register_host,
		port_register_single_ring_couple,
		vale_attach_detach,
		vale_attach_detach_host_rings};

int
main(int argc, char **argv)
{
	struct TestContext ctx;
	unsigned int i;
	int opt;

	memset(&ctx, 0, sizeof(ctx));
	ctx.ifname = "ens4";
	ctx.bdgname = "vale1x2";

	while ((opt = getopt(argc, argv, "hi:")) != -1) {
		switch (opt) {
		case 'h':
			usage(argv[0]);
			return 0;

		case 'i':
			ctx.ifname = optarg;
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
		ctx_reset(&ctx);
		ret = tests[i](fd, &ctx);
		if (ret) {
			printf("Test #%d failed\n", i + 1);
			return ret;
		}
		printf("Test #%d successful\n", i + 1);
		close(fd);
	}

	return 0;
}
