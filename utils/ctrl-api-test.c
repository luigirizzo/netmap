#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <net/if.h>
#include <net/netmap.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <unistd.h>
#include <pthread.h>
#include <assert.h>

#ifdef __linux__
#include <sys/eventfd.h>
#else
static int
eventfd(int x, int y)
{
	(void)x;
	(void)y;
	return 19;
}
#endif /* __linux__ */

#define THRET_SUCCESS	((void *)128)
#define THRET_FAILURE	((void *)0)

struct TestContext {
	int fd; /* netmap file descriptor */
	char *ifname;
	const char *bdgname;
	uint32_t nr_tx_slots;   /* slots in tx rings */
	uint32_t nr_rx_slots;   /* slots in rx rings */
	uint16_t nr_tx_rings;   /* number of tx rings */
	uint16_t nr_rx_rings;   /* number of rx rings */
	uint16_t nr_mem_id;     /* id of the memory allocator */
	uint16_t nr_ringid;     /* ring(s) we care about */
	uint32_t nr_mode;       /* specify NR_REG_* modes */
	uint64_t nr_flags;      /* additional flags (see below) */
	uint32_t nr_extra_bufs; /* number of requested extra buffers */

	uint32_t nr_hdr_len; /* for PORT_HDR_SET and PORT_HDR_GET */

	uint32_t nr_first_cpu_id;     /* vale polling */
	uint32_t nr_num_polling_cpus; /* vale polling */
	void *csb;                    /* CSB entries (atok and ktoa) */
	struct nmreq_option *nr_opt;  /* list of options */

	struct nmport_d *nmport;      /* nmport descriptor from libnetmap */
};

#if 0
static void
ctx_reset(struct TestContext *ctx)
{
	const char *tmp1 = ctx->ifname;
	const char *tmp2 = ctx->bdgname;
	memset(ctx, 0, sizeof(*ctx));
	ctx->ifname = tmp1;
	ctx->bdgname = tmp2;
}
#endif

typedef int (*testfunc_t)(struct TestContext *ctx);

static void
nmreq_hdr_init(struct nmreq_header *hdr, const char *ifname)
{
	memset(hdr, 0, sizeof(*hdr));
	hdr->nr_version = NETMAP_API;
	strncpy(hdr->nr_name, ifname, sizeof(hdr->nr_name) - 1);
}

/* Single NETMAP_REQ_PORT_INFO_GET. */
static int
port_info_get(struct TestContext *ctx)
{
	struct nmreq_port_info_get req;
	struct nmreq_header hdr;
	int success;
	int ret;

	printf("Testing NETMAP_REQ_PORT_INFO_GET on '%s'\n", ctx->ifname);

	nmreq_hdr_init(&hdr, ctx->ifname);
	hdr.nr_reqtype = NETMAP_REQ_PORT_INFO_GET;
	hdr.nr_body    = (uintptr_t)&req;
	memset(&req, 0, sizeof(req));
	req.nr_mem_id = ctx->nr_mem_id;
	ret           = ioctl(ctx->fd, NIOCCTRL, &hdr);
	if (ret) {
		perror("ioctl(/dev/netmap, NIOCCTRL, PORT_INFO_GET)");
		return ret;
	}
	printf("nr_memsize %lu\n", req.nr_memsize);
	printf("nr_tx_slots %u\n", req.nr_tx_slots);
	printf("nr_rx_slots %u\n", req.nr_rx_slots);
	printf("nr_tx_rings %u\n", req.nr_tx_rings);
	printf("nr_rx_rings %u\n", req.nr_rx_rings);
	printf("nr_mem_id %u\n", req.nr_mem_id);

	success = req.nr_memsize && req.nr_tx_slots && req.nr_rx_slots &&
	          req.nr_tx_rings && req.nr_rx_rings && req.nr_tx_rings;
	if (!success) {
		return -1;
	}

	/* Write back results to the context structure.*/
	ctx->nr_tx_slots = req.nr_tx_slots;
	ctx->nr_rx_slots = req.nr_rx_slots;
	ctx->nr_tx_rings = req.nr_tx_rings;
	ctx->nr_rx_rings = req.nr_rx_rings;
	ctx->nr_mem_id   = req.nr_mem_id;

	return 0;
}

/* Single NETMAP_REQ_REGISTER, no use. */
static int
port_register(struct TestContext *ctx)
{
	struct nmreq_register req;
	struct nmreq_header hdr;
	int success;
	int ret;

	printf("Testing NETMAP_REQ_REGISTER(mode=%d,ringid=%d,"
	       "flags=0x%lx) on '%s'\n",
	       ctx->nr_mode, ctx->nr_ringid, ctx->nr_flags, ctx->ifname);

	nmreq_hdr_init(&hdr, ctx->ifname);
	hdr.nr_reqtype = NETMAP_REQ_REGISTER;
	hdr.nr_body    = (uintptr_t)&req;
	hdr.nr_options = (uintptr_t)ctx->nr_opt;
	memset(&req, 0, sizeof(req));
	req.nr_mem_id     = ctx->nr_mem_id;
	req.nr_mode       = ctx->nr_mode;
	req.nr_ringid     = ctx->nr_ringid;
	req.nr_flags      = ctx->nr_flags;
	req.nr_tx_slots   = ctx->nr_tx_slots;
	req.nr_rx_slots   = ctx->nr_rx_slots;
	req.nr_tx_rings   = ctx->nr_tx_rings;
	req.nr_rx_rings   = ctx->nr_rx_rings;
	req.nr_extra_bufs = ctx->nr_extra_bufs;
	ret               = ioctl(ctx->fd, NIOCCTRL, &hdr);
	if (ret) {
		perror("ioctl(/dev/netmap, NIOCCTRL, REGISTER)");
		return ret;
	}
	printf("nr_offset 0x%lx\n", req.nr_offset);
	printf("nr_memsize %lu\n", req.nr_memsize);
	printf("nr_tx_slots %u\n", req.nr_tx_slots);
	printf("nr_rx_slots %u\n", req.nr_rx_slots);
	printf("nr_tx_rings %u\n", req.nr_tx_rings);
	printf("nr_rx_rings %u\n", req.nr_rx_rings);
	printf("nr_mem_id %u\n", req.nr_mem_id);
	printf("nr_extra_bufs %u\n", req.nr_extra_bufs);

	success = req.nr_memsize && (ctx->nr_mode == req.nr_mode) &&
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
	                       (ctx->nr_extra_bufs == req.nr_extra_bufs);
	if (!success) {
		return -1;
	}

	/* Write back results to the context structure.*/
	ctx->nr_tx_slots   = req.nr_tx_slots;
	ctx->nr_rx_slots   = req.nr_rx_slots;
	ctx->nr_tx_rings   = req.nr_tx_rings;
	ctx->nr_rx_rings   = req.nr_rx_rings;
	ctx->nr_mem_id     = req.nr_mem_id;
	ctx->nr_extra_bufs = req.nr_extra_bufs;

	return -0;
}

static int
niocregif(struct TestContext *ctx, int netmap_api)
{
	struct nmreq req;
	int success;
	int ret;

	printf("Testing legacy NIOCREGIF on '%s'\n", ctx->ifname);

	memset(&req, 0, sizeof(req));
	strncpy(req.nr_name, ctx->ifname, sizeof(req.nr_name)-1);
	req.nr_version = netmap_api;
	req.nr_ringid     = ctx->nr_ringid;
	req.nr_flags      = ctx->nr_mode | ctx->nr_flags;
	req.nr_tx_slots   = ctx->nr_tx_slots;
	req.nr_rx_slots   = ctx->nr_rx_slots;
	req.nr_tx_rings   = ctx->nr_tx_rings;
	req.nr_rx_rings   = ctx->nr_rx_rings;
	req.nr_arg2     = ctx->nr_mem_id;
	req.nr_arg3 = ctx->nr_extra_bufs;

	ret = ioctl(ctx->fd, NIOCREGIF, &req);
	if (ret) {
		perror("ioctl(/dev/netmap, NIOCREGIF)");
		return ret;
	}

	printf("nr_offset 0x%x\n", req.nr_offset);
	printf("nr_memsize  %u\n", req.nr_memsize);
	printf("nr_tx_slots %u\n", req.nr_tx_slots);
	printf("nr_rx_slots %u\n", req.nr_rx_slots);
	printf("nr_tx_rings %u\n", req.nr_tx_rings);
	printf("nr_rx_rings %u\n", req.nr_rx_rings);
	printf("nr_version  %d\n", req.nr_version);
	printf("nr_ringid   %x\n", req.nr_ringid);
	printf("nr_flags    %x\n", req.nr_flags);
	printf("nr_arg2     %u\n", req.nr_arg2);
	printf("nr_arg3     %u\n", req.nr_arg3);

	success = req.nr_memsize &&
	       (ctx->nr_ringid == req.nr_ringid) &&
	       ((ctx->nr_mode | ctx->nr_flags) == req.nr_flags) &&
	       ((!ctx->nr_tx_slots && req.nr_tx_slots) ||
		(ctx->nr_tx_slots == req.nr_tx_slots)) &&
	       ((!ctx->nr_rx_slots && req.nr_rx_slots) ||
		(ctx->nr_rx_slots == req.nr_rx_slots)) &&
	       ((!ctx->nr_tx_rings && req.nr_tx_rings) ||
		(ctx->nr_tx_rings == req.nr_tx_rings)) &&
	       ((!ctx->nr_rx_rings && req.nr_rx_rings) ||
		(ctx->nr_rx_rings == req.nr_rx_rings)) &&
	       ((!ctx->nr_mem_id && req.nr_arg2) ||
		(ctx->nr_mem_id == req.nr_arg2)) &&
	       (ctx->nr_extra_bufs == req.nr_arg3);
	if (!success) {
		return -1;
	}

	/* Write back results to the context structure.*/
	ctx->nr_tx_slots   = req.nr_tx_slots;
	ctx->nr_rx_slots   = req.nr_rx_slots;
	ctx->nr_tx_rings   = req.nr_tx_rings;
	ctx->nr_rx_rings   = req.nr_rx_rings;
	ctx->nr_mem_id     = req.nr_arg2;
	ctx->nr_extra_bufs = req.nr_arg3;

	return ret;
}

/* The 11 ABI is the one right before the introduction of the new NIOCCTRL
 * ABI. The 11 ABI is useful to perform tests with legacy applications
 * (which use the 11 ABI) and new kernel (which uses 12, or higher). */
#define NETMAP_API_NIOCREGIF	11

static int
legacy_regif_default(struct TestContext *ctx)
{
	return niocregif(ctx, NETMAP_API_NIOCREGIF);
}

static int
legacy_regif_all_nic(struct TestContext *ctx)
{
	ctx->nr_mode = NR_REG_ALL_NIC;
	return niocregif(ctx, NETMAP_API);
}

static int
legacy_regif_12(struct TestContext *ctx)
{
	ctx->nr_mode = NR_REG_ALL_NIC;
	return niocregif(ctx, NETMAP_API_NIOCREGIF+1);
}

static int
legacy_regif_sw(struct TestContext *ctx)
{
	ctx->nr_mode = NR_REG_SW;
	return niocregif(ctx,  NETMAP_API_NIOCREGIF);
}

static int
legacy_regif_future(struct TestContext *ctx)
{
	ctx->nr_mode = NR_REG_NIC_SW;
	/* Test forward compatibility for the legacy ABI. This means
	 * using an older kernel (with ABI 12 or higher) and a newer
	 * application (with ABI greater than NETMAP_API). */
	return niocregif(ctx, NETMAP_API+2);
}

static int
legacy_regif_extra_bufs(struct TestContext *ctx)
{
	ctx->nr_mode = NR_REG_ALL_NIC;
	ctx->nr_extra_bufs = 20;
	return niocregif(ctx, NETMAP_API_NIOCREGIF);
}

static int
legacy_regif_extra_bufs_pipe(struct TestContext *ctx)
{
	char pipe_name[128];

	snprintf(pipe_name, sizeof(pipe_name), "%s{%s", ctx->ifname, "pipeexbuf");
	ctx->ifname  = pipe_name;
	ctx->nr_mode = NR_REG_ALL_NIC;
	ctx->nr_extra_bufs = 20;

	return niocregif(ctx, NETMAP_API_NIOCREGIF);
}

static int
legacy_regif_extra_bufs_pipe_vale(struct TestContext *ctx)
{
	ctx->ifname = "valeX1:Y4";
	return legacy_regif_extra_bufs_pipe(ctx);
}

/* Only valid after a successful port_register(). */
static int
num_registered_rings(struct TestContext *ctx)
{
	assert(ctx->nr_tx_slots > 0 && ctx->nr_rx_slots > 0 &&
	       ctx->nr_tx_rings > 0 && ctx->nr_rx_rings > 0);
	if (ctx->nr_flags & NR_TX_RINGS_ONLY) {
		return ctx->nr_tx_rings;
	}
	if (ctx->nr_flags & NR_RX_RINGS_ONLY) {
		return ctx->nr_rx_rings;
	}

	return ctx->nr_tx_rings + ctx->nr_rx_rings;
}

static int
port_register_hwall_host(struct TestContext *ctx)
{
	ctx->nr_mode = NR_REG_NIC_SW;
	return port_register(ctx);
}

static int
port_register_host(struct TestContext *ctx)
{
	ctx->nr_mode = NR_REG_SW;
	return port_register(ctx);
}

static int
port_register_hwall(struct TestContext *ctx)
{
	ctx->nr_mode = NR_REG_ALL_NIC;
	return port_register(ctx);
}

static int
port_register_single_ring_couple(struct TestContext *ctx)
{
	ctx->nr_mode   = NR_REG_ONE_NIC;
	ctx->nr_ringid = 0;
	return port_register(ctx);
}

static int
port_register_hwall_tx(struct TestContext *ctx)
{
	ctx->nr_mode = NR_REG_ALL_NIC;
	ctx->nr_flags |= NR_TX_RINGS_ONLY;
	return port_register(ctx);
}

static int
port_register_hwall_rx(struct TestContext *ctx)
{
	ctx->nr_mode = NR_REG_ALL_NIC;
	ctx->nr_flags |= NR_RX_RINGS_ONLY;
	return port_register(ctx);
}

/* NETMAP_REQ_VALE_ATTACH */
static int
vale_attach(struct TestContext *ctx)
{
	struct nmreq_vale_attach req;
	struct nmreq_header hdr;
	char vpname[256];
	int ret;

	snprintf(vpname, sizeof(vpname), "%s:%s", ctx->bdgname, ctx->ifname);

	printf("Testing NETMAP_REQ_VALE_ATTACH on '%s'\n", vpname);
	nmreq_hdr_init(&hdr, vpname);
	hdr.nr_reqtype = NETMAP_REQ_VALE_ATTACH;
	hdr.nr_body    = (uintptr_t)&req;
	memset(&req, 0, sizeof(req));
	req.reg.nr_mem_id = ctx->nr_mem_id;
	if (ctx->nr_mode == 0) {
		ctx->nr_mode = NR_REG_ALL_NIC; /* default */
	}
	req.reg.nr_mode = ctx->nr_mode;
	ret             = ioctl(ctx->fd, NIOCCTRL, &hdr);
	if (ret) {
		perror("ioctl(/dev/netmap, NIOCCTRL, VALE_ATTACH)");
		return ret;
	}
	printf("nr_mem_id %u\n", req.reg.nr_mem_id);

	return ((!ctx->nr_mem_id && req.reg.nr_mem_id > 1) ||
	        (ctx->nr_mem_id == req.reg.nr_mem_id)) &&
	                       (ctx->nr_flags == req.reg.nr_flags)
	               ? 0
	               : -1;
}

/* NETMAP_REQ_VALE_DETACH */
static int
vale_detach(struct TestContext *ctx)
{
	struct nmreq_header hdr;
	struct nmreq_vale_detach req;
	char vpname[256];
	int ret;

	snprintf(vpname, sizeof(vpname), "%s:%s", ctx->bdgname, ctx->ifname);

	printf("Testing NETMAP_REQ_VALE_DETACH on '%s'\n", vpname);
	nmreq_hdr_init(&hdr, vpname);
	hdr.nr_reqtype = NETMAP_REQ_VALE_DETACH;
	hdr.nr_body    = (uintptr_t)&req;
	ret            = ioctl(ctx->fd, NIOCCTRL, &hdr);
	if (ret) {
		perror("ioctl(/dev/netmap, NIOCCTRL, VALE_DETACH)");
		return ret;
	}

	return 0;
}

/* First NETMAP_REQ_VALE_ATTACH, then NETMAP_REQ_VALE_DETACH. */
static int
vale_attach_detach(struct TestContext *ctx)
{
	int ret;

	if ((ret = vale_attach(ctx))) {
		return ret;
	}

	return vale_detach(ctx);
}

static int
vale_attach_detach_host_rings(struct TestContext *ctx)
{
	ctx->nr_mode = NR_REG_NIC_SW;
	return vale_attach_detach(ctx);
}

/* First NETMAP_REQ_PORT_HDR_SET and the NETMAP_REQ_PORT_HDR_GET
 * to check that we get the same value. */
static int
port_hdr_set_and_get(struct TestContext *ctx)
{
	struct nmreq_port_hdr req;
	struct nmreq_header hdr;
	int ret;

	printf("Testing NETMAP_REQ_PORT_HDR_SET on '%s'\n", ctx->ifname);

	nmreq_hdr_init(&hdr, ctx->ifname);
	hdr.nr_reqtype = NETMAP_REQ_PORT_HDR_SET;
	hdr.nr_body    = (uintptr_t)&req;
	memset(&req, 0, sizeof(req));
	req.nr_hdr_len = ctx->nr_hdr_len;
	ret            = ioctl(ctx->fd, NIOCCTRL, &hdr);
	if (ret) {
		perror("ioctl(/dev/netmap, NIOCCTRL, PORT_HDR_SET)");
		return ret;
	}

	if (req.nr_hdr_len != ctx->nr_hdr_len) {
		return -1;
	}

	printf("Testing NETMAP_REQ_PORT_HDR_GET on '%s'\n", ctx->ifname);
	hdr.nr_reqtype = NETMAP_REQ_PORT_HDR_GET;
	req.nr_hdr_len = 0;
	ret            = ioctl(ctx->fd, NIOCCTRL, &hdr);
	if (ret) {
		perror("ioctl(/dev/netmap, NIOCCTRL, PORT_HDR_SET)");
		return ret;
	}
	printf("nr_hdr_len %u\n", req.nr_hdr_len);

	return (req.nr_hdr_len == ctx->nr_hdr_len) ? 0 : -1;
}

static int
vale_ephemeral_port_hdr_manipulation(struct TestContext *ctx)
{
	int ret;

	ctx->ifname  = "vale:eph0";
	ctx->nr_mode = NR_REG_ALL_NIC;
	if ((ret = port_register(ctx))) {
		return ret;
	}
	/* Try to set and get all the acceptable values. */
	ctx->nr_hdr_len = 12;
	if ((ret = port_hdr_set_and_get(ctx))) {
		return ret;
	}
	ctx->nr_hdr_len = 0;
	if ((ret = port_hdr_set_and_get(ctx))) {
		return ret;
	}
	ctx->nr_hdr_len = 10;
	if ((ret = port_hdr_set_and_get(ctx))) {
		return ret;
	}
	return 0;
}

static int
vale_persistent_port(struct TestContext *ctx)
{
	struct nmreq_vale_newif req;
	struct nmreq_header hdr;
	int result;
	int ret;

	ctx->ifname = "per4";

	printf("Testing NETMAP_REQ_VALE_NEWIF on '%s'\n", ctx->ifname);

	nmreq_hdr_init(&hdr, ctx->ifname);
	hdr.nr_reqtype = NETMAP_REQ_VALE_NEWIF;
	hdr.nr_body    = (uintptr_t)&req;
	memset(&req, 0, sizeof(req));
	req.nr_mem_id   = ctx->nr_mem_id;
	req.nr_tx_slots = ctx->nr_tx_slots;
	req.nr_rx_slots = ctx->nr_rx_slots;
	req.nr_tx_rings = ctx->nr_tx_rings;
	req.nr_rx_rings = ctx->nr_rx_rings;
	ret             = ioctl(ctx->fd, NIOCCTRL, &hdr);
	if (ret) {
		perror("ioctl(/dev/netmap, NIOCCTRL, VALE_NEWIF)");
		return ret;
	}

	/* Attach the persistent VALE port to a switch and then detach. */
	result = vale_attach_detach(ctx);

	printf("Testing NETMAP_REQ_VALE_DELIF on '%s'\n", ctx->ifname);
	hdr.nr_reqtype = NETMAP_REQ_VALE_DELIF;
	hdr.nr_body    = (uintptr_t)NULL;
	ret            = ioctl(ctx->fd, NIOCCTRL, &hdr);
	if (ret) {
		perror("ioctl(/dev/netmap, NIOCCTRL, VALE_NEWIF)");
		if (result == 0) {
			result = ret;
		}
	}

	return result;
}

/* Single NETMAP_REQ_POOLS_INFO_GET. */
static int
pools_info_get(struct TestContext *ctx)
{
	struct nmreq_pools_info req;
	struct nmreq_header hdr;
	int ret;

	printf("Testing NETMAP_REQ_POOLS_INFO_GET on '%s'\n", ctx->ifname);

	nmreq_hdr_init(&hdr, ctx->ifname);
	hdr.nr_reqtype = NETMAP_REQ_POOLS_INFO_GET;
	hdr.nr_body    = (uintptr_t)&req;
	memset(&req, 0, sizeof(req));
	req.nr_mem_id = ctx->nr_mem_id;
	ret           = ioctl(ctx->fd, NIOCCTRL, &hdr);
	if (ret) {
		perror("ioctl(/dev/netmap, NIOCCTRL, POOLS_INFO_GET)");
		return ret;
	}
	printf("nr_memsize %lu\n", req.nr_memsize);
	printf("nr_mem_id %u\n", req.nr_mem_id);
	printf("nr_if_pool_offset 0x%lx\n", req.nr_if_pool_offset);
	printf("nr_if_pool_objtotal %u\n", req.nr_if_pool_objtotal);
	printf("nr_if_pool_objsize %u\n", req.nr_if_pool_objsize);
	printf("nr_ring_pool_offset 0x%lx\n", req.nr_if_pool_offset);
	printf("nr_ring_pool_objtotal %u\n", req.nr_ring_pool_objtotal);
	printf("nr_ring_pool_objsize %u\n", req.nr_ring_pool_objsize);
	printf("nr_buf_pool_offset 0x%lx\n", req.nr_buf_pool_offset);
	printf("nr_buf_pool_objtotal %u\n", req.nr_buf_pool_objtotal);
	printf("nr_buf_pool_objsize %u\n", req.nr_buf_pool_objsize);

	return req.nr_memsize && req.nr_if_pool_objtotal &&
	                       req.nr_if_pool_objsize &&
	                       req.nr_ring_pool_objtotal &&
	                       req.nr_ring_pool_objsize &&
	                       req.nr_buf_pool_objtotal &&
	                       req.nr_buf_pool_objsize
	               ? 0
	               : -1;
}

static int
pools_info_get_and_register(struct TestContext *ctx)
{
	int ret;

	/* Check that we can get pools info before we register
	 * a netmap interface. */
	ret = pools_info_get(ctx);
	if (ret) {
		return ret;
	}

	ctx->nr_mode = NR_REG_ONE_NIC;
	ret          = port_register(ctx);
	if (ret) {
		return ret;
	}
	ctx->nr_mem_id = 1;

	/* Check that we can get pools info also after we register. */
	return pools_info_get(ctx);
}

static int
pools_info_get_empty_ifname(struct TestContext *ctx)
{
	ctx->ifname = "";
	return pools_info_get(ctx) != 0 ? 0 : -1;
}

static int
pipe_master(struct TestContext *ctx)
{
	char pipe_name[128];

	snprintf(pipe_name, sizeof(pipe_name), "%s{%s", ctx->ifname, "pipeid1");
	ctx->ifname  = pipe_name;
	ctx->nr_mode = NR_REG_NIC_SW;

	if (port_register(ctx) == 0) {
		printf("pipes should not accept NR_REG_NIC_SW\n");
		return -1;
	}
	ctx->nr_mode = NR_REG_ALL_NIC;

	return port_register(ctx);
}

static int
pipe_slave(struct TestContext *ctx)
{
	char pipe_name[128];

	snprintf(pipe_name, sizeof(pipe_name), "%s}%s", ctx->ifname, "pipeid2");
	ctx->ifname  = pipe_name;
	ctx->nr_mode = NR_REG_ALL_NIC;

	return port_register(ctx);
}

/* Test PORT_INFO_GET and POOLS_INFO_GET on a pipe. This is useful to test the
 * registration request used internall by netmap. */
static int
pipe_port_info_get(struct TestContext *ctx)
{
	char pipe_name[128];

	snprintf(pipe_name, sizeof(pipe_name), "%s}%s", ctx->ifname, "pipeid3");
	ctx->ifname = pipe_name;

	return port_info_get(ctx);
}

static int
pipe_pools_info_get(struct TestContext *ctx)
{
	char pipe_name[128];

	snprintf(pipe_name, sizeof(pipe_name), "%s{%s", ctx->ifname, "xid");
	ctx->ifname = pipe_name;

	return pools_info_get(ctx);
}

/* NETMAP_REQ_VALE_POLLING_ENABLE */
static int
vale_polling_enable(struct TestContext *ctx)
{
	struct nmreq_vale_polling req;
	struct nmreq_header hdr;
	char vpname[256];
	int ret;

	snprintf(vpname, sizeof(vpname), "%s:%s", ctx->bdgname, ctx->ifname);
	printf("Testing NETMAP_REQ_VALE_POLLING_ENABLE on '%s'\n", vpname);

	nmreq_hdr_init(&hdr, vpname);
	hdr.nr_reqtype = NETMAP_REQ_VALE_POLLING_ENABLE;
	hdr.nr_body    = (uintptr_t)&req;
	memset(&req, 0, sizeof(req));
	req.nr_mode             = ctx->nr_mode;
	req.nr_first_cpu_id     = ctx->nr_first_cpu_id;
	req.nr_num_polling_cpus = ctx->nr_num_polling_cpus;
	ret                     = ioctl(ctx->fd, NIOCCTRL, &hdr);
	if (ret) {
		perror("ioctl(/dev/netmap, NIOCCTRL, VALE_POLLING_ENABLE)");
		return ret;
	}

	return (req.nr_mode == ctx->nr_mode &&
	        req.nr_first_cpu_id == ctx->nr_first_cpu_id &&
	        req.nr_num_polling_cpus == ctx->nr_num_polling_cpus)
	               ? 0
	               : -1;
}

/* NETMAP_REQ_VALE_POLLING_DISABLE */
static int
vale_polling_disable(struct TestContext *ctx)
{
	struct nmreq_vale_polling req;
	struct nmreq_header hdr;
	char vpname[256];
	int ret;

	snprintf(vpname, sizeof(vpname), "%s:%s", ctx->bdgname, ctx->ifname);
	printf("Testing NETMAP_REQ_VALE_POLLING_DISABLE on '%s'\n", vpname);

	nmreq_hdr_init(&hdr, vpname);
	hdr.nr_reqtype = NETMAP_REQ_VALE_POLLING_DISABLE;
	hdr.nr_body    = (uintptr_t)&req;
	memset(&req, 0, sizeof(req));
	ret = ioctl(ctx->fd, NIOCCTRL, &hdr);
	if (ret) {
		perror("ioctl(/dev/netmap, NIOCCTRL, VALE_POLLING_DISABLE)");
		return ret;
	}

	return 0;
}

static int
vale_polling_enable_disable(struct TestContext *ctx)
{
	int ret = 0;

	if ((ret = vale_attach(ctx))) {
		return ret;
	}

	ctx->nr_mode             = NETMAP_POLLING_MODE_SINGLE_CPU;
	ctx->nr_num_polling_cpus = 1;
	ctx->nr_first_cpu_id     = 0;
	if ((ret = vale_polling_enable(ctx))) {
		vale_detach(ctx);
#ifdef __FreeBSD__
		/* NETMAP_REQ_VALE_POLLING_DISABLE is disabled on FreeBSD,
		 * because it is currently broken. We are happy to see that
		 * it fails. */
		return 0;
#endif
		return ret;
	}

	if ((ret = vale_polling_disable(ctx))) {
		vale_detach(ctx);
		return ret;
	}

	return vale_detach(ctx);
}

static void
push_option(struct nmreq_option *opt, struct TestContext *ctx)
{
	opt->nro_next = (uintptr_t)ctx->nr_opt;
	ctx->nr_opt   = opt;
}

static void
clear_options(struct TestContext *ctx)
{
	ctx->nr_opt = NULL;
}

static int
checkoption(struct nmreq_option *opt, struct nmreq_option *exp)
{
	if (opt->nro_next != exp->nro_next) {
		printf("nro_next %p expected %p\n",
		       (void *)(uintptr_t)opt->nro_next,
		       (void *)(uintptr_t)exp->nro_next);
		return -1;
	}
	if (opt->nro_reqtype != exp->nro_reqtype) {
		printf("nro_reqtype %u expected %u\n", opt->nro_reqtype,
		       exp->nro_reqtype);
		return -1;
	}
	if (opt->nro_status != exp->nro_status) {
		printf("nro_status %u expected %u\n", opt->nro_status,
		       exp->nro_status);
		return -1;
	}
	return 0;
}

static int
unsupported_option(struct TestContext *ctx)
{
	struct nmreq_option opt, save;

	printf("Testing unsupported option on %s\n", ctx->ifname);

	memset(&opt, 0, sizeof(opt));
	opt.nro_reqtype = 1234;
	push_option(&opt, ctx);
	save = opt;

	if (port_register_hwall(ctx) >= 0)
		return -1;

	clear_options(ctx);
	save.nro_status = EOPNOTSUPP;
	return checkoption(&opt, &save);
}

static int
infinite_options(struct TestContext *ctx)
{
	struct nmreq_option opt;

	printf("Testing infinite list of options on %s\n", ctx->ifname);

	opt.nro_reqtype = 1234;
	push_option(&opt, ctx);
	opt.nro_next = (uintptr_t)&opt;
	if (port_register_hwall(ctx) >= 0)
		return -1;
	clear_options(ctx);
	return (errno == EMSGSIZE ? 0 : -1);
}

#ifdef CONFIG_NETMAP_EXTMEM
static int
change_param(const char *pname, unsigned long newv, unsigned long *poldv)
{
#ifdef __linux__
	char param[256] = "/sys/module/netmap/parameters/";
	unsigned long oldv;
	FILE *f;

	strncat(param, pname, sizeof(param) - 1);

	f = fopen(param, "r+");
	if (f == NULL) {
		perror(param);
		return -1;
	}
	if (fscanf(f, "%ld", &oldv) != 1) {
		perror(param);
		fclose(f);
		return -1;
	}
	if (poldv)
		*poldv = oldv;
	rewind(f);
	if (fprintf(f, "%ld\n", newv) < 0) {
		perror(param);
		fclose(f);
		return -1;
	}
	fclose(f);
	printf("change_param: %s: %ld -> %ld\n", pname, oldv, newv);
#endif /* __linux__ */
	return 0;
}

static int
push_extmem_option(struct TestContext *ctx, struct nmreq_opt_extmem *e)
{
	void *addr;

	addr = mmap(NULL, (1U << 22), PROT_READ | PROT_WRITE,
	            MAP_ANONYMOUS | MAP_SHARED, -1, 0);
	if (addr == MAP_FAILED) {
		perror("mmap");
		return -1;
	}

	memset(e, 0, sizeof(*e));
	e->nro_opt.nro_reqtype = NETMAP_REQ_OPT_EXTMEM;
	e->nro_usrptr          = (uintptr_t)addr;
	e->nro_info.nr_memsize = (1U << 22);

	push_option(&e->nro_opt, ctx);

	return 0;
}

static int
pop_extmem_option(struct TestContext *ctx, struct nmreq_opt_extmem *exp)
{
	struct nmreq_opt_extmem *e;
	int ret;

	e           = (struct nmreq_opt_extmem *)(uintptr_t)ctx->nr_opt;
	ctx->nr_opt = (struct nmreq_option *)(uintptr_t)ctx->nr_opt->nro_next;

	if ((ret = checkoption(&e->nro_opt, &exp->nro_opt))) {
		return ret;
	}

	if (e->nro_usrptr != exp->nro_usrptr) {
		printf("usrptr %" PRIu64 " expected %" PRIu64 "\n",
		       e->nro_usrptr, exp->nro_usrptr);
		return -1;
	}
	if (e->nro_info.nr_memsize != exp->nro_info.nr_memsize) {
		printf("memsize %" PRIu64 " expected %" PRIu64 "\n",
		       e->nro_info.nr_memsize, exp->nro_info.nr_memsize);
		return -1;
	}

	if ((ret = munmap((void *)(uintptr_t)e->nro_usrptr,
	                  e->nro_info.nr_memsize)))
		return ret;

	return 0;
}

static int
_extmem_option(struct TestContext *ctx, int new_rsz)
{
	struct nmreq_opt_extmem e, save;
	int ret;
	unsigned long old_rsz;

	if ((ret = push_extmem_option(ctx, &e)) < 0)
		return ret;

	save = e;

	ctx->ifname      = "vale0:0";
	ctx->nr_tx_slots = 16;
	ctx->nr_rx_slots = 16;

	if ((ret = change_param("priv_ring_size", new_rsz, &old_rsz)))
		return ret;

	if ((ret = port_register_hwall(ctx)))
		return ret;

	ret = pop_extmem_option(ctx, &save);

	if (change_param("priv_ring_size", old_rsz, NULL) < 0)
		return -1;

	return ret;
}

static int
extmem_option(struct TestContext *ctx)
{
	printf("Testing extmem option on vale0:0\n");

	return _extmem_option(ctx, 512);
}

static int
bad_extmem_option(struct TestContext *ctx)
{
	printf("Testing bad extmem option on vale0:0\n");

	return _extmem_option(ctx, (1 << 16)) < 0 ? 0 : -1;
}

static int
duplicate_extmem_options(struct TestContext *ctx)
{
	struct nmreq_opt_extmem e1, save1, e2, save2;
	int ret;

	printf("Testing duplicate extmem option on vale0:0\n");

	if ((ret = push_extmem_option(ctx, &e1)) < 0)
		return ret;

	if ((ret = push_extmem_option(ctx, &e2)) < 0) {
		clear_options(ctx);
		return ret;
	}

	save1 = e1;
	save2 = e2;

	ret = port_register_hwall(ctx);
	if (ret >= 0) {
		printf("duplicate option not detected\n");
		return -1;
	}

	save2.nro_opt.nro_status = EINVAL;
	if ((ret = pop_extmem_option(ctx, &save2)))
		return ret;

	save1.nro_opt.nro_status = EINVAL;
	if ((ret = pop_extmem_option(ctx, &save1)))
		return ret;

	return 0;
}
#endif /* CONFIG_NETMAP_EXTMEM */

static int
push_csb_option(struct TestContext *ctx, struct nmreq_opt_csb *opt)
{
	size_t csb_size;
	int num_entries;
	int ret;

	ctx->nr_flags |= NR_EXCLUSIVE;

	/* Get port info in order to use num_registered_rings(). */
	ret = port_info_get(ctx);
	if (ret) {
		return ret;
	}
	num_entries = num_registered_rings(ctx);

	csb_size = (sizeof(struct nm_csb_atok) + sizeof(struct nm_csb_ktoa)) *
	           num_entries;
	assert(csb_size > 0);
	if (ctx->csb) {
		free(ctx->csb);
	}
	ret = posix_memalign(&ctx->csb, sizeof(struct nm_csb_atok), csb_size);
	if (ret) {
		printf("Failed to allocate CSB memory\n");
		exit(EXIT_FAILURE);
	}

	memset(opt, 0, sizeof(*opt));
	opt->nro_opt.nro_reqtype = NETMAP_REQ_OPT_CSB;
	opt->csb_atok            = (uintptr_t)ctx->csb;
	opt->csb_ktoa            = (uintptr_t)(ctx->csb +
                                    sizeof(struct nm_csb_atok) * num_entries);

	printf("Pushing option NETMAP_REQ_OPT_CSB\n");
	push_option(&opt->nro_opt, ctx);

	return 0;
}

static int
csb_mode(struct TestContext *ctx)
{
	struct nmreq_opt_csb opt;
	int ret;

	ret = push_csb_option(ctx, &opt);
	if (ret) {
		return ret;
	}

	ret = port_register_hwall(ctx);
	clear_options(ctx);

	return ret;
}

static int
csb_mode_invalid_memory(struct TestContext *ctx)
{
	struct nmreq_opt_csb opt;
	int ret;

	memset(&opt, 0, sizeof(opt));
	opt.nro_opt.nro_reqtype = NETMAP_REQ_OPT_CSB;
	opt.csb_atok            = (uintptr_t)0x10;
	opt.csb_ktoa            = (uintptr_t)0x800;
	push_option(&opt.nro_opt, ctx);

	ctx->nr_flags = NR_EXCLUSIVE;
	ret           = port_register_hwall(ctx);
	clear_options(ctx);

	return (ret < 0) ? 0 : -1;
}

static int
sync_kloop_stop(struct TestContext *ctx)
{
	struct nmreq_header hdr;
	int ret;

	printf("Testing NETMAP_REQ_SYNC_KLOOP_STOP on '%s'\n", ctx->ifname);

	nmreq_hdr_init(&hdr, ctx->ifname);
	hdr.nr_reqtype = NETMAP_REQ_SYNC_KLOOP_STOP;
	ret            = ioctl(ctx->fd, NIOCCTRL, &hdr);
	if (ret) {
		perror("ioctl(/dev/netmap, NIOCCTRL, SYNC_KLOOP_STOP)");
	}

	return ret;
}

static void *
sync_kloop_worker(void *opaque)
{
	struct TestContext *ctx = opaque;
	struct nmreq_sync_kloop_start req;
	struct nmreq_header hdr;
	int ret;

	printf("Testing NETMAP_REQ_SYNC_KLOOP_START on '%s'\n", ctx->ifname);

	nmreq_hdr_init(&hdr, ctx->ifname);
	hdr.nr_reqtype = NETMAP_REQ_SYNC_KLOOP_START;
	hdr.nr_body    = (uintptr_t)&req;
	hdr.nr_options = (uintptr_t)ctx->nr_opt;
	memset(&req, 0, sizeof(req));
	req.sleep_us = 500;
	ret          = ioctl(ctx->fd, NIOCCTRL, &hdr);
	if (ret) {
		perror("ioctl(/dev/netmap, NIOCCTRL, SYNC_KLOOP_START)");
	}

	pthread_exit(ret ? (void *)THRET_FAILURE : (void *)THRET_SUCCESS);
}

static int
sync_kloop_start_stop(struct TestContext *ctx)
{
	pthread_t th;
	void *thret = THRET_FAILURE;
	int ret;

	ret = pthread_create(&th, NULL, sync_kloop_worker, ctx);
	if (ret) {
		printf("pthread_create(kloop): %s\n", strerror(ret));
		return -1;
	}

	ret = sync_kloop_stop(ctx);
	if (ret) {
		return ret;
	}

	ret = pthread_join(th, &thret);
	if (ret) {
		printf("pthread_join(kloop): %s\n", strerror(ret));
	}

	return thret == THRET_SUCCESS ? 0 : -1;
}

static int
sync_kloop(struct TestContext *ctx)
{
	int ret;

	ret = csb_mode(ctx);
	if (ret) {
		return ret;
	}

	return sync_kloop_start_stop(ctx);
}

static int
sync_kloop_eventfds(struct TestContext *ctx)
{
	struct nmreq_opt_sync_kloop_eventfds *opt = NULL;
	struct nmreq_option save;
	int num_entries;
	size_t opt_size;
	int ret, i;

	num_entries = num_registered_rings(ctx);
	opt_size    = sizeof(*opt) + num_entries * sizeof(opt->eventfds[0]);
	opt         = malloc(opt_size);
	memset(opt, 0, opt_size);
	opt->nro_opt.nro_next    = 0;
	opt->nro_opt.nro_reqtype = NETMAP_REQ_OPT_SYNC_KLOOP_EVENTFDS;
	opt->nro_opt.nro_status  = 0;
	opt->nro_opt.nro_size    = opt_size;
	for (i = 0; i < num_entries; i++) {
		int efd = eventfd(0, 0);

		assert(efd >= 0);
		opt->eventfds[i].ioeventfd = efd;
		efd                        = eventfd(0, 0);
		assert(efd >= 0);
		opt->eventfds[i].irqfd = efd;
	}

	push_option(&opt->nro_opt, ctx);
	save = opt->nro_opt;

	ret = sync_kloop_start_stop(ctx);
	if (ret) {
		free(opt);
		clear_options(ctx);
		return ret;
	}
#ifdef __linux__
	save.nro_status = 0;
#else  /* !__linux__ */
	save.nro_status = EOPNOTSUPP;
#endif /* !__linux__ */

	ret = checkoption(&opt->nro_opt, &save);
	free(opt);
	clear_options(ctx);

	return ret;
}

static int
sync_kloop_eventfds_all(struct TestContext *ctx)
{
	int ret;

	ret = csb_mode(ctx);
	if (ret) {
		return ret;
	}

	return sync_kloop_eventfds(ctx);
}

static int
sync_kloop_eventfds_all_tx(struct TestContext *ctx)
{
	struct nmreq_opt_csb opt;
	int ret;

	ret = push_csb_option(ctx, &opt);
	if (ret) {
		return ret;
	}

	ret = port_register_hwall_tx(ctx);
	if (ret) {
		return ret;
	}
	clear_options(ctx);

	return sync_kloop_eventfds(ctx);
}

static int
sync_kloop_nocsb(struct TestContext *ctx)
{
	int ret;

	ret = port_register_hwall(ctx);
	if (ret) {
		return ret;
	}

	/* Sync kloop must fail because we did not use
	 * NETMAP_REQ_CSB_ENABLE. */
	return sync_kloop_start_stop(ctx) != 0 ? 0 : -1;
}

static int
csb_enable(struct TestContext *ctx)
{
	struct nmreq_option saveopt;
	struct nmreq_opt_csb opt;
	struct nmreq_header hdr;
	int ret;

	ret = push_csb_option(ctx, &opt);
	if (ret) {
		return ret;
	}
	saveopt = opt.nro_opt;
	saveopt.nro_status = 0;

	nmreq_hdr_init(&hdr, ctx->ifname);
	hdr.nr_reqtype = NETMAP_REQ_CSB_ENABLE;
	hdr.nr_options = (uintptr_t)ctx->nr_opt;
	hdr.nr_body = (uintptr_t)NULL;

	printf("Testing NETMAP_REQ_CSB_ENABLE on '%s'\n", ctx->ifname);

	ret           = ioctl(ctx->fd, NIOCCTRL, &hdr);
	if (ret) {
		perror("ioctl(/dev/netmap, NIOCCTRL, CSB_ENABLE)");
		return ret;
	}

	ret = checkoption(&opt.nro_opt, &saveopt);
	clear_options(ctx);

	return ret;
}

static int
sync_kloop_csb_enable(struct TestContext *ctx)
{
	int ret;

	ctx->nr_flags |= NR_EXCLUSIVE;
	ret = port_register_hwall(ctx);
	if (ret) {
		return ret;
	}

	ret = csb_enable(ctx);
	if (ret) {
		return ret;
	}

	return sync_kloop_start_stop(ctx);
}

static int
sync_kloop_conflict(struct TestContext *ctx)
{
	struct nmreq_opt_csb opt;
	pthread_t th1, th2;
	void *thret1 = THRET_FAILURE, *thret2 = THRET_FAILURE;
	int ret;

	ret = push_csb_option(ctx, &opt);
	if (ret) {
		return ret;
	}

	ret = port_register_hwall(ctx);
	if (ret) {
		return ret;
	}
	clear_options(ctx);

	ret = pthread_create(&th1, NULL, sync_kloop_worker, ctx);
	if (ret) {
		printf("pthread_create(kloop1): %s\n", strerror(ret));
		return -1;
	}

	ret = pthread_create(&th2, NULL, sync_kloop_worker, ctx);
	if (ret) {
		printf("pthread_create(kloop2): %s\n", strerror(ret));
		return -1;
	}

	/* Try to avoid a race condition where th1 starts the loop and stops,
	 * and after that th2 starts the loop successfully. */
	usleep(500000);

	ret = sync_kloop_stop(ctx);
	if (ret) {
		return ret;
	}

	ret = pthread_join(th1, &thret1);
	if (ret) {
		printf("pthread_join(kloop1): %s\n", strerror(ret));
	}

	ret = pthread_join(th2, &thret2);
	if (ret) {
		printf("pthread_join(kloop2): %s %d\n", strerror(ret), ret);
	}

	/* Check that one of the two failed, while the other one succeeded. */
	return ((thret1 == THRET_SUCCESS && thret2 == THRET_FAILURE) ||
			(thret1 == THRET_FAILURE && thret2 == THRET_SUCCESS))
	               ? 0
	               : -1;
}

static int
sync_kloop_eventfds_mismatch(struct TestContext *ctx)
{
	struct nmreq_opt_csb opt;
	int ret;

	ret = push_csb_option(ctx, &opt);
	if (ret) {
		return ret;
	}

	ret = port_register_hwall_rx(ctx);
	if (ret) {
		return ret;
	}
	clear_options(ctx);

	/* Deceive num_registered_rings() to trigger a failure of
	 * sync_kloop_eventfds(). The latter will think that all the
	 * rings were registered, and allocate the wrong number of
	 * eventfds. */
	ctx->nr_flags &= ~NR_RX_RINGS_ONLY;

	return (sync_kloop_eventfds(ctx) != 0) ? 0 : -1;
}

static int
null_port(struct TestContext *ctx)
{
	int ret;

	ctx->nr_mem_id = 1;
	ctx->nr_mode = NR_REG_NULL;
	ctx->nr_tx_rings = 10;
	ctx->nr_rx_rings = 5;
	ctx->nr_tx_slots = 256;
	ctx->nr_rx_slots = 100;
	ret = port_register(ctx);
	if (ret) {
		return ret;
	}
	return 0;
}

static int
null_port_all_zero(struct TestContext *ctx)
{
	int ret;

	ctx->nr_mem_id = 1;
	ctx->nr_mode = NR_REG_NULL;
	ctx->nr_tx_rings = 0;
	ctx->nr_rx_rings = 0;
	ctx->nr_tx_slots = 0;
	ctx->nr_rx_slots = 0;
	ret = port_register(ctx);
	if (ret) {
		return ret;
	}
	return 0;
}

static int
null_port_sync(struct TestContext *ctx)
{
	int ret;

	ctx->nr_mem_id = 1;
	ctx->nr_mode = NR_REG_NULL;
	ctx->nr_tx_rings = 10;
	ctx->nr_rx_rings = 5;
	ctx->nr_tx_slots = 256;
	ctx->nr_rx_slots = 100;
	ret = port_register(ctx);
	if (ret) {
		return ret;
	}
	ret = ioctl(ctx->fd, NIOCTXSYNC, 0);
	if (ret) {
		return ret;
	}
	return 0;
}

static void
usage(const char *prog)
{
	printf("%s -i IFNAME\n"
	       "[-j TEST_NUM1[-[TEST_NUM2]] | -[TEST_NUM_2]]\n"
	       "[-l (list test cases)]\n",
	       prog);
}

struct mytest {
	testfunc_t test;
	const char *name;
};

#define decltest(f)                                                            \
	{                                                                      \
		.test = f, .name = #f                                          \
	}

static struct mytest tests[] = {
	decltest(port_info_get),
	decltest(port_register_hwall_host),
	decltest(port_register_hwall),
	decltest(port_register_host),
	decltest(port_register_single_ring_couple),
	decltest(vale_attach_detach),
	decltest(vale_attach_detach_host_rings),
	decltest(vale_ephemeral_port_hdr_manipulation),
	decltest(vale_persistent_port),
	decltest(pools_info_get_and_register),
	decltest(pools_info_get_empty_ifname),
	decltest(pipe_master),
	decltest(pipe_slave),
	decltest(pipe_port_info_get),
	decltest(pipe_pools_info_get),
	decltest(vale_polling_enable_disable),
	decltest(unsupported_option),
	decltest(infinite_options),
#ifdef CONFIG_NETMAP_EXTMEM
	decltest(extmem_option),
	decltest(bad_extmem_option),
	decltest(duplicate_extmem_options),
#endif /* CONFIG_NETMAP_EXTMEM */
	decltest(csb_mode),
	decltest(csb_mode_invalid_memory),
	decltest(sync_kloop),
	decltest(sync_kloop_eventfds_all),
	decltest(sync_kloop_eventfds_all_tx),
	decltest(sync_kloop_nocsb),
	decltest(sync_kloop_csb_enable),
	decltest(sync_kloop_conflict),
	decltest(sync_kloop_eventfds_mismatch),
	decltest(null_port),
	decltest(null_port_all_zero),
	decltest(null_port_sync),
	decltest(legacy_regif_default),
	decltest(legacy_regif_all_nic),
	decltest(legacy_regif_12),
	decltest(legacy_regif_sw),
	decltest(legacy_regif_future),
	decltest(legacy_regif_extra_bufs),
	decltest(legacy_regif_extra_bufs_pipe),
	decltest(legacy_regif_extra_bufs_pipe_vale),
};

static void
context_cleanup(struct TestContext *ctx)
{
	if (ctx->csb) {
		free(ctx->csb);
		ctx->csb = NULL;
	}

	close(ctx->fd);
}

static int
parse_interval(const char *arg, int *j, int *k)
{
	const char *scan = arg;
	char *rest;

	*j = 0;
	*k = -1;
	if (*scan == '-') {
		scan++;
		goto get_k;
	}
	if (!isdigit(*scan))
		goto err;
	*k = strtol(scan, &rest, 10);
	*j = *k - 1;
	scan = rest;
	if (*scan == '-') {
		*k = -1;
		scan++;
	}
get_k:
	if (*scan == '\0')
		return 0;
	if (!isdigit(*scan))
		goto err;
	*k = strtol(scan, &rest, 10);
	scan = rest;
	if (!(*scan == '\0'))
		goto err;

	return 0;

err:
	fprintf(stderr, "syntax error in '%s', must be num[-[num]] or -[num]\n", arg);
	return -1;
}

int
main(int argc, char **argv)
{
	struct TestContext ctx;
	int loopback_if;
	int num_tests;
	int ret  = 0;
	int j    = 0;
	int k    = -1;
	int list = 0;
	int opt;
	int i;

	memset(&ctx, 0, sizeof(ctx));
	ctx.ifname  = "lo";
	ctx.bdgname = "vale1x2";

	while ((opt = getopt(argc, argv, "hi:j:l")) != -1) {
		switch (opt) {
		case 'h':
			usage(argv[0]);
			return 0;

		case 'i':
			ctx.ifname = optarg;
			break;

		case 'j':
			if (parse_interval(optarg, &j, &k) < 0) {
				usage(argv[0]);
				return -1;
			}
			break;

		case 'l':
			list = 1;
			break;

		default:
			printf("    Unrecognized option %c\n", opt);
			usage(argv[0]);
			return -1;
		}
	}

	num_tests = sizeof(tests) / sizeof(tests[0]);

	if (j < 0 || j >= num_tests || k > num_tests) {
		fprintf(stderr, "Test interval %d-%d out of range (%d-%d)\n",
				j + 1, k, 1, num_tests + 1);
		return -1;
	}

	if (k < 0)
		k = num_tests;

	if (list) {
		printf("Available tests:\n");
		for (i = 0; i < num_tests; i++) {
			printf("#%03d: %s\n", i + 1, tests[i].name);
		}
		return 0;
	}

	loopback_if = !strcmp(ctx.ifname, "lo");
	if (loopback_if) {
		/* For the tests, we need the MTU to be smaller than
		 * the NIC RX buffer size, otherwise we will fail on
		 * registering the interface. To stay safe, let's
		 * just use a standard MTU. */
		if (system("ip link set dev lo mtu 1514")) {
			printf("system(%s, mtu=1514) failed\n", ctx.ifname);
			return -1;
		}
	}

	for (i = j; i < k; i++) {
		struct TestContext ctxcopy;
		int fd;
		printf("==> Start of Test #%d [%s]\n", i + 1, tests[i].name);
		fd = open("/dev/netmap", O_RDWR);
		if (fd < 0) {
			perror("open(/dev/netmap)");
			ret = fd;
			goto out;
		}
		memcpy(&ctxcopy, &ctx, sizeof(ctxcopy));
		ctxcopy.fd = fd;
		ret        = tests[i].test(&ctxcopy);
		if (ret) {
			printf("Test #%d [%s] failed\n", i + 1, tests[i].name);
			goto out;
		}
		printf("==> Test #%d [%s] successful\n", i + 1, tests[i].name);
		context_cleanup(&ctxcopy);
	}
out:
	if (loopback_if) {
		if (system("ip link set dev lo mtu 65536")) {
			perror("system(mtu=1514)");
			return -1;
		}
	}

	return ret;
}
