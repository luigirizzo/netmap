#define TEST_NETMAP

#include <ctype.h>
#include <errno.h>
#include <fcntl.h> /* O_RDWR */
#include <inttypes.h>
#include <pthread.h>
#include <signal.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>  /* PROT_* */
#include <sys/param.h> /* ULONG_MAX */
#include <sys/poll.h>
#include <sys/wait.h>
#include <unistd.h>

#define MAX_VARS 100

char *variables[MAX_VARS];
int curr_var;

#define VAR_FAILED ((void *)1)

char *
firstarg(char *buf)
{
	int v;
	char *arg = strtok(buf, " \t\n");
	char *ret;
	if (!arg)
		return NULL;
	if (arg[0] != '$' && arg[0] != '?')
		return arg;
	v = atoi(arg + 1);
	if (v < 0 || v >= MAX_VARS)
		return "";
	ret = variables[v];
	if (ret == NULL)
		return "NULL";
	if (ret == VAR_FAILED) {
		printf("reading failed var, exit\n");
		exit(1);
	}
	if (arg[0] == '?')
		return ret;
	ret = rindex(ret, '=') + 1;
	return ret;
}

char *
nextarg()
{
	return firstarg(NULL);
}

char *
restofline()
{
	return strtok(NULL, "\n");
}

void
resetvar(int v, char *b)
{
	if (variables[v] != VAR_FAILED)
		free(variables[v]);
	variables[v] = b;
}

#define outecho(format, args...)                                               \
	do {                                                                   \
		printf("%u:%lu: " format "\n", getpid(),                       \
		       (unsigned long)pthread_self(), ##args);                 \
		fflush(stdout);                                                \
	} while (0)

#define output(format, args...)                                                \
	do {                                                                   \
		resetvar(curr_var, (char *)malloc(1024));                      \
		snprintf(variables[curr_var], 1024, format, ##args);           \
		outecho(format, ##args);                                       \
	} while (0)

#define output_err(ret, format, args...)                                       \
	do {                                                                   \
		if ((ret) < 0) {                                               \
			resetvar(curr_var, VAR_FAILED);                        \
			outecho(format, ##args);                               \
			outecho("error: %s", strerror(errno));                 \
		} else {                                                       \
			output(format, ##args);                                \
		}                                                              \
	} while (0)

struct chan {
	FILE *out;
	pid_t pid;
	pthread_t tid;
};

int
chan_search_free(struct chan *c[], int max)
{
	int i;

	for (i = 0; i < max && c[i]; i++)
		;

	return i;
}

void
chan_clear_all(struct chan *c[], int max)
{
	int i;

	for (i = 0; i < max; i++) {
		if (c[i]) {
			fclose(c[i]->out);
			free(c[i]);
			c[i] = NULL;
		}
	}
}

int last_fd	    = -1;
size_t last_memsize    = 0;
void *last_mmap_addr   = NULL;
char *last_access_addr = NULL;

void
do_open()
{
	last_fd = open("/dev/netmap", O_RDWR);
	output_err(last_fd, "open(\"/dev/netmap\", O_RDWR)=%d", last_fd);
}

void
do_close()
{
	int ret, fd;
	char *arg = nextarg();
	fd	= arg ? atoi(arg) : last_fd;
	ret       = close(fd);
	output_err(ret, "close(%d)=%d", fd, ret);
}

#ifdef TEST_NETMAP
#include <ifaddrs.h>
#include <net/netmap_user.h>
#include <net/netmap_virt.h>
#include <sys/ioctl.h>
#include <sys/socket.h>

/* legacy */
struct nmreq curr_nmr = {
	.nr_version = 11,
	.nr_flags   = NR_REG_ALL_NIC,
};
char nmr_name[256];

void
parse_nmr_config(char *w, struct nmreq *nmr)
{
	char *tok;
	int i, v;

	nmr->nr_tx_rings = nmr->nr_rx_rings = 0;
	nmr->nr_tx_slots = nmr->nr_rx_slots = 0;
	if (w == NULL || !*w)
		return;
	for (i = 0, tok = strtok(w, ","); tok; i++, tok = strtok(NULL, ",")) {
		v = atoi(tok);
		switch (i) {
		case 0:
			nmr->nr_tx_slots = nmr->nr_rx_slots = v;
			break;
		case 1:
			nmr->nr_rx_slots = v;
			break;
		case 2:
			nmr->nr_tx_rings = nmr->nr_rx_rings = v;
			break;
		case 3:
			nmr->nr_rx_rings = v;
			break;
		default:
			break;
		}
	}
}

void
do_getinfo_legacy()
{
	int ret;
	char *arg, *name;
	int fd;

	bzero(&curr_nmr, sizeof(curr_nmr));
	curr_nmr.nr_version = NETMAP_API;

	name = nextarg();
	if (name) {
		strncpy(curr_nmr.nr_name, name, sizeof(curr_nmr.nr_name)-1);
	} else {
		name = "any";
	}

	arg = nextarg();
	if (!arg) {
		fd = last_fd;
		goto doit;
	}
	fd = atoi(arg);

	arg = nextarg();
	parse_nmr_config(arg, &curr_nmr);

doit:
	ret	  = ioctl(fd, NIOCGINFO, &curr_nmr);
	last_memsize = curr_nmr.nr_memsize;
	output_err(ret, "ioctl(%d, NIOCGINFO) for %s: region %d memsize=%zu",
		   fd, name, curr_nmr.nr_arg2, last_memsize);
}

void
do_regif_legacy()
{
	int ret;
	char *arg, *name;
	int fd = last_fd;

	name = nextarg();
	if (!name) {
		name = nmr_name;
		goto doit;
	}

	bzero(&curr_nmr, sizeof(curr_nmr));
	curr_nmr.nr_version = NETMAP_API;
	curr_nmr.nr_flags   = NR_REG_ALL_NIC;
	strncpy(curr_nmr.nr_name, name, sizeof(curr_nmr.nr_name)-1);

	arg = nextarg();
	if (!arg) {
		goto doit;
	}
	fd = atoi(arg);

	arg = nextarg();
	parse_nmr_config(arg, &curr_nmr);

doit:
	ret	  = ioctl(fd, NIOCREGIF, &curr_nmr);
	last_memsize = curr_nmr.nr_memsize;
	output_err(ret, "ioctl(%d, NIOCREGIF) for %s: region %d memsize=%zu",
		   fd, name, curr_nmr.nr_arg2, last_memsize);
}

void
do_txsync()
{
	char *arg = nextarg();
	int fd    = arg ? atoi(arg) : last_fd;
	int ret   = ioctl(fd, NIOCTXSYNC, NULL);
	output_err(ret, "ioctl(%d, NIOCTXSYNC)=%d", fd, ret);
}

void
do_rxsync()
{
	char *arg = nextarg();
	int fd    = arg ? atoi(arg) : last_fd;
	int ret   = ioctl(fd, NIOCRXSYNC, NULL);
	output_err(ret, "ioctl(%d, NIOCRXSYNC)=%d", fd, ret);
}
#endif /* TEST_NETMAP */

void
do_rd()
{
	char *arg = nextarg();
	char *p;
	if (!arg) {
		if (!last_access_addr) {
			output("missing address");
			return;
		}
		p = last_access_addr;
	} else {
		p = (char *)strtoul((void *)arg, NULL, 0);
	}
	last_access_addr = p + 4096;
	output("%2x", *p);
}

char *last_wr_byte = "x";
void
do_wr()
{
	char *arg = nextarg();
	char *p;
	if (!arg) {
		if (!last_access_addr) {
			output("missing address");
			return;
		}
		p = last_access_addr;
		last_access_addr += 4096;
	} else {
		p = (char *)strtoul((void *)arg, NULL, 0);
	}
	arg = nextarg();
	if (!arg) {
		arg = last_wr_byte;
	}
	for (; arg; arg = nextarg()) {
		*p++ = strtoul((void *)arg, NULL, 0);
	}
}

void
do_dup()
{
	char *arg = nextarg();
	int fd    = last_fd;
	int ret;

	if (arg) {
		fd = atoi(arg);
	}
	ret = dup(fd);
	output_err(ret, "dup(%d)=%d", fd, ret);
}

void
do_mmap()
{
	size_t memsize;
	off_t off = 0;
	int fd;
	char *arg;

	arg = nextarg();
	if (!arg) {
		memsize = last_memsize;
		fd      = last_fd;
		goto doit;
	}
	memsize = atoi(arg);
	arg     = nextarg();
	if (!arg) {
		fd = last_fd;
		goto doit;
	}
	fd  = atoi(arg);
	arg = nextarg();
	if (arg) {
		off = (off_t)atol(arg);
	}
doit:
	last_mmap_addr =
		mmap(0, memsize, PROT_WRITE | PROT_READ, MAP_SHARED, fd, off);
	if (last_access_addr == NULL)
		last_access_addr = last_mmap_addr;
	output_err(last_mmap_addr == MAP_FAILED ? -1 : 0,
		   "mmap(0, %zu, PROT_WRITE|PROT_READ, MAP_SHARED, %d, %jd)=%p",
		   memsize, fd, (intmax_t)off, last_mmap_addr);
}

#ifndef MAP_HUGETLB
#define MAP_HUGETLB 0x40000
#endif

void
do_anon_mmap()
{
	size_t memsize;
	char *arg;
	int flags = 0;

	arg = nextarg();
	if (!arg) {
		memsize = last_memsize;
		goto doit;
	}
	memsize = atoi(arg);
	arg     = nextarg();
	if (!arg)
		goto doit;
	flags |= MAP_HUGETLB;
doit:
	last_mmap_addr = mmap(0, memsize, PROT_WRITE | PROT_READ,
			      MAP_SHARED | MAP_ANONYMOUS | flags, -1, 0);
	if (last_access_addr == NULL)
		last_access_addr = last_mmap_addr;
	output_err(last_mmap_addr == MAP_FAILED ? -1 : 0,
		   "mmap(0, %zu, PROT_WRITE|PROT_READ, "
		   "MAP_SHARED|MAP_ANONYMOUS%s, -1, 0)=%p",
		   memsize, (flags ? "|MAP_HUGETLB" : ""), last_mmap_addr);
}

void
do_munmap()
{
	void *mmap_addr;
	size_t memsize;
	char *arg;
	int ret;

	arg = nextarg();
	if (!arg) {
		mmap_addr = last_mmap_addr;
		memsize   = last_memsize;
		goto doit;
	}
	mmap_addr = (void *)strtoul(arg, NULL, 0);
	arg       = nextarg();
	if (!arg) {
		memsize = last_memsize;
		goto doit;
	}
	memsize = (size_t)strtoul(arg, NULL, 0);
doit:
	ret = munmap(mmap_addr, memsize);
	output_err(ret, "munmap(%p, %zu)=%d", mmap_addr, memsize, ret);
}

void
do_poll()
{
	/* timeout fd fd... */
	nfds_t nfds = 0, allocated_fds = 10, i;
	struct pollfd *fds;
	int timeout = 500; /* 1/2 second */
	char *arg;
	int ret;

	arg = nextarg();
	if (arg)
		timeout = atoi(arg);
	fds = malloc(allocated_fds * sizeof(struct pollfd));
	if (fds == NULL) {
		output_err(-1, "out of memory");
		return;
	}
	while ((arg = nextarg())) {
		if (nfds >= allocated_fds) {
			struct pollfd *new_fds;
			allocated_fds *= 2;
			new_fds = realloc(fds, allocated_fds *
						       sizeof(struct pollfd));
			if (new_fds == NULL) {
				free(fds);
				output_err(-1, "out of memory");
				return;
			}
			fds = new_fds;
		}
		fds[nfds].fd     = atoi(arg);
		fds[nfds].events = POLLIN;
		nfds++;
	}
	ret = poll(fds, nfds, timeout);
	for (i = 0; i < nfds; i++) {
		output("poll(%d)=%s%s%s%s%s", fds[i].fd,
		       (fds[i].revents & POLLIN) ? "IN  " : "-   ",
		       (fds[i].revents & POLLOUT) ? "OUT " : "-   ",
		       (fds[i].revents & POLLERR) ? "ERR " : "-   ",
		       (fds[i].revents & POLLHUP) ? "HUP " : "-   ",
		       (fds[i].revents & POLLNVAL) ? "NVAL" : "-");
	}
	output_err(ret, "poll(...)=%d", ret);
	free(fds);
}

void
do_expr()
{
	unsigned long stack[11];
	int top = 10;
	char *arg;
	int err = 0;

	stack[10] = ULONG_MAX;
	while ((arg = nextarg())) {
		errno = 0;
		char *rest;
		unsigned long n = strtoul(arg, &rest, 0);
		if (!errno && rest != arg) {
			if (top <= 0) {
				err = -1;
				break;
			}
			stack[--top] = n;
			continue;
		}
		if (top <= 8) {
			unsigned long n1 = stack[top++];
			unsigned long n2 = stack[top++];
			unsigned long r  = 0;
			switch (arg[0]) {
			case '+':
				r = n1 + n2;
				break;
			case '-':
				r = n1 - n2;
				break;
			case '*':
				r = n1 * n2;
				break;
			case '/':
				if (n2)
					r = n1 / n2;
				else {
					errno = EDOM;
					err   = -1;
				}
				break;
			default:
				err = -1;
				break;
			}
			stack[--top] = r;
			continue;
		}
		err = -1;
		break;
	}
	output_err(err, "expr=%lu", stack[top]);
}

void
do_echo()
{
	char *arg;
	for (arg = nextarg(); arg; arg = nextarg()) {
		printf("%s\n", arg);
	}
}

void
do_vars()
{
	int i;
	for (i = 0; i < MAX_VARS; i++) {
		const char *v = variables[i];
		if (v == NULL)
			continue;
		printf("?%d\t%s\n", i, v == VAR_FAILED ? "FAILED" : v);
	}
}

struct netmap_if *
get_if()
{
	void *mmap_addr;
	uint32_t off;
	char *arg;

	/* defaults */
	off       = curr_nmr.nr_offset;
	mmap_addr = last_mmap_addr;

	/* first arg: if offset */
	arg = nextarg();
	if (!arg || (strcmp(arg, "-") == 0)) {
		goto doit;
	}
	off = strtoul(arg, NULL, 0);
	/* second arg: mmap address */
	arg = nextarg();
	if (!arg) {
		goto doit;
	}
	mmap_addr = (void *)strtoul(arg, NULL, 0);
doit:
	return NETMAP_IF(mmap_addr, off);
}

void
do_if()
{
	struct netmap_if *nifp;
	unsigned int i;

	nifp = get_if();

	printf("name       %s\n", nifp->ni_name);
	printf("version    %u\n", nifp->ni_version);
	printf("flags      %x", nifp->ni_flags);
	if (nifp->ni_flags) {
		printf(" [");
		if (nifp->ni_flags & NI_PRIV_MEM) {
			printf(" PRIV_MEM");
		}
		printf(" ]");
	}
	printf("\n");
	printf("tx_rings        %u\n", nifp->ni_tx_rings);
	printf("rx_rings        %u\n", nifp->ni_rx_rings);
	printf("bufs_head       %u\n", nifp->ni_bufs_head);
	printf("host_tx_rings   %u\n", nifp->ni_host_tx_rings);
	printf("host_rx_rings   %u\n", nifp->ni_host_rx_rings);
	for (i = 0; i < 3; i++)
		printf("spare1[%d]  %u\n", i, nifp->ni_spare1[i]);
	for (i = 0; i < (nifp->ni_tx_rings + nifp->ni_rx_rings + nifp->ni_host_tx_rings + nifp->ni_host_rx_rings); i++)
		printf("ring_ofs[%d] %zd\n", i, nifp->ring_ofs[i]);
}

struct netmap_ring *
get_ring()
{
	struct netmap_if *nifp;
	char *arg;
	unsigned int ringid;

	/* defaults */
	ringid = 0;

	/* first arg: ring number */
	arg = nextarg();
	if (!arg)
		goto doit;
	ringid = strtoul(arg, NULL, 0);
doit:
	nifp = get_if();
	return NETMAP_TXRING(nifp, ringid);
}

void
dump_ring(struct netmap_ring *ring)
{
	printf("buf_ofs     %" PRId64 "\n", ring->buf_ofs);
	printf("num_slots   %u\n", ring->num_slots);
	printf("nr_buf_size %u\n", ring->nr_buf_size);
	printf("ringid      %d\n", ring->ringid);
	printf("dir         %d [", ring->dir);
	switch (ring->dir) {
	case 1:
		printf("rx");
		break;
	case 0:
		printf("tx");
		break;
	default:
		printf("??");
		break;
	}
	printf("]\n");
	printf("head        %u\n", ring->head);
	printf("cur         %u\n", ring->cur);
	printf("tail        %u\n", ring->tail);
	printf("flags       %x", ring->flags);
	if (ring->flags) {
		printf(" [");
		if (ring->flags & NR_TIMESTAMP) {
			printf(" TIMESTAMP");
		}
		if (ring->flags & NR_FORWARD) {
			printf(" FORWARD");
		}
		printf(" ]");
	}
	printf("\n");
	printf("ts          %ld:%ld\n", (long int)ring->ts.tv_sec,
	       (long int)ring->ts.tv_usec);
}

void
do_ring()
{
	struct netmap_ring *ring;
	char *arg;
	int upd = -1;
	unsigned int v;

	ring = get_ring();

	arg = nextarg();
	if (!arg) {
		dump_ring(ring);
		return;
	}
	if (strcmp(arg, "head") == 0) {
		upd = 1;
	} else if (strcmp(arg, "cur") == 0) {
		upd = 2;
	} else if (strcmp(arg, "both") == 0) {
		upd = 3;
	} else {
		return;
	}
	arg = nextarg();
	if (!arg) {
		v = ring->cur + 1;
		if (ring->cur >= ring->num_slots)
			ring->cur = 0;
	} else {
		v = strtoul((void *)arg, NULL, 0);
	}
	if (upd & 1)
		ring->head = v;
	if (upd & 2)
		ring->cur = v;
}

void
dump_slot(struct netmap_slot *slot)
{
	printf("buf_idx       %u\n", slot->buf_idx);
	printf("len           %u\n", slot->len);
	printf("flags         %x", slot->flags);
	if (slot->flags) {
		printf(" [");
		if (slot->flags & NS_BUF_CHANGED) {
			printf(" BUF_CHANGED");
		}
		if (slot->flags & NS_REPORT) {
			printf(" REPORT");
		}
		if (slot->flags & NS_FORWARD) {
			printf(" FORWARD");
		}
		if (slot->flags & NS_NO_LEARN) {
			printf(" NO_LEARN");
		}
		if (slot->flags & NS_INDIRECT) {
			printf(" INDIRECT");
		}
		if (slot->flags & NS_MOREFRAG) {
			printf(" MOREFRAG");
		}
		if (NS_RFRAGS(slot)) {
			printf(" fragments=%u", NS_RFRAGS(slot));
		}
		printf(" ]");
	}
	printf("\n");
	printf("ptr           %lx\n", (long)slot->ptr);
}

void
do_slot()
{
	struct netmap_ring *ring;
	struct netmap_slot *slot;
	long int index;
	char *arg;

	/* defaults */
	index = 0;

	arg = nextarg();
	if (!arg)
		goto doit;
	index = strtoll(arg, NULL, 0);
doit:
	ring = get_ring();
	slot = ring->slot + index;
	arg  = nextarg();
	if (!arg) {
		dump_slot(slot);
		return;
	}
	if (strcmp(arg, "buf_idx") == 0) {
		arg = nextarg();
		if (!arg) {
			output("buf_idx=%u", slot->buf_idx);
			return;
		}
		slot->buf_idx = strtoul((void *)arg, NULL, 0);
	} else if (strcmp(arg, "len") == 0) {
		arg = nextarg();
		if (!arg) {
			output("len=%u", slot->len);
			return;
		}
		slot->len = strtoul((void *)arg, NULL, 0);
	}
}

static void
dump_payload(char *p, int len)
{
	char buf[128];
	int i, j, i0;

	/* hexdump routine */
	for (i = 0; i < len;) {
		memset(buf, ' ', sizeof(buf));
		sprintf(buf, "%5d: ", i);
		i0 = i;
		for (j = 0; j < 16 && i < len; i++, j++)
			sprintf(buf + 7 + j * 3, "%02x ", (uint8_t)(p[i]));
		i = i0;
		for (j = 0; j < 16 && i < len; i++, j++)
			sprintf(buf + 7 + j + 48, "%c",
				isprint(p[i]) ? p[i] : '.');
		printf("%s\n", buf);
	}
}

void
do_buf()
{
	struct netmap_ring *ring;
	long int buf_idx, len;
	char *buf, *arg;

	/* defaults */
	buf_idx = 2;
	len     = 64;

	arg = nextarg();
	if (!arg)
		goto doit;
	buf_idx = strtoll(arg, NULL, 0);

	arg = nextarg();
	if (!arg)
		goto doit;
	len = strtoll(arg, NULL, 0);
doit:
	ring = get_ring();
	buf  = NETMAP_BUF(ring, buf_idx);
	output("buf=%p", buf);
	last_access_addr = buf;
	dump_payload(buf, len);
}

struct cmd_def {
	const char *name;
	void (*f)(void);
};

int
_find_command(const struct cmd_def *cmds, int ncmds, const char *cmd)
{
	int i;
	for (i = 0; i < ncmds; i++) {
		if (strcmp(cmds[i].name, cmd) == 0)
			break;
	}
	return i;
}

struct pools_info_field {
	char *name;
	size_t off;
	size_t size;
};
#define PIFD(n, f)                                                             \
	{                                                                      \
		n, offsetof(struct nmreq_pools_info, nr_##f),                  \
			sizeof(((struct nmreq_pools_info *)0)->nr_##f)         \
	}
struct pools_info_field pools_info_fields[] = {
	PIFD("memsize", memsize),
	PIFD("mem_id", mem_id),
	PIFD("if-off", if_pool_offset),
	PIFD("if-tot", if_pool_objtotal),
	PIFD("if-siz", if_pool_objsize),
	PIFD("ring-off", ring_pool_offset),
	PIFD("ring-tot", ring_pool_objtotal),
	PIFD("ring-siz", ring_pool_objsize),
	PIFD("buf-off", buf_pool_offset),
	PIFD("buf-tot", buf_pool_objtotal),
	PIFD("buf-siz", buf_pool_objsize),
	{NULL, 0, 0}};
#define PIF(t, p, o) (*(t *)((void *)((char *)(p) + (o))))
void
pools_info_dump(int tab, struct nmreq_pools_info *upi)
{
	static const char space[] = "        ";
	struct pools_info_field *f;
	for (f = pools_info_fields; f->name; f++) {
		printf("%.*s%-12s", tab, space, f->name);
		switch (f->size) {
		case 8:
			printf("%" PRIu64 "\n", PIF(uint64_t, upi, f->off));
			break;
		case 4:
			printf("%" PRIu32 "\n", PIF(uint32_t, upi, f->off));
			break;
		case 2:
			printf("%" PRIu16 "\n", PIF(uint16_t, upi, f->off));
			break;
		}
	}
}

static struct nmreq_pools_info curr_pools_info;

/* prepare the curr_pools_info */
void
do_pools_info()
{
	char *cmd = nextarg();
	unsigned long long v;

	if (cmd == NULL) {
		pools_info_dump(0, &curr_pools_info);
		return;
	}
	struct pools_info_field *f = NULL;
	for (f = pools_info_fields; f->name; f++) {
		if (strcmp(f->name, cmd) == 0)
			break;
	}
	if (f == NULL)
		return;
	cmd = nextarg();
	if (cmd == NULL)
		return;
	v = strtoll(cmd, NULL, 0);
	switch (f->size) {
	case 8:
		PIF(uint64_t, &curr_pools_info, f->off) = v;
		break;
	case 4:
		PIF(uint32_t, &curr_pools_info, f->off) = v;
		break;
	case 2:
		PIF(uint16_t, &curr_pools_info, f->off) = v;
		break;
	}
}

typedef void (*nmr_arg_interp_fun)();

#define nmr_arg_unexpected(n)                                                  \
	printf("arg%d:      %d%s\n", n, curr_nmr.nr_arg##n,                    \
	       (curr_nmr.nr_arg##n ? "???" : ""))

void
nmr_arg_bdg_attach()
{
	uint16_t v = curr_nmr.nr_arg1;
	printf("arg1:      %d [", v);
	if (v == 0) {
		printf("no host rings");
	} else if (v == NETMAP_BDG_HOST) {
		printf("BDG_HOST");
	} else {
		printf("???");
	}
	printf("]\n");
	nmr_arg_unexpected(2);
	nmr_arg_unexpected(3);
}

void
nmr_arg_bdg_detach()
{
	nmr_arg_unexpected(1);
	nmr_arg_unexpected(2);
	nmr_arg_unexpected(3);
}

void
nmr_arg_bdg_list()
{
	if (!strlen(curr_nmr.nr_name)) {
		nmr_arg_unexpected(1);
		nmr_arg_unexpected(2);
	} else {
		printf("arg1:      %d [bridge]\n", curr_nmr.nr_arg1);
		printf("arg2:      %d [port]\n", curr_nmr.nr_arg2);
	}
	nmr_arg_unexpected(3);
}

void
nmr_arg_bdg_regops()
{
}

void
nmr_arg_vnet_hdr()
{
	printf("arg1:      %d [vnet hdr len]\n", curr_nmr.nr_arg1);
	nmr_arg_unexpected(2);
	nmr_arg_unexpected(3);
}

void
nmr_pt_host_create()
{
}

void
nmr_pt_host_delete()
{
}

void
nmr_bdg_polling_on()
{
	printf("arg1:      %d [nr cpus]\n", curr_nmr.nr_arg1);
	nmr_arg_unexpected(2);
	nmr_arg_unexpected(3);
}

void
nmr_arg_error()
{
	nmr_arg_unexpected(1);
	nmr_arg_unexpected(2);
	nmr_arg_unexpected(3);
}

void
nmr_arg_extra()
{
	printf("arg1:      %d [reserved]\n", curr_nmr.nr_arg1);
	printf("arg2:      %d [%s memory allocator]\n", curr_nmr.nr_arg2,
	       (curr_nmr.nr_arg2 == 0
			? "default"
			: curr_nmr.nr_arg2 == 1 ? "global" : "private"));
	printf("arg3:      %d [%sextra buffers]\n", curr_nmr.nr_arg3,
	       (curr_nmr.nr_arg3 ? "" : "no "));
}

void
do_nmr_legacy_dump()
{
	u_int ringid = curr_nmr.nr_ringid & NETMAP_RING_MASK;
	nmr_arg_interp_fun arg_interp;

	snprintf(nmr_name, IFNAMSIZ + 1, "%s", curr_nmr.nr_name);
	nmr_name[IFNAMSIZ] = '\0';
	printf("name:      %s\n", nmr_name);
	printf("version:   %d\n", curr_nmr.nr_version);
	printf("offset:    %d\n", curr_nmr.nr_offset);
	printf("memsize:   %u [", curr_nmr.nr_memsize);
	if (curr_nmr.nr_memsize < (1 << 20)) {
		printf("%u KiB", curr_nmr.nr_memsize >> 10);
	} else {
		printf("%u MiB", curr_nmr.nr_memsize >> 20);
	}
	printf("]\n");
	printf("tx_slots:  %d\n", curr_nmr.nr_tx_slots);
	printf("rx_slots:  %d\n", curr_nmr.nr_rx_slots);
	printf("tx_rings:  %d\n", curr_nmr.nr_tx_rings);
	printf("rx_rings:  %d\n", curr_nmr.nr_rx_rings);
	printf("ringid:    %x [", curr_nmr.nr_ringid);
	if (curr_nmr.nr_ringid & NETMAP_SW_RING) {
		printf("host rings");
	} else if (curr_nmr.nr_ringid & NETMAP_HW_RING) {
		printf("hw ring %d", ringid);
	} else {
		printf("hw rings");
	}
	if (curr_nmr.nr_ringid & NETMAP_NO_TX_POLL) {
		printf(", no tx poll");
	}
	if (curr_nmr.nr_ringid & NETMAP_DO_RX_POLL) {
		printf(", do rx poll");
	}
	printf(", region %d", curr_nmr.nr_arg2);
	printf("]\n");
	printf("cmd:       %d", curr_nmr.nr_cmd);
	if (curr_nmr.nr_cmd) {
		printf(" [");
		switch (curr_nmr.nr_cmd) {
		case NETMAP_BDG_ATTACH:
			printf("BDG_ATTACH");
			arg_interp = nmr_arg_bdg_attach;
			break;
		case NETMAP_BDG_DETACH:
			printf("BDG_DETACH");
			arg_interp = nmr_arg_bdg_detach;
			break;
		case NETMAP_BDG_REGOPS:
			printf("BDG_REGOPS");
			arg_interp = nmr_arg_bdg_regops;
			break;
		case NETMAP_BDG_LIST:
			printf("BDG_LIST");
			arg_interp = nmr_arg_bdg_list;
			break;
		case NETMAP_BDG_VNET_HDR:
			printf("BDG_VNET_HDR");
			arg_interp = nmr_arg_vnet_hdr;
			break;
		case NETMAP_BDG_NEWIF:
			printf("BDG_NEWIF");
			arg_interp = nmr_arg_error;
			break;
		case NETMAP_BDG_DELIF:
			printf("BDG_DELIF");
			arg_interp = nmr_arg_error;
			break;
		case NETMAP_PT_HOST_CREATE:
			printf("PT_HOST_CREATE");
			arg_interp = nmr_pt_host_create;
			break;
		case NETMAP_PT_HOST_DELETE:
			printf("PT_HOST_DELETE");
			arg_interp = nmr_pt_host_delete;
			break;
		case NETMAP_BDG_POLLING_ON:
			printf("BDG_POLLING_ON");
			arg_interp = nmr_bdg_polling_on;
			break;
		case NETMAP_BDG_POLLING_OFF:
			printf("BDG_POLLING_OFF");
			arg_interp = nmr_arg_error;
			break;
		default:
			printf("???");
			arg_interp = nmr_arg_error;
			break;
		}
		printf("]");
	} else {
		arg_interp = nmr_arg_extra;
	}
	printf("\n");
	arg_interp();
	printf("flags:     %x [", curr_nmr.nr_flags);
	switch (curr_nmr.nr_flags & NR_REG_MASK) {
	case NR_REG_DEFAULT:
		printf("obey ringid");
		break;
	case NR_REG_ALL_NIC:
		printf("ALL_NIC");
		break;
	case NR_REG_SW:
		printf("SW");
		break;
	case NR_REG_NIC_SW:
		printf("NIC_SW");
		break;
	case NR_REG_ONE_NIC:
		printf("ONE_NIC(%d)", ringid);
		break;
	case NR_REG_PIPE_MASTER:
		printf("PIPE_MASTER(%d)", ringid);
		break;
	case NR_REG_PIPE_SLAVE:
		printf("PIPE_SLAVE(%d)", ringid);
		break;
	default:
		printf("???");
		break;
	}
	if (curr_nmr.nr_flags & NR_MONITOR_TX) {
		printf(", MONITOR_TX");
	}
	if (curr_nmr.nr_flags & NR_MONITOR_RX) {
		printf(", MONITOR_RX");
	}
	if (curr_nmr.nr_flags & NR_ZCOPY_MON) {
		printf(", ZCOPY_MON");
	}
	if (curr_nmr.nr_flags & NR_EXCLUSIVE) {
		printf(", EXCLUSIVE");
	}
	printf("]\n");
	printf("spare2[0]: %x\n", curr_nmr.spare2[0]);
}

void
do_nmr_legacy_reset()
{
	bzero(&curr_nmr, sizeof(curr_nmr));
	curr_nmr.nr_version = NETMAP_API;
	curr_nmr.nr_flags   = NR_REG_ALL_NIC;
}

void
do_nmr_legacy_name()
{
	char *name = nextarg();
	if (name) {
		strncpy(curr_nmr.nr_name, name, IFNAMSIZ-1);
	}
	strncpy(nmr_name, curr_nmr.nr_name, IFNAMSIZ);
	nmr_name[IFNAMSIZ] = '\0';
	output("name=%s", nmr_name);
}

void
do_nmr_legacy_ringid()
{
	char *arg;
	uint16_t ringid = curr_nmr.nr_ringid;
	int n;
	for (n = 0, arg = nextarg(); arg; arg = nextarg(), n++) {
		if (strcmp(arg, "hw-ring") == 0) {
			ringid |= NETMAP_HW_RING;
		} else if (strcmp(arg, "sw-ring") == 0) {
			ringid |= NETMAP_SW_RING;
		} else if (strcmp(arg, "no-tx-poll") == 0) {
			ringid |= NETMAP_NO_TX_POLL;
		} else if (strcmp(arg, "default") == 0) {
			ringid = 0;
		} else {
			ringid &= ~NETMAP_RING_MASK;
			ringid |= (atoi(arg) & NETMAP_RING_MASK);
		}
	}
	if (n)
		curr_nmr.nr_ringid = ringid;
	output("ringid=%x", curr_nmr.nr_ringid);
}

void
do_nmr_legacy_cmd()
{
	char *arg = nextarg();
	if (arg == NULL)
		goto out;

	if (strcmp(arg, "bdg-attach") == 0) {
		curr_nmr.nr_cmd = NETMAP_BDG_ATTACH;
	} else if (strcmp(arg, "bdg-detach") == 0) {
		curr_nmr.nr_cmd = NETMAP_BDG_DETACH;
	} else if (strcmp(arg, "bdg-list") == 0) {
		curr_nmr.nr_cmd = NETMAP_BDG_LIST;
	} else if (strcmp(arg, "bdg-host") == 0) {
		curr_nmr.nr_cmd = NETMAP_BDG_HOST;
	} else if (strcmp(arg, "bdg-vnet-hdr") == 0) {
		curr_nmr.nr_cmd = NETMAP_BDG_VNET_HDR;
	} else if (strcmp(arg, "bdg-newif") == 0) {
		curr_nmr.nr_cmd = NETMAP_BDG_NEWIF;
	} else if (strcmp(arg, "bdg-delif") == 0) {
		curr_nmr.nr_cmd = NETMAP_BDG_DELIF;
	} else if (strcmp(arg, "bdg-polling-on") == 0) {
		curr_nmr.nr_cmd = NETMAP_BDG_POLLING_ON;
	} else if (strcmp(arg, "bdg-polling-off") == 0) {
		curr_nmr.nr_cmd = NETMAP_BDG_POLLING_OFF;
	} else if (strcmp(arg, "pt-host-create") == 0) {
		curr_nmr.nr_cmd = NETMAP_PT_HOST_CREATE;
	} else if (strcmp(arg, "pt-host-delete") == 0) {
		curr_nmr.nr_cmd = NETMAP_PT_HOST_DELETE;
	}
out:
	output("cmd=%x", curr_nmr.nr_cmd);
}

void
do_nmr_legacy_flags()
{
	char *arg;
	uint32_t flags = curr_nmr.nr_flags;
	int n;
	for (n = 0, arg = nextarg(); arg; arg = nextarg(), n++) {
		if (strcmp(arg, "all-nic") == 0) {
			flags &= ~NR_REG_MASK;
			flags |= NR_REG_ALL_NIC;
		} else if (strcmp(arg, "sw") == 0) {
			flags &= ~NR_REG_MASK;
			flags |= NR_REG_SW;
		} else if (strcmp(arg, "nic-sw") == 0) {
			flags &= ~NR_REG_MASK;
			flags |= NR_REG_NIC_SW;
		} else if (strcmp(arg, "one-nic") == 0) {
			flags &= ~NR_REG_MASK;
			flags |= NR_REG_ONE_NIC;
		} else if (strcmp(arg, "pipe-master") == 0) {
			flags &= ~NR_REG_MASK;
			flags |= NR_REG_PIPE_MASTER;
		} else if (strcmp(arg, "pipe-slave") == 0) {
			flags &= ~NR_REG_MASK;
			flags |= NR_REG_PIPE_SLAVE;
		} else if (strcmp(arg, "monitor-tx") == 0) {
			flags |= NR_MONITOR_TX;
		} else if (strcmp(arg, "monitor-rx") == 0) {
			flags |= NR_MONITOR_RX;
		} else if (strcmp(arg, "zcopy-mon") == 0) {
			flags |= NR_ZCOPY_MON;
		} else if (strcmp(arg, "exclusive") == 0) {
			flags |= NR_EXCLUSIVE;
		} else if (strcmp(arg, "default") == 0) {
			flags = 0;
		}
	}
	if (n)
		curr_nmr.nr_flags = flags;
	output("flags=%x", curr_nmr.nr_flags);
}

struct cmd_def nmr_legacy_commands[] = {
	{"dump", do_nmr_legacy_dump}, {"reset", do_nmr_legacy_reset},
	{"name", do_nmr_legacy_name}, {"ringid", do_nmr_legacy_ringid},
	{"cmd", do_nmr_legacy_cmd},   {"flags", do_nmr_legacy_flags},
};

const int N_NMR_LEGACY_CMDS =
	sizeof(nmr_legacy_commands) / sizeof(struct cmd_def);

int
find_nmr_legacy_command(const char *cmd)
{
	return _find_command(nmr_legacy_commands, N_NMR_LEGACY_CMDS, cmd);
}

#define __nmr_arg_update(nmr, f)                                               \
	({                                                                     \
		int __ret = 0;                                                 \
		if (strcmp(cmd, #f) == 0) {                                    \
			char *arg = nextarg();                                 \
			if (arg) {                                             \
				curr_##nmr.nr_##f = strtol(arg, NULL, 0);      \
			}                                                      \
			output(#f "=%llu",                                     \
			       (unsigned long long)curr_##nmr.nr_##f);         \
			__ret = 1;                                             \
		}                                                              \
		__ret;                                                         \
	})

#define nmr_arg_update(f) __nmr_arg_update(nmr, f)

/* prepare the curr_nmr */
void
do_nmr_legacy()
{
	char *cmd = nextarg();
	int i;

	if (cmd == NULL) {
		do_nmr_legacy_dump();
		return;
	}
	if (cmd[0] == '.') {
		cmd++;
	} else {
		i = find_nmr_legacy_command(cmd);
		if (i < N_NMR_LEGACY_CMDS) {
			nmr_legacy_commands[i].f();
			return;
		}
	}
	if (nmr_arg_update(version) || nmr_arg_update(offset) ||
	    nmr_arg_update(memsize) || nmr_arg_update(tx_slots) ||
	    nmr_arg_update(rx_slots) || nmr_arg_update(tx_rings) ||
	    nmr_arg_update(rx_rings) || nmr_arg_update(ringid) ||
	    nmr_arg_update(cmd) || nmr_arg_update(arg1) ||
	    nmr_arg_update(arg2) || nmr_arg_update(arg3) ||
	    nmr_arg_update(flags))
		return;
	output("unknown field: %s", cmd);
}

/****************************************************************
 * new API							*
 ****************************************************************/

static struct nmreq_header curr_hdr = {.nr_version = NETMAP_API};
static struct nmreq_register curr_register;
static struct nmreq_port_info_get curr_port_info_get;
static struct nmreq_vale_attach curr_vale_attach;
static struct nmreq_vale_list curr_vale_list;
static struct nmreq_port_hdr curr_port_hdr;
static struct nmreq_vale_newif curr_vale_newif;
static struct nmreq_vale_polling curr_vale_polling;

typedef void (*nmr_body_dump_fun)(void *);

static void
nmr_body_dump_register(void *b)
{
	struct nmreq_register *r = b;
	int flags		 = 0;
	printf("offset:         %" PRIu64 "\n", r->nr_offset);
	printf("memsize:        %" PRIu64 " [", r->nr_memsize);
	if (r->nr_memsize < (1 << 20)) {
		printf("%" PRIu64 " KiB", r->nr_memsize >> 10);
	} else {
		printf("%" PRIu64 " MiB", r->nr_memsize >> 20);
	}
	printf("]\n");
	printf("tx_slots:       %" PRIu16 "\n", r->nr_tx_slots);
	printf("rx_slots:       %" PRIu16 "\n", r->nr_rx_slots);
	printf("tx_rings:       %" PRIu16 "\n", r->nr_tx_rings);
	printf("rx_rings:       %" PRIu16 "\n", r->nr_rx_rings);
	printf("host_tx_rings:  %" PRIu16 "\n", r->nr_host_tx_rings);
	printf("host_rx_rings:  %" PRIu16 "\n", r->nr_host_rx_rings);
	printf("mem_id:         %" PRIu16 " [%s memory region]\n", r->nr_mem_id,
	       (r->nr_mem_id == 0 ? "default"
				  : r->nr_mem_id == 1 ? "global" : "private"));
	printf("ringid          %" PRIu16 "\n", r->nr_ringid);
	printf("mode            %" PRIu32 " [", r->nr_mode);
	switch (r->nr_mode) {
	case NR_REG_DEFAULT:
		printf("*DEFAULT");
		break;
	case NR_REG_ALL_NIC:
		printf("ALL_NIC");
		break;
	case NR_REG_SW:
		printf("SW");
		break;
	case NR_REG_NIC_SW:
		printf("NIC_SW");
		break;
	case NR_REG_ONE_NIC:
		printf("ONE_NIC(%" PRIu16 ")", r->nr_ringid);
		break;
	case NR_REG_PIPE_MASTER:
		printf("*PIPE_MASTER(%d)", r->nr_ringid);
		break;
	case NR_REG_PIPE_SLAVE:
		printf("*PIPE_SLAVE(%d)", r->nr_ringid);
		break;
	case NR_REG_NULL:
		printf("NULL");
		break;
	case NR_REG_ONE_SW:
		printf("ONE_SW(%d)", r->nr_ringid);
		break;
	default:
		printf("???");
		break;
	}
	printf("]\n");
	printf("flags:     %" PRIx64 " [", r->nr_flags);
#define pflag(f)                                                               \
	if (r->nr_flags & NR_##f) {                                            \
		printf("%s" #f, flags++ ? ", " : "");                          \
	}
	pflag(MONITOR_TX);
	pflag(MONITOR_RX);
	pflag(ZCOPY_MON);
	pflag(EXCLUSIVE);
	pflag(RX_RINGS_ONLY);
	pflag(TX_RINGS_ONLY);
	pflag(ACCEPT_VNET_HDR);
	pflag(DO_RX_POLL);
	pflag(NO_TX_POLL);
#undef pflag
	printf("]\n");
	printf("extra_bufs %" PRIu32 "\n", r->nr_extra_bufs);
}

static void
do_register_dump()
{
	nmr_body_dump_register(&curr_register);
}

static void
do_register_reset()
{
	memset(&curr_register, 0, sizeof(curr_register));
}

static void
do_register_mode()
{
	char *mode = nextarg();

	if (mode == NULL)
		goto out;

	if (strcmp(mode, "default") == 0) {
		curr_register.nr_mode = NR_REG_DEFAULT;
	} else if (strcmp(mode, "all-nic") == 0) {
		curr_register.nr_mode = NR_REG_ALL_NIC;
	} else if (strcmp(mode, "sw") == 0) {
		curr_register.nr_mode = NR_REG_SW;
	} else if (strcmp(mode, "nic-sw") == 0) {
		curr_register.nr_mode = NR_REG_NIC_SW;
	} else if (strcmp(mode, "one-nic") == 0) {
		curr_register.nr_mode = NR_REG_ONE_NIC;
	} else if (strcmp(mode, "pipe-master") == 0) {
		curr_register.nr_mode = NR_REG_PIPE_MASTER;
	} else if (strcmp(mode, "pipe-slave") == 0) {
		curr_register.nr_mode = NR_REG_PIPE_SLAVE;
	} else if (strcmp(mode, "null") == 0) {
		curr_register.nr_mode = NR_REG_NULL;
	} else if (strcmp(mode, "one-sw") == 0) {
		curr_register.nr_mode = NR_REG_ONE_SW;
	}

out:
	output("mode=%" PRIu32, curr_register.nr_mode);
}

void
do_register_flags()
{
	char *arg;
	uint64_t flags = curr_register.nr_flags;
	int n;
	for (n = 0, arg = nextarg(); arg; arg = nextarg(), n++) {
		if (strcmp(arg, "monitor-tx") == 0) {
			flags |= NR_MONITOR_TX;
		} else if (strcmp(arg, "monitor-rx") == 0) {
			flags |= NR_MONITOR_RX;
		} else if (strcmp(arg, "zcopy-mon") == 0) {
			flags |= NR_ZCOPY_MON;
		} else if (strcmp(arg, "exclusive") == 0) {
			flags |= NR_EXCLUSIVE;
		} else if (strcmp(arg, "rx-rings-only") == 0) {
			flags |= NR_RX_RINGS_ONLY;
		} else if (strcmp(arg, "tx-rings-only") == 0) {
			flags |= NR_TX_RINGS_ONLY;
		} else if (strcmp(arg, "accept-vnet-hdr") == 0) {
			flags |= NR_ACCEPT_VNET_HDR;
		} else if (strcmp(arg, "do-rx-poll") == 0) {
			flags |= NR_DO_RX_POLL;
		} else if (strcmp(arg, "no-tx-poll") == 0) {
			flags |= NR_NO_TX_POLL;
		} else if (strcmp(arg, "reset") == 0) {
			flags = 0;
		}
	}
	if (n)
		curr_register.nr_flags = flags;
	output("flags=%" PRIx64, curr_register.nr_flags);
}

struct cmd_def register_commands[] = {
	{"dump", do_register_dump},
	{"reset", do_register_reset},
	{"mode", do_register_mode},
	{"flags", do_register_flags},
};

const int N_REGISTER_CMDS = sizeof(register_commands) / sizeof(struct cmd_def);

int
find_register_command(const char *cmd)
{
	return _find_command(register_commands, N_REGISTER_CMDS, cmd);
}

#define register_update(f) __nmr_arg_update(register, f)

void
do_register()
{
	char *cmd = nextarg();
	int i;

	if (cmd == NULL) {
		do_register_dump();
		return;
	}
	if (cmd[0] == '.') {
		cmd++;
	} else {
		i = find_register_command(cmd);
		if (i < N_REGISTER_CMDS) {
			register_commands[i].f();
			return;
		}
	}
	if (register_update(offset) || register_update(memsize) ||
	    register_update(tx_slots) || register_update(rx_slots) ||
	    register_update(tx_rings) || register_update(rx_rings) ||
	    register_update(host_tx_rings) || register_update(host_rx_rings) ||
	    register_update(mem_id) || register_update(ringid) ||
	    register_update(mode) || register_update(flags) ||
	    register_update(extra_bufs))
		return;
	output("unknown field: %s", cmd);
}

static void
nmr_body_dump_port_info_get(void *b)
{
	struct nmreq_port_info_get *r = b;
	int i;

	printf("memsize:        %" PRIu64 " [", r->nr_memsize);
	if (r->nr_memsize < (1 << 20)) {
		printf("%" PRIu64 " KiB", r->nr_memsize >> 10);
	} else {
		printf("%" PRIu64 " MiB", r->nr_memsize >> 20);
	}
	printf("]\n");
	printf("tx_slots:       %" PRIu16 "\n", r->nr_tx_slots);
	printf("rx_slots:       %" PRIu16 "\n", r->nr_rx_slots);
	printf("tx_rings:       %" PRIu16 "\n", r->nr_tx_rings);
	printf("rx_rings:       %" PRIu16 "\n", r->nr_rx_rings);
	printf("host_tx_rings:  %" PRIu16 "\n", r->nr_host_tx_rings);
	printf("host_rx_rings:  %" PRIu16 "\n", r->nr_host_rx_rings);
	printf("mem_id:         %" PRIu16 " [%s memory region]\n", r->nr_mem_id,
	       (r->nr_mem_id == 0 ? "default"
				  : r->nr_mem_id == 1 ? "global" : "private"));
	for (i = 0; i < 3; i++)
		printf("pad[%d]         %" PRIu16 "\n", i, r->pad[i]);
}

static void
nmr_body_dump_vale_attach(void *b)
{
	(void)b;
}

static void
nmr_body_dump_vale_list(void *b)
{
	(void)b;
}

static void
nmr_body_dump_port_hdr(void *b)
{
	(void)b;
}

static void
nmr_body_dump_vale_newif(void *b)
{
	(void)b;
}

static void
nmr_body_dump_vale_polling(void *b)
{
	(void)b;
}

static void
nmr_body_dump_pools_info_get(void *b)
{
	(void)b;
}

typedef void (*nmr_option_dump_fun)(struct nmreq_option *);

static void
nmr_option_dump_extmem(struct nmreq_option *opt)
{
	struct nmreq_opt_extmem *e = (struct nmreq_opt_extmem *)opt;

	printf("usrptr: %p\n", (void *)(uintptr_t)e->nro_usrptr);
	printf("info:\n");
	pools_info_dump(4, &e->nro_info);
}

static void
nmr_option_dump(struct nmreq_option *opt)
{
	nmr_option_dump_fun d = NULL;

	printf("next: %p\n", (void *)(uintptr_t)opt->nro_next);
	printf("type: %" PRIu32 " [", opt->nro_reqtype);
	switch (opt->nro_reqtype) {
	case NETMAP_REQ_OPT_EXTMEM:
		printf("extmem");
		d = nmr_option_dump_extmem;
		break;
	default:
#ifdef NETMAP_OPT_DEBUG
		if (opt->nro_reqtype & NETMAP_REQ_OPT_DEBUG) {
			printf("debug: %u",
			       (opt->nro_reqtype & ~NETMAP_REQ_OPT_DEBUG));
			break;
		}
#endif /* NETMAP_OPT_DEBUG */
		printf("???");
	}
	printf("]\n");
	printf("status: %" PRIu32 " [%s]\n", opt->nro_status,
	       strerror(opt->nro_status));
	if (d)
		d(opt);
}

static void
do_hdr_dump()
{
	struct nmreq_option *opt;
	nmr_body_dump_fun body_dump = NULL;

	snprintf(nmr_name, NETMAP_REQ_IFNAMSIZ + 1, "%s", curr_hdr.nr_name);
	nmr_name[NETMAP_REQ_IFNAMSIZ] = '\0';
	printf("version:   %d\n", curr_hdr.nr_version);
	printf("reqtype:   %d [", curr_hdr.nr_reqtype);
	switch (curr_hdr.nr_reqtype) {
	case NETMAP_REQ_REGISTER:
		printf("register");
		body_dump = nmr_body_dump_register;
		break;
	case NETMAP_REQ_PORT_INFO_GET:
		printf("info-get");
		body_dump = nmr_body_dump_port_info_get;
		break;
	case NETMAP_REQ_VALE_ATTACH:
		printf("vale-attach");
		body_dump = nmr_body_dump_vale_attach;
		break;
	case NETMAP_REQ_VALE_DETACH:
		printf("vale-detach");
		break;
	case NETMAP_REQ_VALE_LIST:
		printf("vale-list");
		body_dump = nmr_body_dump_vale_list;
		break;
	case NETMAP_REQ_PORT_HDR_SET:
		printf("port-hdr-set");
		body_dump = nmr_body_dump_port_hdr;
		break;
	case NETMAP_REQ_PORT_HDR_GET:
		printf("port-hdr-get");
		body_dump = nmr_body_dump_port_hdr;
		break;
	case NETMAP_REQ_VALE_NEWIF:
		printf("vale-newif");
		body_dump = nmr_body_dump_vale_newif;
		break;
	case NETMAP_REQ_VALE_DELIF:
		printf("vale-delif");
		break;
	case NETMAP_REQ_VALE_POLLING_ENABLE:
		printf("vale-polliing-enable");
		body_dump = nmr_body_dump_vale_polling;
		break;
	case NETMAP_REQ_VALE_POLLING_DISABLE:
		printf("vale-polling-disable");
		body_dump = nmr_body_dump_vale_polling;
		break;
	case NETMAP_REQ_POOLS_INFO_GET:
		printf("pools-info-get");
		body_dump = nmr_body_dump_pools_info_get;
		break;
	default:
		printf("???");
		break;
	}
	printf("]\n");
	printf("name: %s\n", nmr_name);
	opt = (struct nmreq_option *)(uintptr_t)curr_hdr.nr_options;
	printf("options:   %p\n", opt);
	while (opt) {
		nmr_option_dump(opt);
		opt = (struct nmreq_option *)(uintptr_t)opt->nro_next;
	}
	printf("body:	   %p\n", (void *)(uintptr_t)curr_hdr.nr_body);
	if (body_dump)
		body_dump((void *)(uintptr_t)curr_hdr.nr_body);
}

static void
do_hdr_reset()
{
	struct nmreq_option *opt = (struct nmreq_option *)(uintptr_t)curr_hdr.nr_options;
	while (opt) {
		struct nmreq_option *next =
			(struct nmreq_option *)(uintptr_t)opt->nro_next;
		free(opt);
		opt = next;
	}
	memset(&curr_hdr, 0, sizeof(curr_hdr));
	curr_hdr.nr_version = NETMAP_API;
}

void
do_hdr_name()
{
	char *name = nextarg();
	if (name) {
		strncpy(curr_hdr.nr_name, name, NETMAP_REQ_IFNAMSIZ-1);
	}
	strncpy(nmr_name, curr_hdr.nr_name, NETMAP_REQ_IFNAMSIZ);
	nmr_name[NETMAP_REQ_IFNAMSIZ] = '\0';
	output("name=%s", nmr_name);
}

static void
do_hdr_type()
{
	char *type = nextarg();

	if (strcmp(type, "register") == 0) {
		curr_hdr.nr_reqtype = NETMAP_REQ_REGISTER;
		curr_hdr.nr_body    = (uintptr_t)&curr_register;
	} else if (strcmp(type, "info-get") == 0) {
		curr_hdr.nr_reqtype = NETMAP_REQ_PORT_INFO_GET;
		curr_hdr.nr_body    = (uintptr_t)&curr_port_info_get;
	} else if (strcmp(type, "vale-attach") == 0) {
		curr_hdr.nr_reqtype = NETMAP_REQ_VALE_ATTACH;
		curr_hdr.nr_body    = (uintptr_t)&curr_vale_attach;
	} else if (strcmp(type, "vale-detach") == 0) {
		curr_hdr.nr_reqtype = NETMAP_REQ_VALE_DETACH;
	} else if (strcmp(type, "vale-list") == 0) {
		curr_hdr.nr_reqtype = NETMAP_REQ_VALE_LIST;
		curr_hdr.nr_body    = (uintptr_t)&curr_vale_list;
	} else if (strcmp(type, "port-hdr-set") == 0) {
		curr_hdr.nr_reqtype = NETMAP_REQ_PORT_HDR_SET;
		curr_hdr.nr_body    = (uintptr_t)&curr_port_hdr;
	} else if (strcmp(type, "port-hdr-get") == 0) {
		curr_hdr.nr_reqtype = NETMAP_REQ_PORT_HDR_GET;
		curr_hdr.nr_body    = (uintptr_t)&curr_port_hdr;
	} else if (strcmp(type, "vale-newif") == 0) {
		curr_hdr.nr_reqtype = NETMAP_REQ_VALE_NEWIF;
		curr_hdr.nr_body    = (uintptr_t)&curr_vale_newif;
	} else if (strcmp(type, "vale-delif") == 0) {
		curr_hdr.nr_reqtype = NETMAP_REQ_VALE_DELIF;
	} else if (strcmp(type, "vale-polliing-enable") == 0) {
		curr_hdr.nr_reqtype = NETMAP_REQ_VALE_POLLING_ENABLE;
		curr_hdr.nr_body    = (uintptr_t)&curr_vale_polling;
	} else if (strcmp(type, "vale-polling-disable") == 0) {
		curr_hdr.nr_reqtype = NETMAP_REQ_VALE_POLLING_DISABLE;
		curr_hdr.nr_body    = (uintptr_t)&curr_vale_polling;
	} else if (strcmp(type, "pools-info-get") == 0) {
		curr_hdr.nr_reqtype = NETMAP_REQ_POOLS_INFO_GET;
		curr_hdr.nr_body    = (uintptr_t)&curr_pools_info;
	} else {
		output("unknown type: %s", type);
	}
	output("type=%u", curr_hdr.nr_reqtype);
}

typedef void (*nmreq_opt_init)(struct nmreq_option *);

static void
nmreq_opt_extmem_init(struct nmreq_option *opt)
{
	struct nmreq_opt_extmem *e = (struct nmreq_opt_extmem *)opt;
	e->nro_usrptr		   = (uintptr_t)last_mmap_addr;
	e->nro_info.nr_memsize     = last_memsize;
}

static void
do_hdr_option()
{
	char *type;
	struct nmreq_option **ptr = (struct nmreq_option **)&curr_hdr
					    .nr_options,
			    *old = *ptr;
	size_t sz		 = sizeof(struct nmreq_option);
	nmreq_opt_init init      = NULL;

	while ((type = nextarg())) {
		uint16_t reqtype = 0;

		if (strcmp(type, "extmem") == 0) {
			reqtype = NETMAP_REQ_OPT_EXTMEM;
			sz      = sizeof(struct nmreq_opt_extmem);
			init    = nmreq_opt_extmem_init;
#ifdef NETMAP_OPT_DEBUG
		} else {
			reqtype = strtol(type, NULL, 0) | NETMAP_REQ_OPT_DEBUG;
#endif /* NETMAP_OPT_DEBUG */
		}
		*ptr = malloc(sz);
		if (*ptr == NULL) {
			output_err(-1, "malloc");
		}
		memset(*ptr, 0, sz);
		(*ptr)->nro_reqtype = reqtype;
		if (init)
			init(*ptr);
		ptr = (struct nmreq_option **)&(*ptr)->nro_next;
	}
	*ptr = old;
}

struct cmd_def hdr_commands[] = {
	{"dump", do_hdr_dump}, {"reset", do_hdr_reset},   {"name", do_hdr_name},
	{"type", do_hdr_type}, {"option", do_hdr_option},
};

const int N_HDR_CMDS = sizeof(hdr_commands) / sizeof(struct cmd_def);

int
find_hdr_command(const char *cmd)
{
	return _find_command(hdr_commands, N_HDR_CMDS, cmd);
}

static void
do_hdr()
{
	char *cmd = nextarg();
	int i;

	if (cmd == NULL) {
		do_hdr_dump();
		return;
	}
	i = find_hdr_command(cmd);
	if (i < N_HDR_CMDS) {
		hdr_commands[i].f();
		return;
	}
	output("unknown command: %s", cmd);
}

static void
do_ctrl()
{
	char *arg;
	int fd, ret;

	arg = nextarg();
	if (!arg) {
		fd = last_fd;
		goto doit;
	}
	last_fd = fd = atoi(arg);
doit:
	ret = ioctl(fd, NIOCCTRL, &curr_hdr);
	switch (curr_hdr.nr_reqtype) {
	case NETMAP_REQ_REGISTER:
		last_memsize = curr_register.nr_memsize;
		break;
	case NETMAP_REQ_PORT_INFO_GET:
		last_memsize = curr_port_info_get.nr_memsize;
		break;
	default:
		break;
	}
	output_err(ret, "ioctl(%d, NIOCCTL, %p)=%d", fd, &curr_hdr, ret);
}

struct cmd_def commands[] = {{
				     "open",
				     do_open,
			     },
			     {
				     "close",
				     do_close,
			     },
#ifdef TEST_NETMAP
			     {
				     "getinfo-legacy",
				     do_getinfo_legacy,
			     },
			     {
				     "regif-legacy",
				     do_regif_legacy,
			     },
			     {
				     "txsync",
				     do_txsync,
			     },
			     {
				     "rxsync",
				     do_rxsync,
			     },
#endif /* TEST_NETMAP */
			     {
				     "dup",
				     do_dup,
			     },
			     {
				     "mmap",
				     do_mmap,
			     },
			     {
				     "anon-mmap",
				     do_anon_mmap,
			     },
			     {
				     "rd",
				     do_rd,
			     },
			     {
				     "wr",
				     do_wr,
			     },
			     {
				     "munmap",
				     do_munmap,
			     },
			     {
				     "poll",
				     do_poll,
			     },
			     {
				     "expr",
				     do_expr,
			     },
			     {
				     "echo",
				     do_echo,
			     },
			     {
				     "vars",
				     do_vars,
			     },
			     {
				     "if",
				     do_if,
			     },
			     {
				     "ring",
				     do_ring,
			     },
			     {
				     "slot",
				     do_slot,
			     },
			     {
				     "buf",
				     do_buf,
			     },
			     {
				     "nmr-legacy",
				     do_nmr_legacy,
			     },
			     {
				     "hdr",
				     do_hdr,
			     },
			     {"ctrl", do_ctrl},
			     {"register", do_register}};

const int N_CMDS = sizeof(commands) / sizeof(struct cmd_def);

int
find_command(const char *cmd)
{
	return _find_command(commands, N_CMDS, cmd);
}

#define MAX_CHAN 10

void
prompt(FILE *f)
{
	if (isatty(fileno(f))) {
		printf("> ");
	}
}

struct chan *channels[MAX_CHAN];

void *
thread_cmd_loop(void *arg)
{
	char buf[1024];
	FILE *in = (FILE *)arg;

	while (fgets(buf, 1024, in)) {
		char *cmd;
		int i;

		cmd = firstarg(buf);
		i   = find_command(cmd);
		if (i < N_CMDS) {
			commands[i].f();
			continue;
		}
		output("unknown cmd %s", cmd);
	}
	fclose(in);
	return NULL;
}

void
do_exit()
{
	output("quit");
}

void
cmd_loop(FILE *input)
{
	char buf[1024];
	int i;
	struct chan *c;

	bzero(channels, sizeof(*channels) * MAX_CHAN);

	atexit(do_exit);

	for (prompt(input); fgets(buf, 1024, input); prompt(input)) {
		char *cmd;
		int slot;

		cmd = firstarg(buf);
		if (!cmd)
			continue;
		if (cmd[0] == '@') {
			curr_var = atoi(cmd + 1);
			if (curr_var < 0 || curr_var >= MAX_VARS)
				curr_var = 0;
			cmd = nextarg();
			if (!cmd)
				continue;
		} else {
			curr_var = 0;
		}

		if (strcmp(cmd, "fork") == 0) {
			int slot       = chan_search_free(channels, MAX_CHAN);
			struct chan *c = NULL;
			pid_t pid;
			int p1[2] = {-1, -1};

			if (slot == MAX_CHAN) {
				output("too many channels");
				continue;
			}
			c = channels[slot] =
				(struct chan *)malloc(sizeof(struct chan));
			if (c == NULL) {
				output_err(-1, "malloc");
				continue;
			}
			bzero(c, sizeof(*c));
			if (pipe(p1) < 0) {
				output_err(-1, "pipe");
				goto clean1;
			}
			c->out = fdopen(p1[1], "w");
			if (c->out == NULL) {
				output_err(-1, "fdopen");
				goto clean1;
			}
			pid = fork();
			switch (pid) {
			case -1:
				output_err(-1, "fork");
				goto clean1;
			case 0:
				close(p1[1]);
				input = fdopen(p1[0], "r");
				chan_clear_all(channels, MAX_CHAN);
				goto out;
			default:
				break;
			}
			c->pid = pid;
			close(p1[0]);
			output("fork()=%d slot=%d", pid, slot);
			continue;
		clean1:
			if (c) {
				fclose(c->out);
			}
			close(p1[0]);
			close(p1[1]);
			free(c);
		out:
			continue;
		}
		if (strcmp(cmd, "kill") == 0) {
			int ret;

			cmd = nextarg();
			if (!cmd) {
				output("missing slot");
				continue;
			}
			slot = atoi(cmd);
			if (slot < 0 || slot >= MAX_CHAN || !channels[slot]) {
				output("invalid slot: %s", cmd);
				continue;
			}
			c   = channels[slot];
			ret = kill(c->pid, SIGTERM);
			output_err(ret, "kill(%d, SIGTERM)=%d", c->pid, ret);
			if (ret != -1) {
				wait(NULL);
				fclose(c->out);
				free(c);
				channels[slot] = NULL;
			}
			continue;
		}
		if (strcmp(cmd, "thread") == 0) {
			int slot       = chan_search_free(channels, MAX_CHAN);
			struct chan *c = NULL;
			pthread_t tid;
			int p1[2] = {-1, -1};
			int ret;
			FILE *in = NULL;

			if (slot == MAX_CHAN) {
				output("too many channels");
				continue;
			}
			c = channels[slot] =
				(struct chan *)malloc(sizeof(struct chan));
			bzero(c, sizeof(*c));
			if (pipe(p1) < 0) {
				output_err(-1, "pipe");
				goto clean2;
			}
			c->out = fdopen(p1[1], "w");
			if (c->out == NULL) {
				output_err(-1, "fdopen");
				goto clean2;
			}
			in = fdopen(p1[0], "r");
			if (in == NULL) {
				output_err(-1, "fdopen");
				goto clean2;
			}
			ret = pthread_create(&tid, NULL, thread_cmd_loop, in);
			output_err(ret, "pthread_create() tid=%lu slot=%d",
				   (unsigned long)tid, slot);
			if (ret < 0)
				goto clean2;
			c->pid = getpid();
			c->tid = tid;
			continue;
		clean2:
			fclose(in);
			fclose(c->out);
			close(p1[0]);
			close(p1[1]);
			free(c);
			continue;
		}
		if (strcmp(cmd, "cancel") == 0) {
			int ret;

			cmd = nextarg();
			if (!cmd) {
				output("missing slot");
				continue;
			}
			slot = atoi(cmd);
			if (slot < 0 || slot >= MAX_CHAN || !channels[slot]) {
				output("invalid slot: %s", cmd);
				continue;
			}
			c = channels[slot];
			fclose(c->out);
			ret = pthread_join(c->tid, NULL);
			output_err(ret, "pthread_join(%lu)=%d",
				   (unsigned long)c->tid, ret);
			if (ret > 0) {
				free(c);
				channels[slot] = NULL;
			}
			continue;
		}
		if (strcmp(cmd, "next") == 0) {
			return;
		}
		i = find_command(cmd);
		if (i < N_CMDS) {
			commands[i].f();
			continue;
		}
		slot = atoi(cmd);
		if (slot < 0 || slot > MAX_CHAN || !channels[slot]) {
			output("invalid cmd/slot: %s", cmd);
			continue;
		}
		cmd = restofline();
		if (!cmd) {
			output("missing command");
			continue;
		}
		fprintf(channels[slot]->out, "%s\n", cmd);
		fflush(channels[slot]->out);
		sleep(1);
	}
}

int
main(int argc, char **argv)
{
	int i;
	if (argc > 1) {
		for (i = 1; i < argc; i++) {
			FILE *f;
			if (!strcmp(argv[i], "-")) {
				f = stdin;
			} else {
				f = fopen(argv[i], "r");
				if (f == NULL) {
					perror(argv[i]);
					continue;
				}
			}
			cmd_loop(f);
			if (f != stdin)
				fclose(f);
		}
	} else {
		cmd_loop(stdin);
	}
	return 0;
}
