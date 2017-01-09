#define TEST_NETMAP

#include <inttypes.h>
#include <sys/param.h>	/* ULONG_MAX */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/poll.h>
#include <sys/wait.h>
#include <sys/mman.h>	/* PROT_* */
#include <fcntl.h>	/* O_RDWR */
#include <pthread.h>
#include <signal.h>
#include <ctype.h>


#define MAX_VARS 100

char *variables[MAX_VARS];
int curr_var;

#define VAR_FAILED ((void*)1)

char *firstarg(char *buf)
{
	int v;
	char *arg = strtok(buf, " \t\n");
	char *ret;
	if (!arg)
		return NULL;
	if (arg[0] != '$' && arg[0] != '?')
		return arg;
	v = atoi(arg+1);
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

char *nextarg()
{
	return firstarg(NULL);
}

char *restofline()
{
	return strtok(NULL, "\n");
}

void resetvar(int v, char *b)
{
	if (variables[v] != VAR_FAILED)
		free(variables[v]);
	variables[v] = b;
}

#define outecho(format, args...) \
	do {\
		printf("%u:%lu: " format "\n", getpid(), (unsigned long) pthread_self(), ##args);\
		fflush(stdout);\
	} while (0)

#define output(format, args...) \
	do {\
		resetvar(curr_var, (char*)malloc(1024));\
		snprintf(variables[curr_var], 1024, format, ##args);\
		outecho(format, ##args);\
	} while (0)

#define output_err(ret, format, args...)\
	do {\
		if (ret < 0) {\
			resetvar(curr_var, VAR_FAILED);\
			outecho(format, ##args);\
			outecho("error: %s", strerror(errno));\
		} else {\
			output(format, ##args);\
		}\
	} while (0)

struct chan {
	FILE *out;
	pid_t pid;
	pthread_t tid;
};

int chan_search_free(struct chan* c[], int max)
{
	int i;

	for (i = 0; i < max && c[i]; i++)
		;

	return i;
}

void chan_clear_all(struct chan *c[], int max)
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

int last_fd = -1;
size_t last_memsize = 0;
void* last_mmap_addr = NULL;
char* last_access_addr = NULL;


void do_open()
{
	last_fd = open("/dev/netmap", O_RDWR);
	output_err(last_fd, "open(\"/dev/netmap\", O_RDWR)=%d", last_fd);
}

void do_close()
{
	int ret, fd;
	char *arg = nextarg();
	fd = arg ? atoi(arg) : last_fd;
	ret = close(fd);
	output_err(ret, "close(%d)=%d", fd, ret);
}

#ifdef TEST_NETMAP
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <ifaddrs.h>
#include <net/netmap_user.h>

struct nmreq curr_nmr = { .nr_version = NETMAP_API, .nr_flags = NR_REG_ALL_NIC, };
char nmr_name[64];

void parse_nmr_config(char* w, struct nmreq *nmr)
{
	char *tok;
	int i, v;

	nmr->nr_tx_rings = nmr->nr_rx_rings = 0;
	nmr->nr_tx_slots = nmr->nr_rx_slots = 0;
	if (w == NULL || ! *w)
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

void do_getinfo()
{
	int ret;
	char *arg, *name;
	int fd;

	bzero(&curr_nmr, sizeof(curr_nmr));
	curr_nmr.nr_version = NETMAP_API;

	name = nextarg();
	if (name) {
		strncpy(curr_nmr.nr_name, name, sizeof(curr_nmr.nr_name));
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
	ret = ioctl(fd, NIOCGINFO, &curr_nmr);
	last_memsize = curr_nmr.nr_memsize;
	output_err(ret, "ioctl(%d, NIOCGINFO) for %s: region %d memsize=%zu",
		fd, name, curr_nmr.nr_arg2, last_memsize);
}


void do_regif()
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
	curr_nmr.nr_flags = NR_REG_ALL_NIC;
	strncpy(curr_nmr.nr_name, name, sizeof(curr_nmr.nr_name));

	arg = nextarg();
	if (!arg) {
		goto doit;
	}
	fd = atoi(arg);

	arg = nextarg();
	parse_nmr_config(arg, &curr_nmr);

doit:
	ret = ioctl(fd, NIOCREGIF, &curr_nmr);
	last_memsize = curr_nmr.nr_memsize;
	output_err(ret, "ioctl(%d, NIOCREGIF) for %s: region %d memsize=%zu",
		fd, name, curr_nmr.nr_arg2, last_memsize);
}

void
do_txsync()
{
	char *arg = nextarg();
	int fd = arg ? atoi(arg) : last_fd;
	int ret = ioctl(fd, NIOCTXSYNC, NULL);
	output_err(ret, "ioctl(%d, NIOCTXSYNC)=%d", fd, ret);
}

void
do_rxsync()
{
	char *arg = nextarg();
	int fd = arg ? atoi(arg) : last_fd;
	int ret = ioctl(fd, NIOCRXSYNC, NULL);
	output_err(ret, "ioctl(%d, NIOCRXSYNC)=%d", fd, ret);
}
#endif /* TEST_NETMAP */


volatile char tmp1;
void do_access()
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
	tmp1 = *p;
}

void do_dup()
{
	char *arg = nextarg();
	int fd = last_fd;
	int ret;

	if (arg) {
		fd = atoi(arg);
	}
	ret = dup(fd);
	output_err(ret, "dup(%d)=%d", fd, ret);

}

void do_mmap()
{
	size_t memsize;
	off_t off = 0;
	int fd;
	char *arg;

	arg = nextarg();
	if (!arg) {
		memsize = last_memsize;
		fd = last_fd;
		goto doit;
	}
	memsize = atoi(arg);
	arg = nextarg();
	if (!arg) {
		fd = last_fd;
		goto doit;
	}
	fd = atoi(arg);
	arg = nextarg();
	if (arg) {
		off = (off_t)atol(arg);
	}
doit:
	last_mmap_addr = mmap(0, memsize,
			PROT_WRITE | PROT_READ,
			MAP_SHARED, fd, off);
	if (last_access_addr == NULL)
		last_access_addr = last_mmap_addr;
	output_err(last_mmap_addr == MAP_FAILED ? -1 : 0,
		"mmap(0, %zu, PROT_WRITE|PROT_READ, MAP_SHARED, %d, %jd)=%p",
		memsize, fd, (intmax_t)off, last_mmap_addr);

}

void do_munmap()
{
	void *mmap_addr;
	size_t memsize;
	char *arg;
	int ret;

	arg = nextarg();
	if (!arg) {
		mmap_addr = last_mmap_addr;
		memsize = last_memsize;
		goto doit;
	}
	mmap_addr = (void*)strtoul(arg, NULL, 0);
	arg = nextarg();
	if (!arg) {
		memsize = last_memsize;
		goto doit;
	}
	memsize = (size_t)strtoul(arg, NULL, 0);
doit:
	ret = munmap(mmap_addr, memsize);
	output_err(ret, "munmap(%p, %zu)=%d", mmap_addr, memsize, ret);
}

void do_poll()
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
	while ( (arg = nextarg()) ) {
		if (nfds >= allocated_fds) {
			struct pollfd *new_fds;
			allocated_fds *= 2;
			new_fds = realloc(fds, allocated_fds * sizeof(struct pollfd));
			if (new_fds == NULL) {
				free(fds);
				output_err(-1, "out of memory");
				return;
			}
			fds = new_fds;
		}
		fds[nfds].fd = atoi(arg);
		fds[nfds].events = POLLIN;
		nfds++;
	}
	ret = poll(fds, nfds, timeout);
	for (i = 0; i < nfds; i++) {
		output("poll(%d)=%s%s%s%s%s", fds[i].fd,
			(fds[i].revents & POLLIN) ? "IN  " : "-   ",
			(fds[i].revents & POLLOUT)? "OUT " : "-   ",
			(fds[i].revents & POLLERR)? "ERR " : "-   ",
			(fds[i].revents & POLLHUP)? "HUP " : "-   ",
			(fds[i].revents & POLLNVAL)?"NVAL" : "-");

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
	while ( (arg = nextarg()) ) {
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
			unsigned long r = 0;
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
					err = -1;
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
		printf("?%d\t%s\n", i, v == VAR_FAILED ?  "FAILED" : v);
	}
}

struct netmap_if *
get_if()
{
	void *mmap_addr;
	uint32_t off;
	char *arg;

	/* defaults */
	off = curr_nmr.nr_offset;
	mmap_addr = last_mmap_addr;

	/* first arg: if offset */
	arg = nextarg();
	if (!arg) {
		goto doit;
	}
	off = strtoul(arg, NULL, 0);
	/* second arg: mmap address */
	arg = nextarg();
	if (!arg) {
		goto doit;
	}
	mmap_addr = (void*)strtoul(arg, NULL, 0);
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
	printf("tx_rings   %u\n", nifp->ni_tx_rings);
	printf("rx_rings   %u\n", nifp->ni_rx_rings);
	printf("bufs_head  %u\n", nifp->ni_bufs_head);
	for (i = 0; i < 5; i++)
		printf("spare1[%d]  %u\n", i, nifp->ni_spare1[i]);
	for (i = 0; i < (nifp->ni_tx_rings + nifp->ni_rx_rings + 2); i++)
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
do_ring()
{
	struct netmap_ring *ring;

	ring = get_ring();

	printf("buf_ofs     %"PRId64"\n", ring->buf_ofs);
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
	printf("cur         %u\n", ring->head);
	printf("tail        %u\n", ring->head);
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
	printf("ts          %ld:%ld\n",
			(long int)ring->ts.tv_sec, (long int)ring->ts.tv_usec);
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
		printf(" ]");
	}
	printf("\n");
	printf("ptr           %lx\n", (long)slot->ptr);
}

static void
dump_payload(char *p, int len)
{
	char buf[128];
	int i, j, i0;

	/* hexdump routine */
	for (i = 0; i < len; ) {
		memset(buf, sizeof(buf), ' ');
		sprintf(buf, "%5d: ", i);
		i0 = i;
		for (j=0; j < 16 && i < len; i++, j++)
			sprintf(buf+7+j*3, "%02x ", (uint8_t)(p[i]));
		i = i0;
		for (j=0; j < 16 && i < len; i++, j++)
			sprintf(buf+7+j + 48, "%c",
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
	len = 64;

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
	buf = NETMAP_BUF(ring, buf_idx);
	dump_payload(buf, len);
}

struct cmd_def {
	const char *name;
	void (*f)(void);
};

int _find_command(const struct cmd_def *cmds, int ncmds, const char* cmd)
{
	int i;
	for (i = 0; i < ncmds; i++) {
		if (strcmp(cmds[i].name, cmd) == 0)
			break;
	}
	return i;
}

typedef void (*nmr_arg_interp_fun)();

#define nmr_arg_unexpected(n) \
	printf("arg%d:      %d%s\n", n, curr_nmr.nr_arg ## n, \
		(curr_nmr.nr_arg ## n ? "???" : ""))

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
	printf("arg1:      %d [%sextra rings]\n", curr_nmr.nr_arg1,
		(curr_nmr.nr_arg1 ? "" : "no "));
	printf("arg2:      %d [%s memory allocator]\n", curr_nmr.nr_arg2,
		(curr_nmr.nr_arg2 == 0 ? "default" :
		 curr_nmr.nr_arg2 == 1 ? "global"  : "private"));
	printf("arg3:      %d [%sextra buffers]\n", curr_nmr.nr_arg3,
		(curr_nmr.nr_arg3 ? "" : "no "));
}

void
do_nmr_dump()
{
	u_int ringid = curr_nmr.nr_ringid & NETMAP_RING_MASK;
	nmr_arg_interp_fun arg_interp;

	snprintf(nmr_name, IFNAMSIZ + 1, "%s", curr_nmr.nr_name);
	nmr_name[IFNAMSIZ] = '\0';
	printf("name:      %s\n", nmr_name);
	printf("version:   %d\n", curr_nmr.nr_version);
	printf("offset:    %d\n", curr_nmr.nr_offset);
	printf("memsize:   %d [", curr_nmr.nr_memsize);
	if (curr_nmr.nr_memsize < (1<<20)) {
		printf("%d KiB", curr_nmr.nr_memsize >> 10);
	} else {
		printf("%d MiB", curr_nmr.nr_memsize >> 20);
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
	if (curr_nmr.nr_flags & NR_PTNETMAP_HOST) {
		printf(", PTNETMAP_HOST");
	}
	printf("]\n");
	printf("spare2[0]: %x\n", curr_nmr.spare2[0]);
}

void
do_nmr_reset()
{
	bzero(&curr_nmr, sizeof(curr_nmr));
}

void
do_nmr_name()
{
	char *name = nextarg();
	if (name) {
		strncpy(curr_nmr.nr_name, name, IFNAMSIZ);
	}
	strncpy(nmr_name, curr_nmr.nr_name, IFNAMSIZ);
	nmr_name[IFNAMSIZ] = '\0';
	output("name=%s", nmr_name);
}

void
do_nmr_ringid()
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
do_nmr_cmd()
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
do_nmr_flags()
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
		} else if (strcmp(arg, "ptnetmap-host") == 0) {
			flags |= NR_PTNETMAP_HOST;
		} else if (strcmp(arg, "default") == 0) {
			flags = 0;
		}
	}
	if (n)
		curr_nmr.nr_flags = flags;
	output("flags=%x", curr_nmr.nr_flags);
}

struct cmd_def nmr_commands[] = {
	{ "dump",	do_nmr_dump },
	{ "reset",	do_nmr_reset },
	{ "name",	do_nmr_name },
	{ "ringid",	do_nmr_ringid },
	{ "cmd",	do_nmr_cmd },
	{ "flags",	do_nmr_flags },
};

const int N_NMR_CMDS = sizeof(nmr_commands) / sizeof(struct cmd_def);

int
find_nmr_command(const char *cmd)
{
	return _find_command(nmr_commands, N_NMR_CMDS, cmd);
}

#define nmr_arg_update(f) 				\
	({						\
		int __ret = 0;				\
		if (strcmp(cmd, #f) == 0) {		\
			char *arg = nextarg();		\
			if (arg) {			\
				curr_nmr.nr_##f = strtol(arg, NULL, 0); \
			}				\
			output(#f "=%d", curr_nmr.nr_##f);	\
			__ret = 1;			\
		} 					\
		__ret;					\
	})

/* prepare the curr_nmr */
void
do_nmr()
{
	char *cmd = nextarg();
	int i;

	if (cmd == NULL) {
		do_nmr_dump();
		return;
	}
	if (cmd[0] == '.') {
		cmd++;
	} else {
		i = find_nmr_command(cmd);
		if (i < N_NMR_CMDS) {
			nmr_commands[i].f();
			return;
		}
	}
	if (nmr_arg_update(version) ||
	    nmr_arg_update(offset) ||
	    nmr_arg_update(memsize) ||
	    nmr_arg_update(tx_slots) ||
	    nmr_arg_update(rx_slots) ||
	    nmr_arg_update(tx_rings) ||
	    nmr_arg_update(rx_rings) ||
	    nmr_arg_update(ringid) ||
	    nmr_arg_update(cmd) ||
	    nmr_arg_update(arg1) ||
	    nmr_arg_update(arg2) ||
	    nmr_arg_update(arg3) ||
	    nmr_arg_update(flags))
		return;
	output("unknown field: %s", cmd);
}



struct cmd_def commands[] = {
	{ "open",	do_open,	},
	{ "close", 	do_close,	},
#ifdef TEST_NETMAP
	{ "getinfo",	do_getinfo,	},
	{ "regif",	do_regif,	},
	{ "txsync",	do_txsync,	},
	{ "rxsync",	do_rxsync,	},
#endif /* TEST_NETMAP */
	{ "dup",	do_dup,		},
	{ "mmap",	do_mmap,	},
	{ "access",	do_access,	},
	{ "munmap",	do_munmap,	},
	{ "poll",	do_poll,	},
	{ "expr",	do_expr,	},
	{ "echo",	do_echo,	},
	{ "vars",	do_vars,	},
	{ "if",         do_if,          },
	{ "ring",       do_ring,        },
	{ "slot",       do_slot,        },
	{ "buf",        do_buf,         },
	{ "nmr",	do_nmr,		}
};

const int N_CMDS = sizeof(commands) / sizeof(struct cmd_def);

int find_command(const char* cmd)
{
	return _find_command(commands, N_CMDS, cmd);
}

#define MAX_CHAN 10

void prompt()
{
	if (isatty(STDIN_FILENO)) {
		printf("> ");
	}
}

struct chan *channels[MAX_CHAN];

void*
thread_cmd_loop(void *arg)
{
	char buf[1024];
	FILE *in = (FILE*)arg;

	while (fgets(buf, 1024, in)) {
		char *cmd;
		int i;

		cmd = firstarg(buf);
		i = find_command(cmd);
		if (i < N_CMDS) {
			commands[i].f();
			continue;
		}
		output("unknown cmd %s", cmd);
	}
	fclose(in);
	return NULL;
}

void do_exit()
{
	output("quit");
}

void
cmd_loop()
{
	char buf[1024];
	int i;
	struct chan *c;

	bzero(channels, sizeof(*channels) * MAX_CHAN);

	atexit(do_exit);

	for (prompt(); fgets(buf, 1024, stdin); prompt()) {
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
			int slot = chan_search_free(channels, MAX_CHAN);
			struct chan *c = NULL;
			pid_t pid;
			int p1[2] = { -1, -1};

			if (slot == MAX_CHAN) {
				output("too many channels");
				continue;
			}
			c = channels[slot] = (struct chan*)malloc(sizeof(struct chan));
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
				fclose(stdin);
				if (dup(p1[0]) < 0) {
					output_err(-1, "dup");
					exit(1);
				}
				close(p1[1]);
				stdin = fdopen(0, "r");
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
			c = channels[slot];
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
			int slot = chan_search_free(channels, MAX_CHAN);
			struct chan *c = NULL;
			pthread_t tid;
			int p1[2] = { -1, -1};
			int ret;
			FILE *in = NULL;

			if (slot == MAX_CHAN) {
				output("too many channels");
				continue;
			}
			c = channels[slot] = (struct chan*)malloc(sizeof(struct chan));
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
				(unsigned long) tid, slot);
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
				(unsigned long) c->tid, ret);
			if (ret > 0) {
				free(c);
				channels[slot] = NULL;
			}
			continue;
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
	(void) argc;
	(void) argv;
	printf("testmmap\n");
	cmd_loop();
	return 0;
}
