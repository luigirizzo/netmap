#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#define NETMAP_WITH_LIBS
#include <net/netmap_user.h>

#ifdef NMREQ_DEBUG
#define ED(...)	D(__VA_ARGS__)
#else
#define ED(...)
#endif /* NMREQ_DEBUG */

static void
nmreq_error_stderr(const char *errmsg)
{
	fprintf(stderr, "%s\n", errmsg);
}

static void
nmreq_error_ignore(const char *errmsg)
{
	(void)errmsg;
}

typedef void (*nmreq_error_callback_t)(const char *);
static nmreq_error_callback_t nmreq_error_callback = nmreq_error_stderr;

/* an identifier is a possibly empty sequence of alphanum characters and
 * underscores
 */
static int
nmreq_is_identifier(const char *s, const char *e)
{
	for (; s != e; s++) {
		if (!isalnum(*s) && *s != '_') {
			return 0;
		}
	}

	return 1;
}

nmreq_error_callback_t nmreq_set_error_callback(nmreq_error_callback_t f)
{
	nmreq_error_callback_t old = nmreq_error_callback;
	nmreq_error_callback = f;
	return old;
}

#ifndef MAXERRMSG
#define MAXERRMSG 1000
#endif
static void
nmreq_ferror(const char *fmt, ...)
{
	char errmsg[MAXERRMSG];
	va_list ap;
	int rv;

	va_start(ap, fmt);
	rv = vsnprintf(errmsg, MAXERRMSG, fmt, ap);
	va_end(ap);

	if (rv > 0) {
		if (rv < MAXERRMSG) {
			nmreq_error_callback(errmsg);
		} else {
			nmreq_error_callback("error message too long");
		}
	} else {
		nmreq_error_callback("internal error");
	}
}

void
nmreq_push_option(struct nmreq_header *h, struct nmreq_option *o)
{
	o->nro_next = h->nr_options;
	h->nr_options = (uintptr_t)o;
}

const char *
nmreq_header_decode(const char *ifname, struct nmreq_header *h)
{
	int is_vale;
	const char *scan = NULL;
	const char *vpname = NULL;
	const char *pipesep = NULL;
	u_int namelen;
	static size_t NM_BDG_NAMSZ = strlen(NM_BDG_NAME);

	if (strncmp(ifname, "netmap:", 7) &&
			strncmp(ifname, NM_BDG_NAME, NM_BDG_NAMSZ) &&
			strncmp(ifname, NM_STACK_NAME, strlen(NM_STACK_NAME))) {
		nmreq_ferror("invalid request '%s' (must begin with 'netmap:' or '" NM_BDG_NAME "')", ifname);
		goto fail;
	}

	is_vale = (ifname[0] == 'v') || ifname[0] == 's';
	if (is_vale) {
		scan = index(ifname, ':');
		if (scan == NULL) {
			nmreq_ferror("missing ':' in VALE name '%s'", ifname);
			goto fail;
		}

		if (!nmreq_is_identifier(ifname + NM_BDG_NAMSZ, scan)) {
			nmreq_ferror("invalid VALE bridge name '%.*s'",
					(scan - ifname - NM_BDG_NAMSZ), ifname + NM_BDG_NAMSZ);
			goto fail;
		}

		vpname = ++scan;
	} else {
		ifname += 7;
		scan = ifname;
		vpname = ifname;
	}

	/* scan for a separator */
	for (; *scan && !index("-*^/@", *scan); scan++)
		;

	/* search for possible pipe indicators */
	for (pipesep = vpname; pipesep != scan && !index("{}", *pipesep); pipesep++)
		;

	if (!nm_is_identifier(vpname, pipesep)) {
		nmreq_ferror("invalid %sport name '%.*s'", (is_vale ? "VALE " : ""),
				pipesep - vpname, vpname);
		goto fail;
	}
	if (pipesep != scan) {
		pipesep++;
		if (!nm_is_identifier(pipesep, scan)) {
			nmreq_ferror("invalid pipe name '%.*s'", scan - pipesep, pipesep);
			goto fail;
		}
	}

	namelen = scan - ifname;
	if (namelen >= sizeof(h->nr_name)) {
		nmreq_ferror("name '%.*s' too long", namelen, ifname);
		goto fail;
	}

	/* fill the header */
	memset(h, 0, sizeof(*h));
	h->nr_version = NETMAP_API;
	memcpy(h->nr_name, ifname, namelen);
	h->nr_name[namelen] = '\0';
	ED("name %s", h->nr_name);

	return scan;
fail:
	errno = EINVAL;
	return NULL;
}


static int
nmreq_mem_id_parse(const char *mem_id, struct nmreq_header *h,
		struct nmreq_register *r, struct nmreq_opt_extmem *e)
{
	int fd = -1;
	struct nmreq_header gh;
	struct nmreq_port_info_get gb;
	off_t mapsize;
	const char *rv;
	nmreq_error_callback_t old;
	void *p;

	if (mem_id == NULL)
		return 0;

	errno = 0;

	/* first, try to look for a netmap port with this name */
	fd = open("/dev/netmap", O_RDONLY);
	if (fd < 0) {
		nmreq_ferror("cannot open /dev/netmap: %s", strerror(errno));
		goto fail;
	}
	old = nmreq_set_error_callback(nmreq_error_ignore);
	rv = nmreq_header_decode(mem_id, &gh);
	nmreq_set_error_callback(old);
	if (rv != NULL) {
		if (*rv != '\0') {
			nmreq_ferror("unexpected characters '%s' in mem_id spec", rv);
			goto fail;
		}
		gh.nr_reqtype = NETMAP_REQ_PORT_INFO_GET;
		memset(&gb, 0, sizeof(gb));
		gh.nr_body = (uintptr_t)&gb;
		if (ioctl(fd, NIOCCTRL, &gh) < 0) {
			if (errno == ENOENT || errno == ENXIO)
				goto try_external;
			nmreq_ferror("cannot get info for '%s': %s", mem_id, strerror(errno));
			goto fail;
		}
		r->nr_mem_id = gb.nr_mem_id;
		close(fd);
		return 0;
	}

try_external:
	close(fd);
	ED("trying with external memory");
	if (e == NULL) {
		nmreq_ferror("external memory request, but no option struct provided");
		goto fail;
	}
	fd = open(mem_id, O_RDWR);
	if (fd < 0) {
		nmreq_ferror("cannot open '%s': %s", mem_id, strerror(errno));
		goto fail;
	}
	mapsize = lseek(fd, 0, SEEK_END);
	if (mapsize < 0) {
		nmreq_ferror("failed to obtain filesize of '%s': %s", mem_id, strerror(errno));
		goto fail;
	}
	p = mmap(0, mapsize, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	if (p == MAP_FAILED) {
		nmreq_ferror("cannot mmap '%s': %s", mem_id, strerror(errno));
		goto fail;
	}
	memset(e, 0, sizeof(*e));
	e->nro_opt.nro_reqtype = NETMAP_REQ_OPT_EXTMEM;
	e->nro_usrptr = (uintptr_t)p;
	e->nro_info.nr_memsize = mapsize;
	nmreq_push_option(h, &e->nro_opt);
	ED("mapped %zu bytes at %p from file %s", mapsize, pi, mem_id);
	return 0;

fail:
	if (fd >= 0)
		close(fd);
	if (!errno)
		errno = EINVAL;
	return -1;
}

int
nmreq_register_decode(const char *ifname, struct nmreq_header *h,
		struct nmreq_register *r, struct nmreq_opt_extmem *e)
{
	enum { P_START, P_RNGSFXOK, P_GETNUM, P_FLAGS, P_FLAGSOK, P_MEMID } p_state;
	long num;
	const char *scan;
	int memid_allowed = 1;

	scan = nmreq_header_decode(ifname, h);
	if (scan == NULL)
		goto fail;

	h->nr_body = (uintptr_t)r;

	/* fill the request */
	memset(r, 0, sizeof(*r));

	p_state = P_START;
	r->nr_mode = NR_REG_ALL_NIC; /* default for no suffix */
	while (*scan) {
		switch (p_state) {
		case P_START:
			switch (*scan) {
			case '^': /* only SW ring */
				r->nr_mode = NR_REG_SW;
				p_state = P_RNGSFXOK;
				break;
			case '*': /* NIC and SW */
				r->nr_mode = NR_REG_NIC_SW;
				p_state = P_RNGSFXOK;
				break;
			case '-': /* one NIC ring pair */
				r->nr_mode = NR_REG_ONE_NIC;
				p_state = P_GETNUM;
				break;
			case '/': /* start of flags */
				p_state = P_FLAGS;
				break;
			case '@': /* start of memid */
				p_state = P_MEMID;
				break;
			default:
				nmreq_ferror("unknown modifier: '%c'", *scan);
				goto fail;
			}
			scan++;
			break;
		case P_RNGSFXOK:
			switch (*scan) {
			case '/':
				p_state = P_FLAGS;
				break;
			case '@':
				p_state = P_MEMID;
				break;
			default:
				nmreq_ferror("unexpected character: '%c'", *scan);
				goto fail;
			}
			scan++;
			break;
		case P_GETNUM:
			if (!isdigit(*scan)) {
				nmreq_ferror("got '%s' while expecting a number", scan);
				goto fail;
			}
			num = strtol(scan, (char **)&scan, 10);
			if (num < 0 || num >= NETMAP_RING_MASK) {
				nmreq_ferror("'%ld' out of range [0, %d)",
						num, NETMAP_RING_MASK);
				goto fail;
			}
			r->nr_ringid = num & NETMAP_RING_MASK;
			p_state = P_RNGSFXOK;
			break;
		case P_FLAGS:
		case P_FLAGSOK:
			if (*scan == '@') {
				scan++;
				p_state = P_MEMID;
				break;
			}
			switch (*scan) {
			case 'x':
				r->nr_flags |= NR_EXCLUSIVE;
				break;
			case 'z':
				r->nr_flags |= NR_ZCOPY_MON;
				break;
			case 't':
				r->nr_flags |= NR_MONITOR_TX;
				break;
			case 'r':
				r->nr_flags |= NR_MONITOR_RX;
				break;
			case 'R':
				r->nr_flags |= NR_RX_RINGS_ONLY;
				break;
			case 'T':
				r->nr_flags |= NR_TX_RINGS_ONLY;
				break;
			default:
				nmreq_ferror("unrecognized flag: '%c'", *scan);
				goto fail;
			}
			scan++;
			p_state = P_FLAGSOK;
			break;
		case P_MEMID:
			if (!memid_allowed) {
				nmreq_ferror("double setting of mem_id");
				goto fail;
			}
			if (isdigit(*scan)) {
				num = strtol(scan, (char **)&scan, 10);
				r->nr_mem_id = num;
				memid_allowed = 0;
				p_state = P_RNGSFXOK;
			} else {
				ED("non-numeric mem_id '%s'", scan);
				if (nmreq_mem_id_parse(scan, h, r, e) < 0)
					goto fail;
				goto out;
			}
			break;
		}
	}
	if (p_state != P_START && p_state != P_RNGSFXOK &&
	    p_state != P_FLAGSOK && p_state != P_MEMID) {
		nmreq_ferror("unexpected end of request");
		goto fail;
	}
out:
	ED("flags: %s %s %s %s %s %s",
			(r->nr_flags & NR_EXCLUSIVE) ? "EXCLUSIVE" : "",
			(r->nr_flags & NR_ZCOPY_MON) ? "ZCOPY_MON" : "",
			(r->nr_flags & NR_MONITOR_TX) ? "MONITOR_TX" : "",
			(r->nr_flags & NR_MONITOR_RX) ? "MONITOR_RX" : "",
			(r->nr_flags & NR_RX_RINGS_ONLY) ? "RX_RINGS_ONLY" : "",
			(r->nr_flags & NR_TX_RINGS_ONLY) ? "TX_RINGS_ONLY" : "");
	return 0;

fail:
	if (!errno)
		errno = EINVAL;
	return -1;
}

static int
nmreq_mmap(struct nm_desc *d, const struct nm_desc *parent)
{
	//XXX TODO: check if mmap is already done

	if (IS_NETMAP_DESC(parent) && parent->mem &&
	    parent->nr.reg.nr_mem_id == d->nr.reg.nr_mem_id) {
		/* do not mmap, inherit from parent */
		D("do not mmap, inherit from parent");
		d->memsize = parent->memsize;
		d->mem = parent->mem;
	} else {
		/* XXX TODO: check if memsize is too large (or there is overflow) */
		d->memsize = d->nr.reg.nr_memsize;
		d->mem = mmap(0, d->memsize, PROT_WRITE | PROT_READ, MAP_SHARED,
				d->fd, 0);
		if (d->mem == MAP_FAILED) {
			goto fail;
		}
		d->done_mmap = 1;
	}
	{
		struct netmap_if *nifp = NETMAP_IF(d->mem, d->nr.reg.nr_offset);
		struct netmap_ring *r = NETMAP_RXRING(nifp, d->first_rx_ring);
		if ((void *)r == (void *)nifp) {
			/* the descriptor is open for TX only */
			r = NETMAP_TXRING(nifp, d->first_tx_ring);
		}

		*(struct netmap_if **)(uintptr_t)&(d->nifp) = nifp;
		*(struct netmap_ring **)(uintptr_t)&d->some_ring = r;
		*(void **)(uintptr_t)&d->buf_start = NETMAP_BUF(r, 0);
		*(void **)(uintptr_t)&d->buf_end =
			(char *)d->mem + d->memsize;
	}

	return 0;

fail:
	return EINVAL;
}

int
nmreq_close(struct nm_desc *d)
{
	/*
	 * ugly trick to avoid unused warnings
	 */
	static void *__xxzt[] __attribute__ ((unused))  =
		{ (void *)nm_open, (void *)nm_inject,
		  (void *)nm_dispatch, (void *)nm_nextpkt } ;

	if (d == NULL || d->self != d)
		return EINVAL;
	if (d->done_mmap && d->mem)
		munmap(d->mem, d->memsize);
	if (d->fd != -1) {
		close(d->fd);
	}

	bzero(d, sizeof(*d));
	free(d);
	return 0;
}

struct nm_desc *
nmreq_open(const char *ifname, uint64_t new_flags, const struct nm_desc *arg)
{
	struct nm_desc *d = NULL;
	const struct nm_desc *parent = arg;
	uint32_t nr_reg;

	d = (struct nm_desc *)calloc(1, sizeof(*d));
	if (d == NULL) {
		nmreq_ferror("nm_desc alloc failure");
		errno = ENOMEM;
		return NULL;
	}
	d->self = d;	/* set this early so nmreq_close() works */
	d->fd = open(NETMAP_DEVICE_NAME, O_RDWR);
	if (d->fd < 0) {
		nmreq_ferror("cannot open /dev/netmap: %s",
				strerror(errno));
		goto fail;
	}

	/* import extmem request before decode */
	if (!(new_flags & NM_OPEN_NO_MMAP) && parent &&
	    parent->nr.ext.nro_opt.nro_reqtype == NETMAP_REQ_OPT_EXTMEM) {
		memcpy(&d->nr.ext, &parent->nr.ext, sizeof(parent->nr.ext));
	}

	/* ifname may contain suffix and removed is stored in hdr.nr_name */
	if (!(new_flags & NM_OPEN_NO_DECODE)) {
		if (nmreq_register_decode(ifname,
		    &d->nr.hdr, &d->nr.reg, &d->nr.ext) < 0) {
			goto fail;
		}
	}

	d->nr.reg.nr_ringid &= NETMAP_RING_MASK;

	/* optionally import info from parent */
	if (IS_NETMAP_DESC(parent) && new_flags) {
		if (new_flags & NM_OPEN_MEMID) {
			D("overriding MEMID %d", parent->nr.reg.nr_mem_id);
			d->nr.reg.nr_mem_id = parent->nr.reg.nr_mem_id;
		}
		if (new_flags & NM_OPEN_EXTRA)
			D("overriding EXTRA %d", parent->nr.reg.nr_extra_bufs);
		d->nr.reg.nr_extra_bufs = new_flags & NM_OPEN_ARG3 ?
			parent->nr.reg.nr_extra_bufs : 0;
		if (new_flags & NM_OPEN_RING_CFG) {
			D("overriding RING_CFG");
			d->nr.reg.nr_tx_slots = parent->nr.reg.nr_tx_slots;
			d->nr.reg.nr_rx_slots = parent->nr.reg.nr_rx_slots;
			d->nr.reg.nr_tx_rings = parent->nr.reg.nr_tx_rings;
			d->nr.reg.nr_rx_rings = parent->nr.reg.nr_rx_rings;
		}
		if (new_flags & NM_OPEN_IFNAME) {
			D("overriding ringid 0x%x flags 0x%lx",
			    parent->nr.reg.nr_ringid, parent->nr.reg.nr_flags);
			d->nr.reg.nr_ringid = parent->nr.reg.nr_ringid;
			d->nr.reg.nr_flags = parent->nr.reg.nr_flags;
			d->nr.reg.nr_mode = parent->nr.reg.nr_mode;
		}
		if (new_flags & NM_OPEN_NO_DECODE) {
			if (nmreq_header_decode(ifname, &d->nr.hdr) == NULL) {
				D("failed to header_decode on NO_DECODE");
				goto fail;
			}
			d->nr.hdr.nr_options = (uintptr_t)NULL;
		}
	}

	/* import extmem configuration if it has been decoded */
	if (d->nr.ext.nro_opt.nro_reqtype == NETMAP_REQ_OPT_EXTMEM) {
#define C(_d, _s, _w) ((_d)->nr.ext.nro_info._w = (_s)->nr.ext.nro_info._w)
		C(d, parent, nr_if_pool_objtotal);
		C(d, parent, nr_ring_pool_objtotal);
		C(d, parent, nr_ring_pool_objsize);
		C(d, parent, nr_buf_pool_objtotal);
#undef C
	}

	/* add the *XPOLL flags */
	d->nr.reg.nr_ringid |=
		new_flags & (NETMAP_NO_TX_POLL | NETMAP_DO_RX_POLL);

	d->nr.hdr.nr_reqtype = NETMAP_REQ_REGISTER;
	d->nr.hdr.nr_body = (uintptr_t)&d->nr.reg;

	if (ioctl(d->fd, NIOCCTRL, &d->nr.hdr)) {
		nmreq_ferror("NIOCCTRL failed: %s", strerror(errno));
		goto fail;
	}

	nr_reg = d->nr.reg.nr_mode;

	if (nr_reg == NR_REG_SW) { /* host stack */
		d->first_tx_ring = d->last_tx_ring = d->nr.reg.nr_tx_rings;
		d->first_rx_ring = d->last_rx_ring = d->nr.reg.nr_rx_rings;
	} else if (nr_reg ==  NR_REG_ALL_NIC) { /* only nic */
		d->first_tx_ring = 0;
		d->first_rx_ring = 0;
		d->last_tx_ring = d->nr.reg.nr_tx_rings - 1;
		d->last_rx_ring = d->nr.reg.nr_rx_rings - 1;
	} else if (nr_reg ==  NR_REG_NIC_SW) {
		d->first_tx_ring = 0;
		d->first_rx_ring = 0;
		d->last_tx_ring = d->nr.reg.nr_tx_rings;
		d->last_rx_ring = d->nr.reg.nr_rx_rings;
	} else if (nr_reg == NR_REG_ONE_NIC) {
		/* XXX check validity */
		d->first_tx_ring = d->last_tx_ring =
		d->first_rx_ring = d->last_rx_ring = d->nr.reg.nr_ringid & NETMAP_RING_MASK;
	} else { /* pipes */
		d->first_tx_ring = d->last_tx_ring = 0;
		d->first_rx_ring = d->last_rx_ring = 0;
	}

        /* if parent is defined, do nm_mmap() even if NM_OPEN_NO_MMAP is set */
	if ((!(new_flags & NM_OPEN_NO_MMAP) || parent) && nmreq_mmap(d, parent)) {
	        nmreq_ferror("mmap failed: %s", strerror(errno));
		goto fail;
	}

	return d;
fail:
	nmreq_close(d);
	return NULL;
}

#ifndef LIB
#include <inttypes.h>
int
main(int argc, char *argv[])
{
	struct nmreq_header h;
	struct nmreq_register r;
	struct nmreq_opt_extmem e;
	u_int flags = 0;
	struct nm_desc *d, base_nmd;
	size_t memsize;

	if (argc < 2) {
		fprintf(stderr, "usage: %s netmap-expr\n", argv[0]);
		return 1;
	}


	if (nmreq_register_decode(argv[1], &h, &r, &e) < 0) {
		perror("nmreq");
		return 1;
	}

	printf("header:\n");
	printf("   nr_version:  %"PRIu16"\n", h.nr_version);
	printf("   nr_reqtype:  %"PRIu16"\n", h.nr_reqtype);
	printf("   nr_reserved: %"PRIu32"\n", h.nr_reserved);
	printf("   nr_name:     %s\n", h.nr_name);
	printf("   nr_options:  %lx\n", (unsigned long)h.nr_options);
	printf("   nr_body:     %lx\n", (unsigned long)h.nr_body);
	printf("\n");
	printf("register (%p):\n", &r);
	printf("   nr_mem_id:   %"PRIu16"\n", r.nr_mem_id);
	printf("   nr_ringid:   %"PRIu16"\n", r.nr_ringid);
	printf("   nr_mode:     %lx\n", (unsigned long)r.nr_mode);
	printf("   nr_flags:    %lx\n", (unsigned long)r.nr_flags);
	printf("\n");
	printf("opt_extmem (%p):\n", &e);
	printf("   nro_opt.nro_next:    %lx\n", (unsigned long)e.nro_opt.nro_next);
	printf("   nro_opt.nro_reqtype: %"PRIu32"\n", e.nro_opt.nro_reqtype);
	printf("   nro_usrptr:          %lx\n", (unsigned long)e.nro_usrptr);
	printf("   nro_info.nr_memsize  %"PRIu64"\n", e.nro_info.nr_memsize);

	/* start another test */

	bzero(&base_nmd, sizeof(base_nmd));
	base_nmd.self = &base_nmd;
	memcpy(base_nmd.nr.hdr.nr_name, argv[1], sizeof(base_nmd.nr.hdr.nr_name));
	base_nmd.nr.reg.nr_flags |= NR_ACCEPT_VNET_HDR;

	flags = NM_OPEN_IFNAME | NM_OPEN_ARG1 | NM_OPEN_ARG2 | NM_OPEN_ARG3 |
		NM_OPEN_RING_CFG;

	memsize = (size_t)atoi(argv[2]) * 1000000;
	base_nmd.nr.ext.nro_opt.nro_reqtype = NETMAP_REQ_OPT_EXTMEM;
	base_nmd.nr.ext.nro_info.nr_if_pool_objtotal = 128;
	base_nmd.nr.ext.nro_info.nr_ring_pool_objtotal = 512;
	base_nmd.nr.ext.nro_info.nr_ring_pool_objsize = 33024;
	base_nmd.nr.ext.nro_info.nr_buf_pool_objtotal = (memsize / 2048) * 9 / 10;

	d = nmreq_open(argv[1], flags, &base_nmd);
        if (d == NULL) {
		perror("nmreq_open");
		return 1;
	}

	return 0;
}
#endif
