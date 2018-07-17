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
nm_is_identifier(const char *s, const char *e)
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

#define MAXERRMSG 1000
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
			strncmp(ifname, NM_BDG_NAME, NM_BDG_NAMSZ)) {
		nmreq_ferror("invalid request '%s' (must begin with 'netmap:' or '" NM_BDG_NAME "')", ifname);
		goto fail;
	}

	is_vale = (ifname[0] == 'v');
	if (is_vale) {
		scan = index(ifname, ':');
		if (scan == NULL) {
			nmreq_ferror("missing ':' in VALE name '%s'", ifname);
			goto fail;
		}

		if (!nm_is_identifier(ifname + NM_BDG_NAMSZ, scan)) {
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
		gh.nr_reqtype = NETMAP_REQ_PORT_INFO_GET;
		memset(&gb, 0, sizeof(gb));
		gh.nr_body = (uintptr_t)&gb;
		if (ioctl(fd, NIOCCTRL, &gh) < 0) {
			if (errno == ENOENT || errno == ENXIO)
				goto try_external;
			nmreq_ferror("cannot get info for %s: %s", mem_id, strerror(errno));
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
		nmreq_ferror("cannot open %s: %s", mem_id, strerror(errno));
		goto fail;
	}
	mapsize = lseek(fd, 0, SEEK_END);
	if (mapsize < 0) {
		nmreq_ferror("failed to obtain filesize of %s: %s", mem_id, strerror(errno));
		goto fail;
	}
	p = mmap(0, mapsize, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	if (p == MAP_FAILED) {
		nmreq_ferror("cannot mmap %s: %s", mem_id, strerror(errno));
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
			num = strtol(scan, (char **)&scan, 10);
			if (num <= 0) {
				ED("non-numeric mem_id '%s'", scan);
				if (nmreq_mem_id_parse(scan, h, r, e) < 0)
					goto fail;
				goto out;
			} else {
				r->nr_mem_id = num;
				memid_allowed = 0;
				p_state = P_RNGSFXOK;
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

#if 0
#include <inttypes.h>
int
main(int argc, char *argv[])
{
	struct nmreq_header h;
	struct nmreq_register r;
	struct nmreq_opt_extmem e;

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
	return 0;
}
#endif
