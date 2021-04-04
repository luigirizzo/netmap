/*
 * Copyright (C) 2016-2017 Michio Honda. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *   1. Redistributions of source code must retain the above copyright
 *      notice, this list of conditions and the following disclaimer.
 *   2. Redistributions in binary form must reproduce the above copyright
 *      notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <inttypes.h>
#include <sys/poll.h>
#ifdef __FreeBSD__
#include <sys/event.h>
#include <sys/stat.h>
#endif /* __FreeBSD__ */
#include <net/if.h>
#include <netinet/in.h>
#include <dirent.h>
#include <x86intrin.h>
#define NMLIB_EXTRA_SLOT 1
#include "nmlib.h"
#ifdef WITH_BPLUS
#include <bplus_support.h>
#include <bplus_common.h>
#endif /* WITH_BPLUS */
#ifdef WITH_NOFLUSH
#define _mm_clflush(p) (void)(p)
#endif
#ifdef WITH_CLFLUSHOPT
#define _mm_clflush(p) _mm_clflushopt(p)
#endif

//#define MYHZ	2400000000
#ifdef MYHZ
static __inline unsigned long long int rdtsc(void)
{
   //unsigned long long int x;
   unsigned a, d;

   __asm__ volatile("rdtsc" : "=a" (a), "=d" (d));

   return ((unsigned long long)a) | (((unsigned long long)d) << 32);;
}

static inline void
user_clock_gettime(struct timespec *ts)
{
        unsigned long long now;

        now = rdtsc();
        ts->tv_sec = now/MYHZ;
        ts->tv_nsec = (now%MYHZ)*1000000000/MYHZ;
}
#endif /* MYHZ */

#define PST_NAME	"pst:0"
#define EXTMEMFILE	"netmap_mem"
#define BPLUSFILE	"bplus"
#define DATAFILE	"dumb"

#define IPV4TCP_HDRLEN	66
#define NETMAP_BUF_SIZE	2048
#define GET_LEN		4
#define POST_LEN	5

#define MAX_PAYLOAD	1400
#define min(a, b) (((a) < (b)) ? (a) : (b)) 
#define max(a, b) (((a) > (b)) ? (a) : (b)) 

#define EPOLLEVENTS	2048
#define MAXQUERYLEN	32767

#define MAX_HTTPLEN	65535

#define DF_FDSYNC	0x1
#define DF_PASTE	0x2
#define DF_BPLUS	0x4
#define DF_KVS		0x8
#define DF_MMAP		0x10
#define DF_PMEM		0x20

#define CLSIZ	64 /* XXX */

struct dbctx {
	int type;
	int flags;
	size_t size;
	size_t pgsiz;
	int i;
	int	fd;
	char *paddr;
	void *vp; // gfile_t
	size_t cur;
};

struct phttpd_global {
	char ifname[NETMAP_REQ_IFNAMSIZ];
	int extmemfd;
	int sd;
	char *http;
	int httplen;
	int msglen;
	struct {
		int	type;
		int	flags;
		size_t	size;
		char	*dir; // directory path for data, metadata ane ppool
	} dba;
};

static inline int
is_pm(struct dbctx *d)
{
	return !!(d->flags & DF_PMEM);
}

static inline size_t
get_aligned(size_t len, size_t align)
{
	size_t d = len & (align - 1);
	return d ? len + align - d : len;
}

enum { DT_NONE=0, DT_DUMB};

#if 0
static u_int stat_nfds;
static u_int stat_eps;
static u_int stat_maxnfds;
static u_int stat_minnfds;
static uint64_t stat_vnfds;
#endif /* 0 */

static int
copy_to_nm(struct netmap_ring *ring, const char *data,
		int len, int off0, int off, int fd)
{
	u_int const tail = ring->tail;
	u_int cur = ring->cur;
	u_int copied = 0;
	const int space = nm_ring_space(ring);

	if (unlikely(space * MAX_PAYLOAD < len)) {
		RD(1, "no space (%d slots)", space);
		return -1;
	}

	while (likely(cur != tail) && copied < len) {
		struct netmap_slot *slot = &ring->slot[cur];
		char *p = NETMAP_BUF_OFFSET(ring, slot) + off0;
		/* off0 contains some payload */
		int l = min(MAX_PAYLOAD - (off0 - off), len - copied);

		if (data) {
			nm_pkt_copy(data + copied, p, l);
		}
		slot->len = off0 + l;
		nm_pst_setuoff(slot, off);
		nm_pst_setfd(slot, fd);
		copied += l;
		off0 = off;
		cur = nm_ring_next(ring, cur);
	}
	ring->cur = ring->head = cur;
	return len;
}

static char *HTTPHDR = "HTTP/1.1 200 OK\r\n"
		 "Connection: keep-alive\r\n"
		 "Server: Apache/2.2.800\r\n"
		 "Content-Length: ";
#define HTTPHDR_LEN 81

ssize_t
generate_httphdr(size_t content_length, char *buf)
{
	uint64_t *h = (uint64_t *)HTTPHDR;
	uint64_t *p = (uint64_t *)buf;
	char *c;

	*p++ = *h++;
	*p++ = *h++;
	*p++ = *h++;
	*p++ = *h++;
	*p++ = *h++;
	*p++ = *h++;
	*p++ = *h++;
	*p++ = *h++;
	*p++ = *h++;
	*p++ = *h++;
	c = (char *)p;
	*c++ = *(char *)h;
	c += sprintf(c, "%lu\r\n\r", content_length);
	*c++ = '\n';
	return c - buf;
}

static int
generate_http(int content_length, char *buf, char *content)
{
	int hlen = generate_httphdr(content_length, buf);

	if (content)
		memcpy(buf + hlen, content, content_length);
	return hlen + content_length;
}

static int
generate_http_nm(int content_length, struct netmap_ring *ring,
		int off, int fd, char *header, int hlen, char *content)
{
	int len, cur = ring->cur;
	struct netmap_slot *slot = &ring->slot[cur];
	char *p = NETMAP_BUF_OFFSET(ring, slot) + off;

	if (header)
		memcpy(p, header, hlen);
	else
		hlen = generate_httphdr(content_length, p);
	len = copy_to_nm(ring, content, content_length,
			off + hlen, off, fd);
	return len < content_length ? -1 : hlen + len;
}

#define SKIP_POST	48
static int
parse_post(char *post, int *coff, uint64_t *key)
{
	int clen;
	char *pp, *p = strstr(post + SKIP_POST, "Content-Length: ");
	char *end;

	*key = 0;
	*coff = 0;
	if (unlikely(!p))
		return -1;
	pp = p + 16; // strlen("Content-Length: ")
	clen = strtol(pp, &end, 10);
	if (unlikely(end == pp))
		return -1;
	pp = strstr(pp, "\r\n\r\n");
	if (unlikely(!pp))
		return -1;
	pp += 4;
	*key = *(uint64_t *)pp;
	*coff = pp - post;
	return clen;
}

static void
usage(void)
{
	fprintf(stderr,
	    "Usage:\n"
	    "\t[-P port] TCP listen port (default 60000)\n"
	    "\t[-l size] message length excluding HTTP header (default 64)\n"
	    "\t[-b ms] timeout in poll(2), kqueue(2) or epoll_wait(2) (default 2000)\n"
	    "\t[-d path] database directory (e.g., /mnt/pmem)\n"
	    "\t\tTo recognize PM, the path string must include \"pm\"\n"
	    "\t[-L MB] size of database file given by -d\n"
	      "\t\tNot required when making netmap objects directly on PM with -x\n"
	    "\t[-i name] netmap(2) port name. This indicates use of PASTE\n"
	    "\t[-x MB] size of netmap memory allocator in MB\n"
	    "\t[-a affinity] (same semantics with pkt-gen)\n"
	    "\t[-p nthreads] (same semantics with pkt-gen)\n"
	    "\t[-C config] virtual port configuration in vale-ctl(8) syntax\n"
	    "\t[-m] mmap(2) database given by -d. For PM, always specify\n"
	    "\t[-D] use fdatasync(2) instead of fsync\n"
	    "\t[-c] static HTTP header (don't use with KVS)\n"
	    "\t[-B] use B+tree (need phttpd-b)\n"
	    "\t[-k] run as KVS (need phttpd-b)\n"
	    "\t[-F] don't clflush on PM (need phttpd-f) \n"
	    "\t[-e ns] emulate PM access time (need phttpd-o)\n"
	    "\t[-h] show this help\n"

	    "\nExamples:\n"
	    "\t1. No database or PASTE\n\n"
	    "\t# phttpd -b 0 -c\n\n"
	    "\t2. PASTE but w/o any database\n\n"
	    "\t# phttpd -b 0 -i eth1 -c\n\n"
	    "\t3. WAL and copy\n\n"
	    "\t# phttpd -b 0 -i eth1 -d /mnt/pmem -L 768 -m -c \n\n"
	    "\t  where /mnt/pmem must be on a DAX-enabled filesystem on (emulated)\n"
	    "\t  PM and have at least 8 GB capacity\n\n"
	    "\t4. WAL w/o copy\n\n"
	    "\t# phttpd -b 0 -i eth1 -d /mnt/pmem -x 768 -m -c \n\n"
	    "\t5. WAL w/o copy and four CPU cores/threads\n\n"
	    "\t# phttpd -b 0 -i eth1 -d /mnt/pmem -x 768 -m -c -C 0,0,4,4 -p 4\n\n"
	    "\t  where the underlying NIC must have at least 4 queues\n\n"
	    "\t6. B+tree w/o copy\n\n"
	    "\t# phttpd-b -b 0 -i eth1 -d /mnt/pmem -x 768 -m -c -B\n\n"

	    "\nTips:\n"
	    "\t1. For client, use of wrk HTTP benchmark tool is recommended.\n"
	    "\t   To generate HTTP POST traffic, use lua script like:\n\n"
	    "\twrk.method = \"POST\"\n"
	    "\ts = \"foo=bar&baz=quux\"\n"
	    "\twrk.body = s\n"
	    "\tfor i = 0, 79 do\n"
	    "\t\twrk.body = wrk.body..s\n"
	    "\tend\n"
	    "\twrk.headers[\"Content-Type\"] = \"application/x-www-form-urlencoded\"\n\n"
	    "\t   This script passed to wrk with -s generates 1280B HTTP POSTs\n\n"

	    "\t2. Make sure all the hardware offloading are disabled except for\n"
	    "\t   tx-checksum-ip-generic (e1000, ixgbe) or tx-checksum-ipv4 (i40e)\n"
	    "\t   in Linux.\n\n"

	    "\t3. When using busy-polling (i.e., -b 0), set NIC interrupt interval\n"
	    "\t   as long as possible (PASTE) or as short as possible (w/o PASTE)\n\n"

	    );

	exit(1);
}

static int
writesync(char *buf, ssize_t len, size_t space, int fd, size_t *pos, int fdsync)
{
	int error;
	size_t cur = *pos;

	ND("len %lu  space %lu fd %d pos %lu, fdsync %d",
			len, space, fd, *pos, fdsync);
	if (unlikely(cur + len > space)) {
		if (lseek(fd, 0, SEEK_SET) < 0) {
			perror("lseek");
			return -1;
		}
		cur = 0;
	}
	len = write(fd, buf, len);
	if (len < 0) {
		perror("write");
		return -1;
	}
	cur += len;
	error = fdsync ? fdatasync(fd) : fsync(fd);
	if (error) {
		fprintf(stderr, "failed in f%ssync\n", fdsync ? "data" : "");
		return -1;
	}
	*pos = cur;
	return 0;
}

static inline uint64_t
pack(uint32_t idx, uint16_t off, uint16_t len)
{
	return (uint64_t)idx << 32 | off << 16 | len;
}

#define KVS_SLOT_OFF 8
#ifdef WITH_BPLUS
static inline uint64_t
parse_get_key(char *get)
{
	return *(uint64_t *)(get + GET_LEN + 1); // jump '/'
}

static inline void
unpack(uint64_t p, uint32_t *idx, uint16_t *off, uint16_t *len)
{
	*idx = p >> 32;
	*off = (p & 0x00000000ffff0000) >> 16;
	*len = p & 0x000000000000ffff;
}

static struct netmap_slot *
set_to_nm(struct netmap_ring *txr, struct netmap_slot *any_slot)
{
	struct netmap_slot tmp, *txs = NULL;

	if (unlikely(nm_ring_space(txr) == 0)) {
		return NULL;
	}
	do {
		txs = &txr->slot[txr->cur];
		if (unlikely(any_slot == txs)) {
			break;
		}
		tmp = *txs;
		*txs = *any_slot;
		txs->flags |= NS_BUF_CHANGED;
		*any_slot = tmp;
		any_slot->flags |= NS_BUF_CHANGED; // this might sit on the ring
	} while (0);
	txr->cur = txr->head = nm_ring_next(txr, txr->cur);
	return txs;
}

enum slot {SLOT_UNKNOWN=0, SLOT_EXTRA, SLOT_USER, SLOT_KERNEL};

static inline int
between(u_int x, u_int a, u_int b)
{
	return x >= a && x < b;
}

/* no handle on x > a && x > b */
static inline int
between_wrap(u_int x, u_int a, u_int b)
{
	return a <= b ? between(x, a, b) : !between(x, b, a);
}

static inline int
between_slot(struct netmap_slot *s, struct netmap_slot *l, struct netmap_slot *h)
{
	return between((uintptr_t)s, (uintptr_t)l, (uintptr_t)h);
}

#define U(x)	((uintptr_t)(x))
static inline int
whose_slot(struct netmap_slot *slot, struct netmap_ring *ring,
		struct netmap_slot *extra, u_int extra_num)
{
	if (between_slot(slot, ring->slot, ring->slot + ring->num_slots)) {
		if (between_wrap(slot - ring->slot, ring->head, ring->tail))
			return SLOT_USER;
		else
			return SLOT_KERNEL;
	} else if (between_slot(slot, extra, extra + extra_num)) {
		return SLOT_EXTRA;
	}
	return SLOT_UNKNOWN; // not on ring or extra, maybe kernel's extra
}
#undef U

/* For KVS we embed a pointer to a slot in the known position in the buffer */

//POST http://www.micchie.net/ HTTP/1.1\r\nHost: 192.168.11.3:60000\r\nContent-Length: 1280\r\n\r\n2
//HTTP/1.1 200 OK\r\nConnection: keep-alive\r\nServer: //Apache/2.2.800\r\nContent-Length: 1280\r\n\r\n
static inline struct netmap_slot*
unembed(char *nmb, u_int coff)
{
	return *(struct netmap_slot **)(nmb + coff + KVS_SLOT_OFF);
}
#endif /* WITH_BPLUS */

static inline void
embed(struct netmap_slot *slot, char *buf)
{
	*(struct netmap_slot **)(buf + KVS_SLOT_OFF) = slot;
}

#ifdef WITH_BPLUS
static inline void
nmidx_bplus(gfile_t *vp, btree_key key, struct netmap_slot *slot, size_t off, size_t len)
{
	uint64_t packed;
	//uint64_t datam;
	static int unique = 0;
	int rc;

	packed = pack(slot->buf_idx, off, len);
	rc = btree_insert(vp, key, packed);
	if (rc == 0)
		unique++;
	ND("key %lu val %lu idx %u off %lu len %lu",
			key, packed, slot->buf_idx, off, len);
}
#endif /* WITH_BPLUS */

static inline void
nmidx_wal(char *paddr, size_t *pos, size_t dbsiz, struct netmap_slot *slot,
		size_t off, size_t len)
{
	uint64_t packed;
	size_t cur = *pos;
	int plen = sizeof(packed);
	char *p = paddr;

	/* make log */
	packed = pack(slot->buf_idx, off, len);
	/* position log */
	if (unlikely(plen > dbsiz - cur))
		cur = 0;
	p += cur;
	*(uint64_t *)p = packed;
	_mm_clflush(p);
	*pos = cur + plen;
}

static inline void
copy_and_log(char *paddr, size_t *pos, size_t dbsiz, char *buf, size_t len,
		u_int nowrap, size_t align, int pm, void *vp, uint64_t key)
{
	char *p;
	int mlen = vp ? 0 : sizeof(uint64_t);
	size_t cur = *pos;
	u_int i = 0;
	size_t aligned = len;

	ND("paddr %p pos %lu dbsiz %lu buf %p len %lu nowrap %u align %lu pm %d vp %p key %lu", paddr, *pos, dbsiz, buf, len, nowrap, align, pm, vp, key);
#ifdef WITH_BPLUS
	if (!align && vp) { // B+tree maintains data by index
		align = NETMAP_BUF_SIZE;
	}
#endif /* WITH_BPLUS */
	if (align) {
		aligned = get_aligned(len, align);
	}

	/* Do we have a space? */
	if (unlikely(cur + max(aligned, nowrap) + mlen > dbsiz)) {
		cur = 0;
	}
	p = paddr + cur;
	p += mlen; // leave a log entry space

	memcpy(p, buf, len);
	if (pm) {
		for (; i < len; i += CLSIZ) {
			_mm_clflush(p + i);
		}
	}
	p -= mlen;
	if (!pm) {
		int error = msync(p, len + mlen, MS_SYNC);
		if (error)
			perror("msync");
	}
#ifdef WITH_BPLUS
	if (vp) {
		static int unique = 0;
		uint64_t packed = pack(cur/NETMAP_BUF_SIZE, 0, len);
		int rc = btree_insert(vp, key, packed);
		if (rc == 0)
			unique++;
	} else
#endif
	{
		*(uint64_t *)p = len;
		if (pm)
			_mm_clflush(p);
		//else {
		//	msync(p, sizeof(size_t), MS_SYNC);
		//}
	}
	*pos = cur + aligned + (align ? 0 : mlen);
}

enum http {NONE=0, POST, GET};
static __inline int
httpreq(const char *p)
{
	enum http req = NONE;

	if (!strncmp(p, "POST ", POST_LEN)) {
		req = POST;
	} else if (!strncmp(p, "GET ", GET_LEN)) {
		req = GET;
	}
	return req;
}

static inline void
leftover(int *fde, const ssize_t len, int *is_leftover, int *thisclen)
{
	if (unlikely(*fde <= 0)) {
		/* XXX OOB message? Just suppress response */
		*is_leftover = 1;
		return;
	}
	*fde -= len;
	if (unlikely(*fde < 0)) {
		D("bad leftover %d (len %ld)", *fde, len);
		*fde = 0;
	} else if (*fde > 0) {
		D("still have leftover %d", *fde);
		*is_leftover = 1;
	}
	*thisclen = len;
}

static inline void
leftover_post(int *fde, const ssize_t len, const ssize_t clen,
		const int coff, int *thisclen, int *is_leftover)
{
	*thisclen = len - coff;
	if (clen > *thisclen) {
		*fde = clen - *thisclen;
		*is_leftover = 1;
	}
}

static int
phttpd_req(char *rxbuf, int fd, int len, struct nm_targ *targ, int *no_ok,
		ssize_t *msglen, char **content, u_int off,
		struct netmap_ring *txr, struct netmap_ring *rxr,
		struct netmap_slot *rxs)
{
	struct dbctx *db = (struct dbctx *)targ->opaque;
	int *fde = &targ->fdtable[fd];

	const int flags = db->flags;
	const size_t dbsiz = db->size;

	*no_ok = 0;

	switch (httpreq(rxbuf)) {
	uint64_t key;
	int coff, clen, thisclen;

	case NONE:
		leftover(fde, len, no_ok, &thisclen);
		break;
	case POST:
		clen = parse_post(rxbuf, &coff, &key);
		if (unlikely(clen < 0))
			return 0;
		rxbuf += coff;
		leftover_post(fde, len, clen, coff, &thisclen, no_ok);

		if (flags & DF_PASTE) {
			u_int i = 0;
			struct netmap_slot tmp, *extra;
			uint32_t extra_i = netmap_extra_next(targ, &db->cur, 1);

			/* flush data buffer */
			for (; i < thisclen; i += CLSIZ) {
				_mm_clflush(rxbuf + i);
			}
#ifdef WITH_BPLUS
			if (db->vp) {
				nmidx_bplus(db->vp, key, rxs,
					off + coff, thisclen);
			} else
#endif
			if (db->paddr) {
				nmidx_wal(db->paddr, &db->cur, dbsiz,
				    rxs, off + coff, thisclen);
			}

			/* swap out buffer */
			extra = &targ->extra[extra_i];
			tmp = *rxs;
			rxs->buf_idx = extra->buf_idx;
			rxs->flags |= NS_BUF_CHANGED;
			*extra = tmp;
			extra->flags &= ~NS_BUF_CHANGED;

			/* record current slot */
			if (db->flags & DF_KVS) {
				embed(extra, rxbuf);
			}
		} else if (db->paddr) {
			copy_and_log(db->paddr, &db->cur, dbsiz, rxbuf,
			    thisclen, db->pgsiz, is_pm(db) ? 0 : db->pgsiz,
			    is_pm(db), db->vp, key);
		} else if (db->fd > 0) {
			if (writesync(rxbuf, len, dbsiz, db->fd,
			    &db->cur, flags & DF_FDSYNC)) {
				return -1;
			}
		} else {
			RD(1, "no db to save POST");
		}
		break;
	case GET:
#ifdef WITH_BPLUS
	{
		uint32_t _idx;
		uint16_t _off, _len;
		uint64_t datam = 0;
		int rc;

		if (flags & DF_KVS || !db->vp)
			break;
		key = parse_get_key(rxbuf);
		rc = btree_lookup(db->vp, key, &datam);
		if (rc == ENOENT)
			break;
		unpack(datam, &_idx, &_off, &_len);
		ND("found key %lu val %lu idx %u off %lu len %lu",
			key, datum, _idx, _off, _len);

		if (flags & DF_PASTE) {
			enum slot t;
			struct netmap_slot *s;
			char *_buf;

			_buf = NETMAP_BUF(rxr, _idx);
			s = unembed(_buf, _off);
			t = whose_slot(s, txr, targ->extra, targ->extra_num);
			if (t == SLOT_UNKNOWN) {
				*msglen = _len;
			} else if (t == SLOT_KERNEL ||
				   s->flags & NS_BUF_CHANGED) {
				*msglen = _len;
				*content = _buf + _off;
			} else { // zero copy
				struct netmap_slot *txs;
				u_int hlen;

				txs = set_to_nm(txr, s);
				nm_pst_setfd(txs, nm_pst_getfd(rxs));
				txs->len = _off + _len - IPV4TCP_HDRLEN; // XXX
				embed(txs, _buf + _off);
				hlen = generate_httphdr(_len, _buf + off);
				if (unlikely(hlen != _off - off)) {
					RD(1, "mismatch");
				}
				*no_ok = 1;
			}
		} else {
			*content = db->paddr + NETMAP_BUF_SIZE * _idx;
			*msglen = _len;
		}
	}
#endif /* WITH_BPLUS */
		break;
	default:
		break;
	}
	return 0;
}

int
phttpd_data(struct nm_msg *m)
{
	struct nm_targ *targ = m->targ;
	struct nm_garg *g = targ->g;
	struct phttpd_global *pg = (struct phttpd_global *)g->garg_private;

	struct netmap_ring *rxr = m->rxring;
	struct netmap_ring *txr = m->txring;
	struct netmap_slot *rxs = m->slot;
	ssize_t msglen = pg->msglen;

	int len, no_ok = 0;
	char *rxbuf, *content = NULL;
	int error;
	const u_int off = nm_pst_getuoff(rxs);
#ifdef MYHZ
	struct timespec ts1, ts2, ts3;
	user_clock_gettime(&ts1);
#endif
	rxbuf = NETMAP_BUF_OFFSET(rxr, rxs) + off;
	len = rxs->len - off;
	if (unlikely(len == 0)) {
		close(nm_pst_getfd(rxs));
		return 0;
	}

	error = phttpd_req(rxbuf, nm_pst_getfd(rxs), len, targ, &no_ok,&msglen,
			&content, off, txr, rxr, rxs);
	if (error) {
		return error;
	}
	if (!no_ok) {
		generate_http_nm(msglen, txr, IPV4TCP_HDRLEN, nm_pst_getfd(rxs),
				 pg->http, pg->httplen, content);
	}
#ifdef MYHZ
	user_clock_gettime(&ts2);
	ts3 = timespec_sub(ts2, ts1);
#endif /* MYHZ */
	return 0;
}

/* We assume GET/POST appears in the beginning of netmap buffer */
int phttpd_read(int fd, struct nm_targ *targ)
{
	char buf[MAXQUERYLEN];
	ssize_t len = 0, written;
	struct nm_garg *g = targ->g;
	struct phttpd_global *tg = (struct phttpd_global *)g->garg_private;
	struct dbctx *db = (struct dbctx *)targ->opaque;
	char *content = NULL;
	int no_ok = 0;
	ssize_t msglen = tg->msglen;
	int error;

	len = read(fd, buf, sizeof(buf));
	if (len <= 0) {
		close(fd);
		return len == 0 ? 0 : -1;
	}

	error = phttpd_req(buf, fd, len, targ, &no_ok, &msglen, &content, 0,
		       	NULL, NULL, NULL);
	if (error)
		return error;
	if (no_ok)
		return 0;
	if (tg->httplen && content == NULL) {
		memcpy(buf, tg->http, tg->httplen);
		len = tg->httplen + msglen;
	} else {
		len = generate_http(msglen, buf, content);
	}
#ifdef WITH_CLFLUSHOPT
	_mm_mfence();
	if (g->emu_delay) {
		wait_ns(g->emu_delay);
	}
#endif
	written = write(fd, buf, len);
	if (unlikely(written < 0)) {
		perror("write");
	} else if (unlikely(written < len)) {
		RD(1, "written %ld len %ld", written, len);
	}
	return 0;
}

static int
init_db(struct dbctx *db, int i, const char *dir, int type, int flags, size_t size)
{
	int fd = 0;
	char path[64];

	bzero(db, sizeof(*db));
	if (type == DT_NONE)
		return 0;
	db->type = type;
	db->flags = flags;
	db->size = size;
	db->pgsiz = getpagesize();

	ND("map %p", map);
#ifdef WITH_BPLUS
	/* need B+tree ? */
	if (db->flags & DF_BPLUS) {
		int rc;

		snprintf(path, sizeof(path), "%s/%s%d", dir, BPLUSFILE, i);
		rc = btree_create_btree(path, ((gfile_t **)&db->vp));
		D("btree_create_btree() done (%d) %s", rc, path);
		if (rc != 0)
			return -1;
		else if (db->flags & DF_PASTE)
			return 0;
	}
#endif /* WITH_BPLUS */
	snprintf(path, sizeof(path), "%s/%s%d", dir, DATAFILE, i);
	fd = open(path, O_RDWR | O_CREAT, S_IRWXU);
	if (fd < 0) {
		perror("open");
		return -1;
	}
	if (db->flags & DF_MMAP) {
		if (fallocate(fd, 0, 0, db->size) < 0) {
			perror("fallocate");
			close(fd);
			return -1;
		}
		db->paddr = do_mmap(fd, db->size);
		if (db->paddr == NULL) {
			close(fd);
			return -1;
		}
	}
	db->fd = fd;
	return 0;
}

static int
phttpd_thread(struct nm_targ *targ)
{
	struct nm_garg *nmg = targ->g;
	struct phttpd_global *g =
		(struct phttpd_global *)nmg->garg_private;

	if (init_db((struct dbctx *)targ->opaque, targ->me, g->dba.dir,
		    g->dba.type, g->dba.flags, g->dba.size / nmg->nthreads)) {
		D("error on init_db");
		return ENOMEM;
	}
	return 0;
}

void
clean_dir(char *dirpath)
{
	DIR *dp;
	struct dirent *ent;

	if (!dirpath) 
		return;
	if ((dp = opendir(dirpath)) == NULL) {
		return;
	}
	while ((ent = readdir(dp))) {
		char fullp[256]; // XXX
		size_t l;

		if (ent->d_name[0] == '.')
			continue;
		else if (strstr(ent->d_name, EXTMEMFILE) == NULL &&
			 strstr(ent->d_name, BPLUSFILE) == NULL &&
			 strstr(ent->d_name, DATAFILE) == NULL)
			continue;
		strncat(strncpy(fullp, dirpath, sizeof(fullp) - 2), "/", 2);
		l = strlen(fullp) + strlen(ent->d_name) + 1;
		if (l < sizeof(fullp)) {
			strncat(fullp, ent->d_name, l);
		}
		//strncat(fullp, ent->d_name, sizeof(fullp) - strlen(fullp) - 1);
		D("removing %s", fullp);
		if (unlink(fullp))
			perror("unlink");
	}
}

int
main(int argc, char **argv)
{
	int ch;
	struct sockaddr_in sin;
	int port = 60000;
	struct phttpd_global pg;
	struct nm_garg nmg, *g;
	int error = 0;
	struct netmap_events e;

	bzero(&nmg, sizeof(nmg));
	nmg.nmr_config = NULL;
	nmg.nthreads = 1;
	nmg.polltimeo = 2000;
	nmg.dev_type = DEV_SOCKET;
	nmg.td_type = TD_TYPE_OTHER;
	nmg.targ_opaque_len = sizeof(struct dbctx);
	nmg.ring_objsize = RING_OBJSIZE;

	bzero(&e, sizeof(e));
	e.thread = phttpd_thread;
	e.read = phttpd_read;

	bzero(&pg, sizeof(pg));
	pg.msglen = 64;

	while ((ch = getopt(argc, argv,
			    "P:l:b:md:Di:PcC:a:p:x:L:BkFe:h")) != -1) {
		switch (ch) {
		default:
			D("bad option %c %s", ch, optarg);
			usage();
			break;
		case 'h':
			usage();
			break;
		case 'P':	/* server port */
			port = atoi(optarg);
			break;
		case 'l': /* HTTP OK content length */
			pg.msglen = atoi(optarg);
			break;
		case 'b': /* give the epoll_wait() timeo argument -1 */
			nmg.polltimeo = atoi(optarg);
			break;
		case 'd': /* directory of data store */
			{
			pg.dba.type = DT_DUMB;
			pg.dba.dir = optarg;
			if (optarg[strlen(optarg) - 1] == '/')
				optarg[strlen(optarg) - 1] = '\0';
			if (strstr(optarg, "pm")) // XXX
			       pg.dba.flags |= DF_PMEM;
			}
			break;
		case 'L':
			//use 7680 for approx 8GB
			pg.dba.size = atoll(optarg) * 1000000;
			break;
		case 'm':
			pg.dba.flags |= DF_MMAP;
			break;
		case 'D':
			pg.dba.flags |= DF_FDSYNC;
			break;
		case 'i':
			nmg.dev_type = DEV_NETMAP;
			if (sizeof(pg.ifname) < strlen(optarg) + 1)
				break;
			strncpy(pg.ifname, optarg, sizeof(pg.ifname));
			e.read = NULL;
			e.data = phttpd_data;
			break;
		case 'x': /* PASTE */
			pg.dba.flags |= DF_PASTE;
			nmg.extmem_siz = atol(optarg) * 1000000; // MB to B
			/* believe 90 % is available for bufs */
			//nmg.extra_bufs =
			 //   (nmg.extmem_siz * 9 /10) / NETMAP_BUF_SIZE;
			break;
		case 'c':
			pg.httplen = 1;
			break;
		case 'a':
			nmg.affinity = atoi(optarg);
			break;
		case 'p':
			nmg.nthreads = atoi(optarg);
			break;
		case 'C':
			nmg.nmr_config = strdup(optarg);
			break;
#ifdef WITH_BPLUS
		case 'B':
			pg.dba.flags |= DF_BPLUS;
			break;
		case 'k':
			pg.dba.flags |= DF_KVS;
			break;
#endif /* WITH_BPLUS */
#ifdef WITH_NOFLUSH
		case 'F': // just to tell the script to use phttpd-f
			break;
#endif /* WITH_NOFLUSH */
#ifdef WITH_CLFLUSHOPT
		case 'e':
			nmg.emu_delay = atoi(optarg);
			break;
#endif /* WITH_CLFLUSHOPT */
		}

	}

	clean_dir(pg.dba.dir);

	fprintf(stderr, "%s built %s %s db: %s\n", argv[0], __DATE__, __TIME__,
			pg.dba.dir ? pg.dba.dir : "none");
	usleep(1000);

	argc -= optind;
	argv += optind;

	/*
	 * Check invariants
	 */
	if (!port || !pg.msglen)
		usage();
	else if (pg.dba.flags & DF_PASTE && strlen(pg.ifname) == 0)
		usage();
	else if (pg.dba.type != DT_NONE && pg.dba.size == 0)
		usage();
	else if (pg.dba.type != DT_DUMB && pg.dba.flags)
		usage();
#ifdef WITH_BPLUS
	else if (pg.dba.flags & DF_BPLUS && !(pg.dba.flags & DF_MMAP))
		usage();
	else if (pg.dba.flags & DF_KVS && pg.httplen)
		usage();
#endif /* WITH_BPLUS */

#ifdef __FreeBSD__
	/* kevent requires struct timespec for timeout */
	if (nmg.dev_type != DEV_NETMAP && nmg.polltimeo >= 0) {
		struct timespec *x = calloc(1, sizeof(*x));
		if (!x) {
			perror("calloc");
			usage();
		}
		x->tv_sec = nmg.polltimeo / 1000;
		x->tv_nsec = (nmg.polltimeo % 1000) * 1000000;
		nmg.polltimeo_ts = x;
	}
#endif /* FreeBSD */

	/* Preallocate HTTP header */
	if (pg.httplen) {
		pg.http = calloc(1, MAX_HTTPLEN);
		if (!pg.http) {
			perror("calloc");
			usage();
		}
		pg.httplen = generate_httphdr(pg.msglen, pg.http);
		D("preallocated http hdr %d", pg.httplen);
	}

	pg.sd = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (pg.sd < 0) {
		perror("socket");
		return 0;
	}
	if (do_setsockopt(pg.sd)) {
		goto close_socket;
	}

	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = htonl(INADDR_ANY);
	sin.sin_port = htons(port);
	if (bind(pg.sd, (struct sockaddr *)&sin, sizeof(sin)) < 0) {
		perror("bind");
		goto close_socket;
	}
	if (listen(pg.sd, SOMAXCONN) != 0) {
		perror("listen");
		goto close_socket;
	}

	if (pg.dba.flags & DF_PASTE) {
		int fd, mode = O_RDWR|O_CREAT;
		char path[64];

		/* check space for netmap objects */
		snprintf(path, sizeof(path), "%s/%s", pg.dba.dir, EXTMEMFILE);
		if ((fd = open(path, mode, S_IRWXU)) < 0) {
                        perror("open");
                        goto close_socket;
                }
		if (fallocate(fd, 0, 0, nmg.extmem_siz)) {
			D("fallocate %s failed size %lu", path, nmg.extmem_siz);
			goto close_socket;
		}
		close(fd);
		nmg.extmem = strdup(path);

		//if (pg.dba.size == 0) {
		//	/* up to 16 byte metadata per buffer */
		//	pg.dba.size = nmg.extra_bufs * 8 * 2;
		//}

		/* checks space for metadata */
		snprintf(path, sizeof(path), "%s/%s", pg.dba.dir, DATAFILE);
		if ((fd = open(path, mode, S_IRWXU)) < 0) {
			perror("open");
			goto close_socket;
		}
		if (fallocate(fd, 0, 0, pg.dba.size)) {
			D("error on fallocate %s ", path);
			close(fd);
			goto close_socket;
		}
		/* unlink as each thread creates one later */
		unlink(path);
		close(fd);
	}
	netmap_eventloop(PST_NAME, pg.ifname, (void **)&g, &error,
			&pg.sd, 1, &e, &nmg, &pg);

	free_if_exist(nmg.nmr_config);

close_socket:
	if (pg.extmemfd) {
		if (nmg.extmem) {
			munmap(nmg.extmem, nmg.extmem_siz);
			free(nmg.extmem);
		}
		close(pg.extmemfd);
	}

	if (pg.sd > 0) {
		close(pg.sd);
	}
	free_if_exist(pg.http);
#ifdef __FreeBSD__
	free_if_exist(nmg.polltimeo_ts);
#endif
	return 0;
}
