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
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
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
#define _mm_mfence() (0)
#endif
#ifdef WITH_CLFLUSHOPT
#define _mm_clflush(p) _mm_clflushopt(p)
#endif
#ifdef WITH_LEVELDB
#include <leveldb/db.h>
#include <leveldb/slice.h>
#endif /* WITH_LEVELDB */

//#define MYHZ	2400000000
#ifdef MYHZ
static __inline unsigned long long int rdtsc(void)
{
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
#define LEVELDBFILE    "leveldb"
#define LEVELDBMEMFILE "leveldb_mem"

#define NETMAP_BUF_SIZE	2048
#define GET_LEN		4 // the request look like GET /3
#define POST_LEN	5

#define EPOLLEVENTS	2048
#define MAXQUERYLEN	32767

#define MAX_HTTPLEN	65535

#define DF_FDSYNC	0x1
#define DF_PASTE	0x2
#define DF_BPLUS	0x4
#define DF_MMAP		0x10
#define DF_PMEM		0x20
#define DF_LEVELDB     0x40

#define CLSIZ	64 /* XXX */

struct dbctx {
	int flags;
	size_t size;
	size_t pgsiz;
	int i;
	int	fd;
	char *paddr;
	void *vp; // gfile_t
#ifdef WITH_LEVELDB
	leveldb::DB *leveldb;
#endif /* WITH_LEVELDB */
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

#if 0
static u_int stat_nfds;
static u_int stat_eps;
static u_int stat_maxnfds;
static u_int stat_minnfds;
static uint64_t stat_vnfds;
#endif /* 0 */

static char *HTTPHDR = (char *)"HTTP/1.1 200 OK\r\n"
		 "Connection: keep-alive\r\n"
		 "Server: Apache/2.2.800\r\n"
		 "Content-Length: ";
#define HTTPHDR_LEN 81

ssize_t
generate_httphdr(size_t content_length, char *buf)
{
	char *c = buf;
	c = mempcpy(c, HTTPHDR, HTTPHDR_LEN);
	c += sprintf(c, "%lu\r\n\r", content_length);
	*c++ = '\n';
	return c - buf;
}

#define SKIP_POST	48
static int
parse_post(char *post, const size_t len,
		size_t *coff, size_t *clen, size_t *thisclen)
{
	char *pp, *p = strstr(post + SKIP_POST, (char *)"Content-Length: ");
	char *end;

	*coff = 0;
	if (unlikely(!p))
		return -1;
	pp = p + 16; // strlen("Content-Length: ")
	*clen = strtol(pp, &end, 10);
	if (unlikely(end == pp))
		return -1;
	pp = strstr(pp, "\r\n\r\n");
	if (unlikely(!pp))
		return -1;
	pp += 4;
	*coff = pp - post;
	*thisclen = len - *coff;
	return 0;
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
	    "\t[-i name] netmap(2) port name. This indicates use of PASTE\n"
	    "\t[-x] use extmem. 32B per buffer is reserved for metadata\n"
	    "\t[-a affinity] (same semantics with pkt-gen)\n"
	    "\t[-p nthreads] (same semantics with pkt-gen)\n"
	    "\t[-C config] virtual port configuration in vale-ctl(8) syntax\n"
	    "\t[-m] mmap(2) database given by -d. For PM, always specify\n"
	    "\t[-D] use fdatasync(2) instead of fsync\n"
	    "\t[-c] static HTTP header\n"
	    "\t[-B] use B+tree (need phttpd-b)\n"
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
	    "\t# phttpd -b 0 -i eth1 -d /mnt/pmem -x -L 768 -m -c \n\n"
	    "\t5. WAL w/o copy and four CPU cores/threads\n\n"
	    "\t# phttpd -b 0 -i eth1 -d /mnt/pmem -x -L 768 -m -c -C 0,0,4,4 -p 4\n\n"
	    "\t  where the underlying NIC must have at least 4 queues\n\n"
	    "\t6. B+tree w/o copy\n\n"
	    "\t# phttpd-b -b 0 -i eth1 -d /mnt/pmem -x -L 768 -m -c -B\n\n"

	    "\nTips:\n"
	    "\t1. wrk HTTP benchmark tool is useful as the client.\n"
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

	    "\t3. When using busy-polling (-b 0), set NIC interrupt interval\n"
	    "\t   as long as possible (PASTE) or as short as possible (w/o PASTE)\n\n"

	    );

	exit(1);
}

static int
writesync(char *buf, ssize_t len, size_t space, int fd, size_t *pos, int fdsync)
{
	int error;
	size_t cur = *pos;

	if (unlikely(cur + len > space)) {
		if (lseek(fd, 0, SEEK_SET) < 0) {
			perror("lseek");
			return -1;
		}
		cur = 0;
	}
	len = write(fd, buf, len);
	if (unlikely(len < 0)) {
		perror("write");
		return -1;
	}
	cur += len;
	error = fdsync ? fdatasync(fd) : fsync(fd);
	if (unlikely(error)) {
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

#ifdef WITH_BPLUS
static inline void
nmidx_bplus(gfile_t *vp, btree_key key, uint32_t bufidx, size_t off, size_t len)
{
	uint64_t packed;
	static int unique = 0;
	int rc;

	packed = pack(bufidx, off, len);
	rc = btree_insert(vp, key, packed);
	if (rc == 0)
		unique++;
	ND("k %lu v %lu idx %u off %lu len %lu", key, packed, bufidx, off, len);
}
#endif /* WITH_BPLUS */

static inline void
nmidx_wal(char *paddr, size_t *pos, size_t dbsiz, uint32_t bufidx,
		size_t off, size_t len)
{
	uint64_t packed;
	size_t cur = *pos;
	size_t plen = sizeof(packed);
	char *p = paddr;

	/* make log */
	packed = pack(bufidx, off, len);
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
		size_t pagesiz, int pm, void *vp, uint64_t key)
{
	char *p;
	int mlen = vp ? 0 : sizeof(uint64_t);
	size_t cur = *pos;
	u_int i = 0;
	size_t aligned = len;
	size_t align = pagesiz;

	if (pm) {
#ifdef WITH_BPLUS
		if (vp)
			align = NETMAP_BUF_SIZE;
		else
#endif
			align = 0;
	}
	if (align > 0) {
		aligned = get_aligned(len, align);
	}
	/* Do we have a space? */
	if (unlikely(cur + aligned + mlen > dbsiz)) {
		cur = 0;
	}
	p = paddr + cur + mlen; // leave a log entry space
	memcpy(p, buf, len);
	if (pm) {
		for (; i < len; i += CLSIZ) {
			_mm_clflush(p + i);
		}
	}
	p -= mlen;
	if (!pm) {
		if (msync(p, len + mlen, MS_SYNC))
			perror("msync");
	}
#ifdef WITH_BPLUS
	if (vp) {
		static int unique = 0;
		uint64_t packed = pack(cur/NETMAP_BUF_SIZE, 0, len);
		int rc = btree_insert((gfile_t *)vp, key, packed);
		if (rc == 0) {
			unique++;
		}
	} else
#endif
	{
		*(uint64_t *)p = len;
		if (pm)
			_mm_clflush(p);
		else {
			msync(p, sizeof(size_t), MS_SYNC);
		}
	}
	*pos = cur + aligned + (align ? 0 : mlen);
}

enum http {NONE=0, POST, GET};
static __inline int
httptype(const char *p)
{
	enum http type = NONE;

	if (!strncmp(p, "POST ", POST_LEN)) {
		type = POST;
	} else if (!strncmp(p, "GET ", GET_LEN)) {
		type = GET;
	}
	return type;
}

static int
phttpd_req(char *req, int len, struct nm_msg *m, int *no_ok,
		size_t *msglen, char **content)
{
	struct dbctx *db = (struct dbctx *)m->targ->opaque;
	int *fde = &m->targ->fdtable[m->fd];
	char *datap;

	const int flags = db->flags;
	const size_t dbsiz = db->size;

	*no_ok = 0;

	switch (httptype(req)) {
	uint64_t key;
	size_t coff, clen, thisclen;

	case NONE:
		if (unlikely(*fde <= 0)) {
			*no_ok = 1;
			*fde = 0;
			break;
		}
		*fde -= len;
		if (unlikely(*fde < 0)) {
			D("bad leftover %d (len %d)", *fde, len);
			*fde = 0;
		} else if (*fde > 0) {
			*no_ok = 1;
		}
		break;
	case POST:
		if (parse_post(req, len, &coff, &clen, &thisclen)) {
			return 0;
		}
		if (clen > thisclen) {
			*fde = clen - thisclen;
			*no_ok = 1;
		}
		datap = req + coff;
		key = *(uint64_t *)datap;

		if (flags & DF_PASTE) {
			u_int i = 0;
			struct netmap_slot tmp, *extra, *slot = m->slot;
			uint32_t xi = netmap_extra_next(m->targ, &db->cur, 1);
			const u_int off = NETMAP_ROFFSET(m->rxring, slot)
				+ nm_pst_getdoff(slot) + coff;
			/* flush data buffer */
			for (; i < thisclen; i += CLSIZ) {
				_mm_clflush(datap + i);
			}
#ifdef WITH_BPLUS
			if (db->vp) {
				nmidx_bplus((gfile_t *)db->vp, key,
				    slot->buf_idx, off, thisclen);
			} else
#endif
			if (db->paddr) {
				nmidx_wal(db->paddr, &db->cur, dbsiz,
				    slot->buf_idx, off, thisclen);
			}

			/* swap out buffer */
			extra = &m->targ->extra[xi];
			tmp = *slot;
			slot->buf_idx = extra->buf_idx;
			slot->flags |= NS_BUF_CHANGED;
			*extra = tmp;
			extra->flags &= ~NS_BUF_CHANGED;
#ifdef WITH_LEVELDB
		} else if (db->leveldb) {
			leveldb::Slice skey((char *)&key, sizeof(key));
			leveldb::Slice sval((char *)&req, thisclen);
			leveldb::Status status;
			leveldb::WriteOptions write_options;
			write_options.sync = true;
			status = db->leveldb->Put(write_options, skey, sval);
			if (!status.ok()) {
				D("leveldb write error");
			}
#endif /* WITH_LEVELDB */
		} else if (db->paddr) {
			copy_and_log(db->paddr, &db->cur, dbsiz, datap,
			    thisclen, db->pgsiz, is_pm(db), db->vp, key);
		} else if (db->fd > 0) {
			if (writesync(datap, len, dbsiz, db->fd,
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

		if (!db->vp)
			break;
		key = *(uint64_t *)(req + GET_LEN + 1); // jump '/'
		rc = btree_lookup((gfile_t *)db->vp, key, &datam);
		if (rc == ENOENT)
			break;
		_idx = datam >> 32;
		_off = (datam & 0x00000000ffff0000) >> 16;
		_len = datam & 0x000000000000ffff;
		ND("found key %lu val %lu idx %u off %u len %u",
			key, datam, _idx, _off, _len);
		*msglen = _len;
		if (flags & DF_PASTE) {
			*content = NETMAP_BUF(m->rxring, _idx) + _off;
		} else {
			*content = db->paddr + NETMAP_BUF_SIZE * _idx;
		}
	}
#endif /* WITH_BPLUS */
		break;
	default:
		break;
	}
	return 0;
}

static int
phttpd_data(struct nm_msg *m)
{
	struct phttpd_global *pg = (struct phttpd_global *)
		m->targ->g->garg_private;
	size_t msglen = pg->msglen, len = 0;
	int error, no_ok = 0;
	char *content = NULL;
	u_int doff = nm_pst_getdoff(m->slot);
#ifdef MYHZ
	struct timespec ts1, ts2, ts3;
	user_clock_gettime(&ts1);
#endif

	len = m->slot->len - doff;
	if (unlikely(len == 0)) {
		close(m->fd);
		return 0;
	}

	error = phttpd_req(NETMAP_BUF_OFFSET(m->rxring, m->slot) + doff,
			len, m, &no_ok, &msglen, &content);
	if (unlikely(error)) {
		return error;
	}
	if (!no_ok) {
		int httplen = pg->httplen;
		struct netmap_ring *txr = m->txring;
		char *p = NETMAP_BUF_OFFSET(txr, &txr->slot[txr->cur])
			+ IPV4TCP_HDRLEN;
		if (pg->http) {
			memcpy(p, pg->http, httplen);
		} else {
			httplen = generate_httphdr(msglen, p);
		}
		len = nm_write(txr, content, msglen, httplen, m->fd);
		if (unlikely(len < msglen)) {
			D("no space");
		}
	}
#ifdef MYHZ
	user_clock_gettime(&ts2);
	ts3 = timespec_sub(ts2, ts1);
#endif /* MYHZ */
	return 0;
}

/* We assume GET/POST appears in the beginning of netmap buffer */
static int
phttpd_read(struct nm_msg *m)
{
	struct phttpd_global *pg = (struct phttpd_global *)
		m->targ->g->garg_private;
	size_t msglen = pg->msglen, len = 0;
	int error, no_ok = 0;
	char *content = NULL;
	char buf[MAXQUERYLEN];

	len = read(m->fd, buf, sizeof(buf));
	if (len <= 0) {
		close(m->fd);
		return len == 0 ? 0 : -1;
	}

	error = phttpd_req(buf, len, m, &no_ok, &msglen, &content);
	if (unlikely(error))
		return error;
	if (!no_ok) {
		int httplen = pg->httplen;

		if (pg->http) {
			memcpy(buf, pg->http, httplen);
		} else {
			httplen = generate_httphdr(msglen, buf);
		}
		if (content) {
			memcpy(buf + httplen, content, msglen);
		}
#ifdef WITH_CLFLUSHOPT
		_mm_mfence();
		if (m->targ->g->emu_delay) {
			wait_ns(m->targ->g->emu_delay);
		}
#endif
		len = write(m->fd, buf, httplen + msglen);
		if (unlikely(len < 0)) {
			perror("write");
		} else if (unlikely(len < httplen + msglen)) {
			RD(1, "written %ld len %ld", len, httplen + msglen);
		}
	}
	return 0;
}

static int
init_db(struct dbctx *db, int i, const char *dir, int flags, size_t size)
{
	int fd = 0;
	char path[64];

	if (!dir)
		return 0;
	bzero(db, sizeof(*db));
	db->flags = flags;
	db->size = size;
	db->pgsiz = getpagesize();

#ifdef WITH_LEVELDB
	if (db->flags & DF_LEVELDB) {
		leveldb::Status status;
		leveldb::Options options;
		char mpath[64];
		std::string val;

		options.create_if_missing = true;
		// 16GB
		options.write_buffer_size = 16384000000;
		options.nvm_buffer_size = 16384000000;
		options.reuse_logs = true;
		snprintf(path, sizeof(path), "%s/%s%d", dir, LEVELDBFILE, i);
		snprintf(mpath, sizeof(mpath), "%s/%s%d", dir, LEVELDBMEMFILE, i);
		status = leveldb::DB::Open(options, path, mpath, &db->leveldb);
		if (!status.ok()) {
			D("error to open leveldb %s", path);
			return -1;
		}
		D("done Open LevelDB dbfile %s memfile %s", path, mpath);

		leveldb::WriteOptions write_options;
		write_options.sync = false;
		status = db->leveldb->Put(write_options, "100", "test");
		if (!status.ok()) {
			D("leveldb write error");
		}
		status = db->leveldb->Get(leveldb::ReadOptions(), "100", &val);
		if (!status.ok()) {
			D("leveldb read error");
		}
		status = db->leveldb->Delete(leveldb::WriteOptions(), "100");
		if (!status.ok()) {
			D("leveldb write error");
		}
		D("leveldb test done (error reported if any)");
	}
#endif
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
		db->paddr = (char *)do_mmap(fd, db->size);
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
		    g->dba.flags, g->dba.size / nmg->nthreads)) {
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

char *
chkpath(char *dir, char *f, size_t size, int rm)
{
	int fd, mode = O_RDWR|O_CREAT;
	char *path = calloc(1, strlen(dir) + strlen(f) + 2);

	if (path == NULL)
		return NULL;
	snprintf(path, sizeof(path), "%s/%s", dir, f);
	if ((fd = open(path, mode, S_IRWXU)) < 0) {
		perror("open");
		return NULL;
	}
	if (fallocate(fd, 0, 0, size)) {
		D("fallocate %s failed size %lu", path, size);
		close(fd);
		return NULL;
	}
	if (rm)
		unlink(path);
	close(fd);
	return path;
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

	bzero(&nmg, sizeof(nmg));
	nmg.nmr_config = NULL;
	nmg.nthreads = 1;
	nmg.polltimeo = 2000;
	nmg.dev_type = DEV_SOCKET;
	nmg.td_type = TD_TYPE_OTHER;
	nmg.targ_opaque_len = sizeof(struct dbctx);
	nmg.ring_objsize = RING_OBJSIZE;

	nmg.thread = phttpd_thread;
	nmg.read = phttpd_read;

	bzero(&pg, sizeof(pg));
	pg.msglen = 64;

	while ((ch = getopt(argc, argv,
			    "P:l:b:md:Di:cC:a:p:xL:BFe:hN")) != -1) {
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
			pg.dba.dir = optarg;
			if (optarg[strlen(optarg) - 1] == '/')
				optarg[strlen(optarg) - 1] = '\0';
			if (strstr(optarg, "pm")) // XXX
			       pg.dba.flags |= DF_PMEM;
			}
			break;
		case 'L':
			pg.dba.size = atoll(optarg) * 1000000; // given in MB
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
			nmg.read = NULL;
			nmg.data = phttpd_data;
			break;
		case 'x': /* PASTE */
			pg.dba.flags |= DF_PASTE;
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
#endif /* WITH_BPLUS */
#ifdef WITH_LEVELDB
		case 'N':
			pg.dba.flags |= DF_LEVELDB;
			break;
#endif /* WITH_LEVELDB */
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
#ifdef WITH_BPLUS
	else if (pg.dba.flags & DF_BPLUS && !(pg.dba.flags & DF_MMAP))
		usage();
#endif /* WITH_BPLUS */
#ifdef WITH_LEVELDB
	else if (pg.dba.flags & DF_LEVELDB) {
		if (pg.dba.flags & (DF_BPLUS|DF_PASTE|DF_MMAP|DF_FDSYNC))
			usage();
	}
#endif /* WITH_LEVELDB */

	if (pg.dba.flags & DF_MMAP) {
		/* checks space for metadata */
		if (!chkpath(pg.dba.dir, DATAFILE, pg.dba.size, 1))
			goto close_socket;
		/* some space for extmem */
		if (pg.dba.flags & DF_PASTE) {
			/* 32B metadata per netmap buffer */
			u_int n = pg.dba.size / NETMAP_BUF_SIZE;
			nmg.extmem_siz = pg.dba.size - 32 * n;
			pg.dba.size -= nmg.extmem_siz;
			nmg.extmem =chkpath(pg.dba.dir, EXTMEMFILE,
					nmg.extmem_siz, 0);
			if (nmg.extmem == NULL)
				goto close_socket;
		}
	}
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
		pg.http = (char *)calloc(1, MAX_HTTPLEN);
		if (!pg.http) {
			perror("calloc");
			usage();
		}
		pg.httplen = generate_httphdr(pg.msglen, pg.http);
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

	netmap_eventloop(PST_NAME, pg.ifname, (void **)&g, &error,
			&pg.sd, 1, NULL, 0, &nmg, &pg);

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
