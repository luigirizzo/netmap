/*
 * Copyright (C) 2011 Matteo Landi, Luigi Rizzo. All rights reserved.
 * Copyright (C) 2013 Universita` di Pisa
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   1. Redistributions of source code must retain the above copyright
 *      notice, this list of conditions and the following disclaimer.
 *   2. Redistributions in binary form must reproduce the above copyright
 *      notice, this list of conditions and the following disclaimer in the
 *      documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

/*
 * $FreeBSD$
 *
 * This header contains the macros used to manipulate netmap structures
 * and packets in userspace. See netmap(4) for more information.
 *
 * The address of the struct netmap_if, say nifp, is computed from the
 * value returned from ioctl(.., NIOCREG, ...) and the mmap region:
 *	ioctl(fd, NIOCREG, &req);
 *	mem = mmap(0, ... );
 *	nifp = NETMAP_IF(mem, req.nr_nifp);
 *		(so simple, we could just do it manually)
 *
 * From there:
 *	struct netmap_ring *NETMAP_TXRING(nifp, index)
 *	struct netmap_ring *NETMAP_RXRING(nifp, index)
 *		we can access ring->nr_cur, ring->nr_avail, ring->nr_flags
 *
 *	ring->slot[i] gives us the i-th slot (we can access
 *		directly plen, flags, bufindex)
 *
 *	char *buf = NETMAP_BUF(ring, x) returns a pointer to
 *		the buffer numbered x
 *
 * Since rings are circular, we have macros to compute the next index
 *	i = NETMAP_RING_NEXT(ring, i);
 *
 * To ease porting apps from pcap to netmap we supply a few fuctions
 * that can be called to open, close and read from netmap in a way
 * similar to libpcap.
 *
 * In order to use these, include #define NETMAP_WITH_LIBS
 * in the source file that invokes these functions.
 */

#ifndef _NET_NETMAP_USER_H_
#define _NET_NETMAP_USER_H_

#include <stdint.h>
#include <net/if.h>
#include <net/netmap.h>

#define _NETMAP_OFFSET(type, ptr, offset) \
	((type)(void *)((char *)(ptr) + (offset)))

#define NETMAP_IF(b, o)	_NETMAP_OFFSET(struct netmap_if *, b, o)

#define NETMAP_TXRING(nifp, index) _NETMAP_OFFSET(struct netmap_ring *, \
	nifp, (nifp)->ring_ofs[index] )

#define NETMAP_RXRING(nifp, index) _NETMAP_OFFSET(struct netmap_ring *,	\
	nifp, (nifp)->ring_ofs[index + (nifp)->ni_tx_rings + 1] )

#define NETMAP_BUF(ring, index)				\
	((char *)(ring) + (ring)->buf_ofs + ((index)*(ring)->nr_buf_size))

#define NETMAP_BUF_IDX(ring, buf)			\
	( ((char *)(buf) - ((char *)(ring) + (ring)->buf_ofs) ) / \
		(ring)->nr_buf_size )

#define	NETMAP_RING_NEXT(r, i)				\
	((i)+1 == (r)->num_slots ? 0 : (i) + 1 )

#define	NETMAP_RING_FIRST_RESERVED(r)			\
	( (r)->cur < (r)->reserved ?			\
	  (r)->cur + (r)->num_slots - (r)->reserved :	\
	  (r)->cur - (r)->reserved )

/*
 * Return 1 if the given tx ring is empty.
 */
#define NETMAP_TX_RING_EMPTY(r)	((r)->avail >= (r)->num_slots - 1)

#ifdef NETMAP_WITH_LIBS
/*
 * Support for simple I/O libraries.
 * Include the headers required for compiling this.
 */

#ifndef HAVE_NETMAP_WITH_LIBS
#define HAVE_NETMAP_WITH_LIBS

#include <sys/time.h>
#include <sys/mman.h>
#include <string.h>	/* memset */
#include <sys/ioctl.h>
#include <sys/errno.h>	/* EINVAL */
#include <fcntl.h>	/* O_RDWR */
#include <malloc.h>

struct nm_hdr_t {
	struct timeval	ts;
	uint32_t	caplen;
	uint32_t	len;
};

struct nm_desc_t {
	struct nm_desc_t *self;
	int fd;
	int pending;	/* must free previous buffer */
	void *mem;
	int memsize;
	struct netmap_if *nifp;
	int first_ring;
	int last_ring;
	int cur_ring;
	struct nmreq req;
	struct nm_hdr_t hdr;
};

/*
 * The callback, invoked on each received packet. Same as libpcap
 */
typedef void (*nm_cb_t)(u_char *, const struct nm_hdr_t *, const u_char *d);

/*
 * The open routine accepts an ifname (netmap:foo or vale:foo) and
 * optionally a second (string) argument indicating the ring number
 * to open. If successful, t opens the fd and maps the memory.
 */
static struct nm_desc_t *nm_open(const char *ifname,
	 const char *ring_no, int flags, int ring_flags);

/*
 * nm_dispatch is the same as pcap_dispatch.
 */
static int nm_dispatch(struct nm_desc_t *, int, nm_cb_t, u_char *);

/*
 * unmap memory, close file descriptor and free the descriptor.
 */
static int nm_close(struct nm_desc_t *desc);


static struct nm_desc_t *
nm_open(const char *ifname, const char *ring, int flags, int ring_flags)
{
	const char *base = "netmap:", *dev, *s;
	int err;
	u_int n = 7; /* strlen netmap: */
	struct nm_desc_t *d;

	if (!strncmp(ifname, base, n) && !strncmp(ifname, "vale", 4))
		return NULL;
	dev = (*ifname == 'v') ? ifname : ifname + n;
	d = (struct nm_desc_t *)calloc(1, sizeof(*d));
	if (d == NULL)
		return NULL;
	d->self = d;
	d->fd = open("/dev/netmap", O_RDWR);
	if (d->fd < 0)
		goto fail;

	if (flags & NETMAP_SW_RING) {
		d->req.nr_ringid = NETMAP_SW_RING;
	} else {
		if (flags & NETMAP_HW_RING) /* interpret ring as int */
			n = (uintptr_t)ring;
		else /* interpret ring as numeric string */
			n = ring ? atoi(ring) : ~0;
		n = (n < NETMAP_RING_MASK) ? (n | NETMAP_HW_RING) : 0;
		d->req.nr_ringid = n; /* set the ring */
	}
	d->req.nr_ringid |= (flags & ~NETMAP_RING_MASK);
	d->req.nr_version = NETMAP_API;
	strncpy(d->req.nr_name, dev, sizeof(d->req.nr_name));
	err = ioctl(d->fd, NIOCREGIF, &d->req);
	if (err)
		goto fail;

	d->memsize = d->req.nr_memsize;
	d->mem = mmap(0, d->memsize, PROT_WRITE | PROT_READ, MAP_SHARED,
	d->fd, 0);
	if (d->mem == NULL)
		goto fail;
	d->nifp = NETMAP_IF(d->mem, d->req.nr_offset);
	if (d->req.nr_ringid & NETMAP_SW_RING) {
		d->first_ring = d->last_ring = d->req.nr_rx_rings;
	} else if (d->req.nr_ringid & NETMAP_HW_RING) {
		d->first_ring = d->last_ring =
			d->req.nr_ringid & NETMAP_RING_MASK;
	} else {
		d->first_ring = 0;
		d->last_ring = d->req.nr_rx_rings - 1;
	}
	d->cur_ring = d->first_ring;
	for (n = d->first_ring; n <= d->last_ring; n++) {
		struct netmap_ring *ring = NETMAP_RXRING(d->nifp, n);
		ring->flags |= ring_flags;
	}
	return d;

fail:
	nm_close(d);
	return NULL;
}


static int
nm_close(struct nm_desc_t *d)
{
	if (d == NULL || d->self != d)
		return EINVAL;
	if (d->mem)
		munmap(d->mem, d->memsize);
	if (d->fd)
		close(d->fd);
	bzero(d, sizeof(*d));
	free(d);
	return 0;
}


/*
 * Same prototype as pcap_dispatch(), only need to cast.
 */
static int
nm_dispatch(struct nm_desc_t *d, int cnt, nm_cb_t cb, u_char *arg)
{
	int n = d->last_ring - d->first_ring + 1;
	int c, got = 0, ri = d->cur_ring;

	if (cnt == 0)
		cnt = -1;
	for (c=0; c < n; c++) {
		/* compute current ring to use */
		struct netmap_ring *ring;
		ri = d->cur_ring + c;

		if (ri > d->last_ring)
			ri -= n;
		ring = NETMAP_RXRING(d->nifp, ri);
		if (ring->avail == 0)
			continue;
		d->hdr.ts = ring->ts;
		while ((cnt == -1 || cnt != got) && ring->avail > 0) {
			u_int i = ring->cur;
			u_int idx = ring->slot[i].buf_idx;
			u_char *buf;

			if (idx < 2) {
				printf("%s bogus RX index %d at offset %d",
					d->nifp->ni_name, idx, i);
				sleep(2);
			}
			buf = (u_char *)NETMAP_BUF(ring, idx);
			// prefetch(buf);
			d->hdr.len = d->hdr.caplen = ring->slot[i].len;
			cb(arg, &d->hdr, buf);
			ring->cur = NETMAP_RING_NEXT(ring, i);
			ring->avail--;
			got++;
		}
	}
	d->cur_ring = ri;
	return got;
}
#endif /* !HAVE_NETMAP_WITH_LIBS */

#endif /* NETMAP_WITH_LIBS */

#endif /* _NET_NETMAP_USER_H_ */
