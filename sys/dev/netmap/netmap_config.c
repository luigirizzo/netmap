/*
 * Copyright (C) 2014 Giuseppe Lettieri. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *   1. Redistributions of source code must retain the above copyright
 *      notice, this list of conditions and the following disclaimer.
 *   2. Redistributions in binary form must reproduce the above copyright
 *      notice, this list of conditions and the following disclaimer in the
 *      documentation and/or other materials provided with the distribution.
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

/* $FreeBSD: readp/sys/dev/netmap/netmap_pipe.c 261909 2014-02-15 04:53:04Z luigi $ */

#if defined(__FreeBSD__)
#include <sys/cdefs.h> /* prerequisite */

#include <sys/types.h>
#include <sys/errno.h>
#include <sys/param.h>	/* defines used in kernel.h */
#include <sys/kernel.h>	/* types used in module initialization */
#include <sys/malloc.h>
#include <sys/poll.h>
#include <sys/lock.h>
#include <sys/rwlock.h>
#include <sys/selinfo.h>
#include <sys/sysctl.h>
#include <sys/socket.h> /* sockaddrs */
#include <net/if.h>
#include <net/if_var.h>
#include <machine/bus.h>	/* bus_dmamap_* */
#include <sys/refcount.h>
#include <sys/uio.h>
#include <machine/stdarg.h>


#elif defined(linux)

#include "bsd_glue.h"

#elif defined(__APPLE__)

#warning OSX support is only partial
#include "osx_glue.h"

#elif defined(_WIN32)

#include "win_glue.h"

#else

#error	Unsupported platform

#endif /* unsupported */

/*
 * common headers
 */

#include <net/netmap.h>
#include <dev/netmap/netmap_kern.h>
#include "jsonlr.h"

#ifdef WITH_NMCONF

#define NM_CBDATASIZ 1024
#define NM_CBDATAMAX 4

/* simple buffers for incoming/outgoing data on read()/write() */

struct nm_confb_data {
	struct nm_confb_data *chain;
	u_int size;
	char data[];
};

static void
nm_confb_trunc(struct nm_confb *cb)
{
	if (cb->writep)
		cb->writep->size = cb->next_w;
}

/* prepare for a write of req_size bytes;
 * returns a pointer to a buffer that can be used for writing,
 * or NULL if not enough space is available;
 * By passing in avl_size, the caller declares that it is
 * willing to accept a buffer with a smaller size than requested.
 */
static void*
nm_confb_pre_write(struct nm_confb *cb, u_int req_size, u_int *avl_size)
{
	struct nm_confb_data *d, *nd;
	u_int s = 0, b;
	void *ret;

	d = cb->writep;
	/* get the current available space */
	if (d)
		s = d->size - cb->next_w;
	if (s > 0 && (s >= req_size || avl_size)) {
		b = cb->next_w;
		goto out;
	}
	/* we need to expand the buffer, if possible */
	if (cb->n_data >= NM_CBDATAMAX)
		return NULL;
	s = NM_CBDATASIZ;
	if (req_size > s && avl_size == NULL)
		s = req_size;
	nd = nm_os_malloc(sizeof(*d) + s);
	if (nd == NULL)
		return NULL;
	nd->size = s;
	nd->chain = NULL;
	if (d) {
		/* the caller is not willing to do a short write
		 * and the available space in the current chunk
		 * is not big enough. Truncate the chunk and
		 * move to the next one.
		 */
		nm_confb_trunc(cb);
		d->chain = nd;
	}
	cb->n_data++;
	if (cb->readp == NULL) {
		/* this was the first chunk, 
		 * initialize all pointers
		 */
		cb->readp = cb->writep = nd;
	}
	d = nd;
	b = 0;
out:
	if (s > req_size)
		s = req_size;
	if (avl_size)
		*avl_size = s;
	ret = d->data + b;
	return ret;
}

static void
nm_confb_post_write(struct nm_confb *cb, u_int size)
{
	if (cb->next_w == cb->writep->size) {
		cb->writep = cb->writep->chain;
		cb->next_w = 0;
	}
	cb->next_w += size;

}

static int
nm_confb_vprintf(struct nm_confb *cb, const char *format, va_list ap)
{
	int rv;
        u_int size = 64, *psz = &size;
	void *p;
	va_list _ap;

	for (;;) {
		p = nm_confb_pre_write(cb, size, psz);
		if (p == NULL)
			return ENOMEM;
		va_copy(_ap, ap);
		rv = vsnprintf(p, size, format, _ap);
		va_end(_ap);
		if (rv < 0)
			return EINVAL;
		if (rv < size) {
			break;
		}
		D("rv %d size %u: retry", rv, size);
		size = rv + 1;
		psz = NULL;
	}
	nm_confb_post_write(cb, rv);
	return 0;
}

static int
nm_confb_printf(struct nm_confb *cb, const char *fmt, ...)
{
	va_list ap;
	int rv;

	va_start(ap, fmt);
	rv = nm_confb_vprintf(cb, fmt, ap);
	va_end(ap);

	return rv;
}

static int
nm_confb_iprintf(struct nm_confb *cb, int i, const char *fmt, ...)
{
	int j, rv = 0;
	va_list ap;

	for (j = 0; j < i; j++)	{
		rv = nm_confb_printf(cb, "    ");
		if (rv)
			return rv;
	}
	if (rv == 0) {
		va_start(ap, fmt);
		rv = nm_confb_vprintf(cb, fmt, ap);
		va_end(ap);
	}
	return rv;
}

/* prepare for a read of size bytes;
 * returns a pointer to a buffer which is at least size bytes big.
 * Note that, on return, size may be smaller than asked for;
 * if size is 0, no other bytes can be read.
 */
static void*
nm_confb_pre_read(struct nm_confb *cb, u_int *size)
{
	struct nm_confb_data *d;
	u_int n;

	d = cb->readp;
	n = cb->next_r;
	for (;;) {
		if (d == NULL) {
			*size = 0;
			return NULL;
		}
		if (d->size > n) {
			/* there is something left to read
			 * in this chunk
			 */
			u_int s = d->size - n;
			void *ret = d->data + n;
			if (*size < s)
				s = *size;
			else
				*size = s;
			return ret;
		}
		/* chunk exausted, move to the next one */
		d = d->chain;
		n = 0;
	}
}

static void
nm_confb_post_read(struct nm_confb *cb, u_int size)
{
	if (cb->next_r == cb->readp->size) {
		struct nm_confb_data *ocb = cb->readp;
		cb->readp = cb->readp->chain;
		cb->next_r = 0;
		nm_os_free(ocb);
		cb->n_data--;
	}
	cb->next_r += size;
}

static int
nm_confb_empty(struct nm_confb *cb)
{
	u_int sz = 1;
	return (nm_confb_pre_read(cb, &sz) == NULL);
}

struct nm_jp_stream {
	struct _jp_stream stream;
	struct nm_confb *cb;
};

static int
nm_confb_peek(struct _jp_stream *jp)
{
	struct nm_jp_stream *n = (struct nm_jp_stream *)jp;
	struct nm_confb *cb = n->cb;
	u_int s = 1;
	void *p = nm_confb_pre_read(cb, &s);
	if (p == NULL)
		return 0;
	return *(char *)p;
}

static void
nm_confb_consume(struct _jp_stream *jp)
{
	struct nm_jp_stream *n = (struct nm_jp_stream *)jp;
	struct nm_confb *cb = n->cb;
	nm_confb_post_read(cb, 1);
}

static void
nm_confb_destroy(struct nm_confb *cb)
{
	struct nm_confb_data *d = cb->readp;

	while (d) {
		struct nm_confb_data *nd = d->chain;
		nm_os_free(d);
		d = nd;
	}
	memset(cb, 0, sizeof(*cb));
}

static int nm_conf_dump_json(const char *pool, struct _jpo*,
		struct nm_confb *);
static int nm_conf_dump_flat(const char *pool, struct _jpo*,
		struct nm_confb *);
extern int nm_conf_flat_mode;
void
nm_conf_init(struct nm_conf *c)
{
	NM_MTX_INIT(c->mux);
	c->dump = (nm_conf_flat_mode ?
	           nm_conf_dump_flat :
		   nm_conf_dump_json);
}

const char *
nm_conf_get_output_mode(struct nm_conf *c)
{
	return (c->dump == nm_conf_dump_json ? "json" :
	       (c->dump == nm_conf_dump_flat ? "flat" :
		"unknown"));
}

int
nm_conf_set_output_mode(struct nm_conf *c, const char *mode)
{
	if (strcmp(mode, "json") == 0) {
		c->dump = nm_conf_dump_json;
	} else if (strcmp(mode, "flat") == 0) {
		c->dump = nm_conf_dump_flat;
	} else {
		return EINVAL;
	}
	return 0;
}

void
nm_conf_uninit(struct nm_conf *c, int locked)
{
	int i;
	
	for (i = 0; i < 2; i++)
		nm_confb_destroy(c->buf + i);
	NM_MTX_DESTROY(c->mux);
}

static int
nm_conf_dump_json_rec(const char *pool, struct _jpo *r,
		struct nm_confb *out, int ind, int cont)
{
	int i, error = 0;
again:
	switch (r->ty) {
	case JPO_NUM:
		return nm_confb_iprintf(out, (cont ? 0 : ind),
				"%ld", jslr_get_num(pool, *r));
		break;
	case JPO_STRING:
		return nm_confb_iprintf(out, (cont ? 0 : ind),
				"\"%s\"", jslr_get_string(pool, *r));
		break;
	case JPO_ARRAY:
		error = nm_confb_iprintf(out, (cont ? 0 : ind), "[");
		for (i = 0; !error && i < r->len; i++) {
			if (i)
				error = nm_confb_printf(out, ",");
			if (!error)
				error = nm_confb_printf(out, "\n");
			if (!error)
				error = nm_conf_dump_json_rec(pool, r + 1 + i,
					out, ind + 1, 0);
		}
		if (!error)
			error = nm_confb_printf(out, "\n");
		if (!error)
			error = nm_confb_iprintf(out, ind, "]");
		break;
	case JPO_OBJECT:
		error = nm_confb_iprintf(out, (cont ? 0: ind), "{");
		for (i = 0; !error && (i < 2 * r->len); i += 2) {
			if (i)
				error = nm_confb_printf(out, ",");
			if (!error)
				error = nm_confb_printf(out, "\n");
			if (!error)
				error = nm_confb_iprintf(out, ind + 1,
					"\"%s\": ",
					jslr_get_string(pool, *(r + 1 + i)));
			if (!error)
				error = nm_conf_dump_json_rec(pool, r + 2 + i,
					out, ind + 1, 1);
		}
		if (!error)
			error = nm_confb_printf(out, "\n");
		if (!error)
			nm_confb_iprintf(out, ind, "}");
		break;
	case JPO_PTR:
		switch (r->len) {
		case JPO_ARRAY:
			r = jslr_get_array(pool, *r);
			break;
		case JPO_OBJECT:
			r = jslr_get_object(pool, *r);
			break;
		default:
			return EINVAL;
		}
		goto again;
	default:
		error = EINVAL;
		break;
	}
	return error;
}

static int
nm_conf_dump_json(const char *pool, struct _jpo* r,
		struct nm_confb *cb)
{
	int error;

	error = nm_conf_dump_json_rec(pool, r, cb, 0, 0);
	if (error)
		return error;
	nm_confb_printf(cb, "\n");
	return 0;
}

struct nm_flat_prefix {
	char *base;
	char *append;
	size_t avail;
};

static int
nm_flat_prefix_append(struct nm_flat_prefix *st, const char *fmt, ...)
{
	int n;
	va_list ap;

	va_start(ap, fmt);
	n = vsnprintf(st->append, st->avail, fmt, ap);
	va_end(ap);
	if (n < 0 || n >= st->avail)
		return ENOMEM;
	st->append += n;
	st->avail -= n;
	return 0;
}

static int
nm_conf_dump_flat_rec(const char *pool, struct _jpo *r,
		struct nm_confb *out, const struct nm_flat_prefix *st)
{
	int i, error = 0;
	struct nm_flat_prefix lst;
again:
	switch (r->ty) {
	case JPO_NUM:
		return nm_confb_printf(out, "%s: %ld\n",
				st->base, jslr_get_num(pool, *r));
		break;
	case JPO_STRING:
		return nm_confb_printf(out, "%s: \"%s\"\n",
				st->base, jslr_get_string(pool, *r));
		break;
	case JPO_ARRAY:
		for (i = 0; !error && i < r->len; i++) {
			lst = *st;
			error = nm_flat_prefix_append(&lst, ".%d", i);
			if (!error)
				error = nm_conf_dump_flat_rec(pool, r + 1 + i,
					out, &lst);
		}
		break;
	case JPO_OBJECT:
		for (i = 0; !error && (i < 2 * r->len); i += 2) {
			lst = *st;
			error = nm_flat_prefix_append(&lst, ".%s",
					jslr_get_string(pool, *(r + 1 + i)));
			if (!error)
				error = nm_conf_dump_flat_rec(pool, r + 2 + i,
					out, &lst);
		}
		break;
	case JPO_PTR:
		switch (r->len) {
		case JPO_ARRAY:
			r = jslr_get_array(pool, *r);
			break;
		case JPO_OBJECT:
			r = jslr_get_object(pool, *r);
			break;
		default:
			return EINVAL;
		}
		goto again;
	default:
		error = EINVAL;
		break;
	}
	return error;
}

static int
nm_conf_dump_flat(const char *pool, struct _jpo *r,
		struct nm_confb *cb)
{
	char buf[128];
	struct nm_flat_prefix lst = {
		.base = buf,
		.append = buf,
		.avail = 128
	};

	return nm_conf_dump_flat_rec(pool, r, cb, &lst);
}

#define NETMAP_CONFIG_POOL_SIZE (1<<12)
int
nm_conf_parse(struct nm_conf *c, int locked)
{
	uint32_t pool_len = NETMAP_CONFIG_POOL_SIZE;
	struct nm_confb *i = &c->buf[0],
			      *o = &c->buf[1];
	struct nm_jp_stream njs = {
		.stream = {
			.peek = nm_confb_peek,
			.consume = nm_confb_consume,
		},
		.cb = i,
	};
	struct _jpo r;
	int error = 0;

	nm_confb_trunc(i);
	if (nm_confb_empty(i))
		return 0;

	c->pool = nm_os_malloc(pool_len);
	if (c->pool == NULL)
		return ENOMEM;
	r = jslr_parse(&njs.stream, c->pool, pool_len);
	if (r.ty == JPO_ERR) {
		D("parse error: %d", r.ptr);
		nm_confb_destroy(i);
		goto out;
	}

	c->dump(c->pool, &r, o);

	nm_confb_trunc(o);
out:
	nm_os_free(c->pool);
	c->pool = NULL;
	return error;
}

int
nm_conf_write(struct nm_conf *c, struct uio *uio)
{
	int ret = 0;
	struct nm_confb *i = &c->buf[0],
		        *o = &c->buf[1];

	NM_MTX_LOCK(c->mux);

	nm_confb_destroy(o);

	while (uio->uio_resid > 0) {
		int s = uio->uio_resid;
		void *p = nm_confb_pre_write(i, s, &s);
		if (p == NULL) {
			ND("NULL p from confbuf_pre_write");
			ret = ENOMEM;
			goto out;
		}
		D("s %d", s);
		ret = uiomove(p, s, uio);
		if (ret)
			goto out;
		nm_confb_post_write(i, s);
	}

out:
	NM_MTX_UNLOCK(c->mux);
	return ret;
}

int
nm_conf_read(struct nm_conf *c, struct uio *uio)
{
	int ret = 0;
	struct nm_confb *o = &c->buf[1];

	NM_MTX_LOCK(c->mux);

	D("");
	ret = nm_conf_parse(c, 0 /* not locked */);
	if (ret)
		goto out;

	while (uio->uio_resid > 0) {
		int s = uio->uio_resid;
		void *p = nm_confb_pre_read(o, &s);
		if (p == NULL) {
			goto out;
		}
		ret = uiomove(p, s, uio);
		if (ret)
			goto out;
		nm_confb_post_read(o, s);
	}

out:
	NM_MTX_UNLOCK(c->mux);

	return ret;
}
#endif /* WITH_NMCONF */
