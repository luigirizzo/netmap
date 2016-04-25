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
	
	(void)nm_conf_parse(c, locked);
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

static struct _jpo nm_jp_interp(struct nm_jp *,
		struct _jpo, struct nm_conf *c);

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
	D("parse OK: ty %u len %u ptr %u", r.ty, r.len, r.ptr);
	if (!locked)
		NMG_LOCK();
	r = nm_jp_interp(&nm_jp_root.up, r, c);
	if (!locked)
		NMG_UNLOCK();
	error = c->dump(c->pool, &r, o);
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
		ND("s %d", s);
		ret = uiomove(p, s, uio);
		if (ret)
			goto out;
		nm_confb_post_write(i, s);
		c->written = 1;
	}

out:
	NM_MTX_UNLOCK(c->mux);
	return ret;
}

int
nm_conf_read(struct nm_conf *c, struct uio *uio)
{
	int ret = 0;
	struct nm_confb *i = &c->buf[0],
			      *o = &c->buf[1];

	NM_MTX_LOCK(c->mux);

	if (!c->written) {
		nm_confb_printf(i, "dump");
		c->written = 1;
	}

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


struct _jpo
nm_jp_error(char *pool, const char *format, ...)
{
	va_list ap;
	struct _jpo r, *o;
#define NM_INTERP_ERRSIZE 128
	char buf[NM_INTERP_ERRSIZE + 1];
	int rv;

	r = jslr_new_object(pool, 1);
	if (r.ty == JPO_ERR)
		return r;
	o = jslr_get_object(pool, r);
	o++;
	*o = jslr_new_string(pool, "err");
	if (o->ty == JPO_ERR)
		return *o;
	o++;
	va_start(ap, format);
	rv = vsnprintf(buf, NM_INTERP_ERRSIZE, format, ap);
	va_end(ap);
	if (rv < 0 || rv >= NM_INTERP_ERRSIZE)
		return (struct _jpo) {.ty = JPO_ERR};
	*o = jslr_new_string(pool, buf);
	if (o->ty == JPO_ERR)
		return *o;
	return r;
#undef	NM_INTERP_ERRSIZE
}

static int
nm_jp_streq(struct _jpo r, char *pool, const char *str1)
{
	const char *str;

	if (r.ty != JPO_STRING)
		return 0;

	str = jslr_get_string(pool, r);
	return (strcmp(str1, str) == 0);
}

static int
nm_jp_is_dump(struct _jpo r, char *pool)
{
	return nm_jp_streq(r, pool, "dump");
}

static void
nm_jp_bracket(struct nm_jp *jp, int stage, struct nm_conf *c)
{
	if (jp->bracket)
		jp->bracket(jp, stage, c);
}

static struct _jpo
nm_jp_interp(struct nm_jp *jp, struct _jpo r, struct nm_conf *c)
{
	nm_jp_bracket(jp, 0, c);
	if (nm_jp_is_dump(r, c->pool) || jp->interp == NULL) {
		r = jp->dump(jp, c);
	} else {
		r = jp->interp(jp, r, c);
	}
	nm_jp_bracket(jp, 2, c);
	return r;
}

static struct _jpo
nm_jp_dump(struct nm_jp *jp, struct nm_conf *c)
{
	struct _jpo r;

	nm_jp_bracket(jp, 0, c);
	r = jp->dump(jp, c);
	nm_jp_bracket(jp, 2, c);
	return r;
}

static struct _jpo
nm_jp_ddelete(struct nm_jp_dict *d, struct nm_jp_delem *e,
		char *pool)
{
	if (d->delete == NULL)
		return nm_jp_error(pool, "'delete' not supported");
	if (!e->have_ref)
		return nm_jp_error(pool, "busy");
	d->delete(e->jp);
	e->have_ref = 0;
	return jslr_new_object(pool, 0);
}

static struct nm_jp_delem *
nm_jp_dsearch(struct nm_jp_dict *d, const char *name);

static struct _jpo
nm_jp_dnew(struct nm_jp_dict *d, struct _jpo *pn, struct nm_conf *c)
{
	struct nm_jp_delem *e = NULL;
	struct nm_jp *jp;
	struct _jpo o;
	int error;

	if (d->new == NULL) {
		o = nm_jp_error(c->pool, "not supported");
		goto out;
	}
	e = nm_jp_dnew_elem(d);
	if (e == NULL) {
		o = nm_jp_error(c->pool, "out of memory");
		goto out;
	}
	error = d->new(e);
	if (error || e->jp == NULL) {
		o = nm_jp_error(c->pool, "error: %d", error);
		goto out;
	}
	*pn++ = jslr_new_string(c->pool, e->name);
	jp = e->jp;
	nm_jp_bracket(jp, 0, c);
	if (jp->interp) {
		o = jp->interp(jp, *pn, c);
		if (o.ty == JPO_ERR)
			goto leave_;
		nm_jp_bracket(jp, 1, c);
	}
	o = jp->dump(jp, c);
leave_:
	nm_jp_bracket(jp, 2, c);
	e->have_ref = 1;
out:
	return o;
}



static struct _jpo
nm_jp_dinterp(struct nm_jp *jp, struct _jpo r, struct nm_conf *c)
{
	struct _jpo *po;
	int i, len, ty = r.len;
	struct nm_jp_dict *d = (struct nm_jp_dict *)jp;
	char *pool = c->pool;

	if (r.ty != JPO_PTR || ty != JPO_OBJECT) {
		r = nm_jp_error(pool, "need object");
		goto out;
	}

	po = jslr_get_object(c->pool, r);
	if (po == NULL || po->ty != ty) {
		r = nm_jp_error(pool, "internal error");
		goto out;
	}

	len = po->len;
	po++;
	for (i = 0; i < len; i++) {
		struct _jpo r1;
		const char *name = jslr_get_string(pool, *po);
		struct nm_jp_delem *e;

		if (name == NULL) {
			r = nm_jp_error(pool, "internal error");
			goto out;
		}
		if (strcmp(name, "new") == 0) {
			r1 = nm_jp_dnew(d, po, c);
			po++;
			goto next;
		}
		e = nm_jp_dsearch(d, name);
		if (e == NULL) {
			po++;
			r1 = nm_jp_error(pool, "%s: not found", name);
			goto next;
		}
		po++;
		D("found %s", name);
		if (nm_jp_streq(*po, pool, "delete")) {
			r1 = nm_jp_ddelete(d, e, pool);
			goto next;
		}
		r1 = nm_jp_interp(e->jp, *po, c);
	next:
		*po++ = r1;
	}

out:
	return r;
}

static struct _jpo
nm_jp_ddump(struct nm_jp *jp, struct nm_conf *c)
{
	struct _jpo *po, r;
	struct nm_jp_dict *d = (struct nm_jp_dict *)jp;
	int i, len = d->nextfree;
	char *pool = c->pool;

	r = jslr_new_object(pool, len);
	if (r.ty == JPO_ERR)
		return r;
	po = jslr_get_object(pool, r);
	po++;
	for (i = 0; i < len; i++) {
		struct nm_jp_delem *e = &d->list[i];
		*po = jslr_new_string(pool, e->name);
		if (po->ty == JPO_ERR)
			return *po;
		po++;
		*po = nm_jp_dump(e->jp, c);
		if (po->ty == JPO_ERR)
			return *po;
		po++;
	}
	return r;
}

int
nm_jp_dinit(struct nm_jp_dict *d, struct nm_jp_delem *list, u_int nelem,
		void (*bracket)(struct nm_jp *, int, struct nm_conf *))
{

	d->up.interp = nm_jp_dinterp;
	d->up.dump   = nm_jp_ddump;
	d->up.bracket = bracket;
	d->minelem = nelem;
	d->list = nm_os_malloc(sizeof(*d->list) * nelem);
	if (d->list == NULL)
		return ENOMEM;
	d->nelem = nelem;
	if (list) {
		u_int i;
		for (i = 0; i < nelem; i++)
			d->list[i] = list[i];
		d->nextfree = nelem;
	} else {
		d->nextfree = 0;
	}
	return 0;
}

void
nm_jp_duninit(struct nm_jp_dict *d)
{
	nm_os_free(d->list);
	memset(d, 0, sizeof(*d));
}

struct nm_jp_delem *
nm_jp_dnew_elem(struct nm_jp_dict *d)
{
	struct nm_jp_delem *newlist;

	if (d->nextfree >= d->nelem) {
		u_int newnelem = d->nelem * 2;
		newlist = nm_os_realloc(d->list, sizeof(*d->list) * newnelem,
				sizeof(*d->list) * d->nelem);
		if (newlist == NULL)
			return NULL;
		d->list = newlist;
		d->nelem = newnelem;
	}
	return &d->list[d->nextfree++];
}

static int
nm_jp_delem_vfill(struct nm_jp_delem *e,
		struct nm_jp *jp,
		const char *fmt, va_list ap)
{
	int n;

	e->jp = jp;
	n = vsnprintf(e->name, NETMAP_CONFIG_MAXNAME, fmt, ap);

	if (n >= NETMAP_CONFIG_MAXNAME)
		return ENAMETOOLONG;

	return 0;
}

int
nm_jp_delem_fill(struct nm_jp_delem *e,
		struct nm_jp *jp,
		const char *fmt, ...)
{
	va_list ap;
	int rv;

	va_start(ap, fmt);
	rv = nm_jp_delem_vfill(e, jp, fmt, ap);
	va_end(ap);

	return rv;
}

int nm_jp_dadd(struct nm_jp_dict *d,
		struct nm_jp *jp,
		const char *fmt, ...)
{
	struct nm_jp_delem *e;
	va_list ap;
	int rv;

	e = nm_jp_dnew_elem(d);
	if (e == NULL) {
		return ENOMEM;
	}
	va_start(ap, fmt);
	rv = nm_jp_delem_vfill(e, jp, fmt, ap);
	va_end(ap);

	return rv;
}


static int
_nm_jp_ddel(struct nm_jp_dict *d, struct nm_jp_delem *e1)
{
	struct nm_jp_delem *e2;

	d->nextfree--;
	e2 = &d->list[d->nextfree];
	if (e1 != e2) {
		strncpy(e1->name, e2->name, NETMAP_CONFIG_MAXNAME);
		e1->jp = e2->jp;
	}
	memset(e2, 0, sizeof(*e2));
	if (d->nelem > d->minelem && d->nextfree < d->nelem / 2) {
		struct nm_jp_delem *newlist;
		u_int newnelem = d->nelem / 2;
		if (newnelem < d->minelem)
			newnelem = d->minelem;
		newlist = nm_os_realloc(d->list, sizeof(*d->list) * newnelem,
				sizeof(*d->list) * d->nelem);
		if (newlist == NULL) {
			D("out of memory when trying to release memory?");
			return 0; /* not fatal */
		}
		d->list = newlist;
		d->nelem = newnelem;
	}
	return 0;
}

static struct nm_jp_delem *
_nm_jp_dfind(struct nm_jp_dict *d, struct nm_jp *jp)
{
	struct nm_jp_delem *e;

	for (e = d->list; e != d->list + d->nextfree; e++)
		if (e->jp == jp)
			return e;
	return NULL;
}

int
nm_jp_ddel(struct nm_jp_dict *d, struct nm_jp *jp)
{
	struct nm_jp_delem *e = _nm_jp_dfind(d, jp);

	if (e == NULL)
		return ENOENT;

	return _nm_jp_ddel(d, e);
}

int
nm_jp_drename(struct nm_jp_dict *d, struct nm_jp *jp, const char *name)
{
	struct nm_jp_delem *e = _nm_jp_dfind(d, jp);

	if (e == NULL)
		return ENOENT;

	return nm_jp_delem_fill(e, e->jp, "%s", name);
}


static struct nm_jp_delem *
nm_jp_dsearch(struct nm_jp_dict *d, const char *name)
{
	int i;
	for (i = 0; i < d->nextfree; i++) {
		struct nm_jp_delem *e = &d->list[i];
		if (strncmp(name, e->name, NETMAP_CONFIG_MAXNAME) == 0)
			break;
	}
	if (i == d->nextfree)
		return NULL;
	return &d->list[i];
}

static int64_t
nm_jp_ngetvar(struct nm_jp_num *in, void *cur_obj)
{
	void *base;
	if (in->size & NM_JP_NUM_REL)
		base = cur_obj + (size_t)in->var;
	else
		base = in->var;

	switch (in->size & NM_JP_NUM_SZMSK) {
	case 0:
		return ((nm_jp_nreader)base)(in);
	case 1:
		return *(int8_t*)base;
	case 2:
		return *(int16_t*)base;
	case 4:
		return *(int32_t*)base;
	case 8:
		return *(int64_t*)base;
	default:
		D("unsupported size %zd", in->size);
		return 0;
	}
}

int
nm_jp_nupdate(struct nm_jp_num *in, int64_t v, void *cur_obj)
{
	void *base;
	if (in->size & NM_JP_NUM_REL)
		base = cur_obj + (size_t)in->var;
	else
		base = in->var;

	switch (in->size & NM_JP_NUM_SZMSK) {
	case 1:
		*(int8_t*)base = (int8_t)v;
		break;
	case 2:
		*(int16_t*)base = (int16_t)v;
		break;
	case 4:
		*(int32_t*)base = (int32_t)v;
		break;
	case 8:
		*(int64_t*)base = (int64_t)v;
		break;
	default:
		return EINVAL;
	}
	return 0;
}

struct _jpo
nm_jp_ninterp(struct nm_jp *jp, struct _jpo r, struct nm_conf *c)
{
	int64_t v, nv;
	struct nm_jp_num *in = (struct nm_jp_num *)jp;
	int error;
	char *pool = c->pool;

	if (r.ty != JPO_NUM) {
		r = nm_jp_error(pool, "need number");
		goto done;
	}

	nv = jslr_get_num(pool, r);
	v = nm_jp_ngetvar(in, c->cur_obj);
	if (v == nv)
		goto done;
	if (in->update == NULL) {
		r = nm_jp_error(pool, "read-only");
		goto done;
	}
	error = in->update(in, nv, c->cur_obj);
	if (error)
		r = nm_jp_error(pool, "invalid; %ld", nv);
	r = jp->dump(jp, c);
done:
	return r;
}

struct _jpo
nm_jp_ndump(struct nm_jp *jp, struct nm_conf *c)
{
	struct nm_jp_num *in = (struct nm_jp_num*)jp;
	int64_t v = nm_jp_ngetvar(in, c->cur_obj);

	return jslr_new_num(c->pool, v);
}

void
nm_jp_ninit(struct nm_jp_num *in, void *var, size_t size,
		int (*update)(struct nm_jp_num *, int64_t, void *))
{
	in->up.interp = nm_jp_ninterp;
	in->up.dump   = nm_jp_ndump;
	in->var = var;
	in->size = size;
	in->update = update;
}

static void *
nm_jp_pnewcurobj(struct nm_jp_ptr *p, void *cur_obj)
{
	void *obj;

	if (p->flags & NM_JP_PTR_REL)
		obj = cur_obj + (size_t)p->arg;
	else
		obj = p->arg;
	if (p->flags & NM_JP_PTR_IND) {
		obj = *(void **)obj;
	}
	return obj;
}

struct _jpo
nm_jp_pinterp(struct nm_jp *jp, struct _jpo r, struct nm_conf *c)
{
	struct nm_jp_ptr *p = (struct nm_jp_ptr *)jp;
	void *save = c->cur_obj;
	struct _jpo rv;

	c->cur_obj = nm_jp_pnewcurobj(p, save);
	rv = nm_jp_interp(p->type, r, c);
	c->cur_obj = save;
	return rv;
}

struct _jpo
nm_jp_pdump(struct nm_jp *jp, struct nm_conf *c)
{
	struct nm_jp_ptr *p = (struct nm_jp_ptr *)jp;
	void *save = c->cur_obj;
	struct _jpo rv;

	c->cur_obj = nm_jp_pnewcurobj(p, save);
	rv = nm_jp_dump(p->type, c);
	c->cur_obj = save;
	return rv;
}

void
nm_jp_pinit(struct nm_jp_ptr *p, struct nm_jp *type,
		void *arg, u_int flags)
{
	p->up.interp  = nm_jp_pinterp;
	p->up.dump    = nm_jp_pdump;
	p->up.bracket = NULL;
	p->type = type;
	p->arg = arg;
	p->flags = flags;
}


#endif /* WITH_NMCONF */
