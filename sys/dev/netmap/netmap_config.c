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

#define NM_CBDATASIZ 4096
#define NM_CBDATAMAX 1024

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
		ND("writing: '%s'", (char *)p);
		va_end(_ap);
		if (rv < 0)
			return EINVAL;
		if (rv < size) {
			break;
		}
		ND("rv %d size %u: retry", rv, size);
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
		D("Unknown JPO: (%u, %u, %u)", r->ty, r->len, r->ptr);
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

#define NETMAP_CONFIG_POOL_SIZE JSLR_MAXSIZE

static struct _jpo nm_jp_interp(struct nm_jp *,
		struct _jpo, struct nm_conf *c);

int
nm_conf_parse(struct nm_conf *c, int locked)
{
	uint32_t pool_len = NETMAP_CONFIG_POOL_SIZE;
	struct nm_confb *i = &c->buf[0], *o = &c->buf[1];
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
	ND("parse OK: ty %u len %u ptr %u", r.ty, r.len, r.ptr);
	if (!locked)
		NMG_LOCK();
	r = nm_jp_interp(&nm_jp_root.up, r, c);
	if (!locked)
		NMG_UNLOCK();
	error = c->dump(c->pool, &r, o);
	ND("error %d", error);
	nm_confb_trunc(o);

out:
	nm_os_free(c->pool);
	c->pool = NULL;
	nm_os_free(c->vars);
	c->max_vars = c->next_var = 0;
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
		nm_confb_printf(i, "?");
		c->written = 1;
	}

	ret = nm_conf_parse(c, 0 /* not locked */);
	if (ret) {
		D("parse error!");
		goto out;
	}

	while (uio->uio_resid > 0) {
		int s = uio->uio_resid;
		void *p = nm_confb_pre_read(o, &s);
		if (p == NULL) {
			goto out;
		}
		ret = uiomove(p, s, uio);
		if (ret) {
			D("uiomove error!");
			goto out;
		}
		nm_confb_post_read(o, s);
	}

out:
	NM_MTX_UNLOCK(c->mux);

	return ret;
}

static struct nm_conf_var *
nm_conf_var_search(struct nm_conf *c, const char *name)
{
	int i;

	for (i = 0; i < c->next_var; i++) {
		struct nm_conf_var *v = &c->vars[i];
		ND("comparing '%s' with '%s'", v->name, name);
		if (strncmp(v->name, name, NETMAP_CONFIG_MAXNAME) == 0)
			return v;
	}
	return NULL;
}

static struct nm_conf_var *
nm_conf_var_create(struct nm_conf *c, const char *name)
{
	struct nm_conf_var *v = NULL;

	if (c->next_var >= c->max_vars) {
		struct nm_conf_var *nv =
			nm_os_realloc(c->vars, 2*c->max_vars + 1, c->max_vars);
		if (nv == NULL)
			return NULL;
		c->vars = nv;
	}
	v = &c->vars[c->next_var];
	c->next_var++;
	strncpy(v->name, name, NETMAP_CONFIG_MAXNAME);
	return v;
}

#if 0
static struct nm_conf_var *
nm_conf_var_get(struct nm_conf *c, const char *name)
{
	struct nm_conf_var *v = nm_conf_var_search(c, name);

	if (v == NULL)
		v = nm_conf_var_create(c, name);

	return v;
}
#endif

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

static char *
nm_jp_getstr(struct _jpo r, const char *pool)
{
	if (r.ty != JPO_STRING)
		return NULL;

	return jslr_get_string(pool, r);
}

#if 0
static int
nm_jp_streq(struct _jpo r, const char *pool, const char *str1)
{
	const char *str = nm_jp_getstr(r, pool);
	if (str == NULL)
		return 0;
	return (strcmp(str1, str) == 0);
}
#endif

static void
nm_jp_bracket(struct nm_jp *jp, int stage, struct nm_conf *c)
{
	if (jp->bracket)
		jp->bracket(jp, stage, c);
}

static int
nm_jp_parse_var(struct _jpo *r, struct nm_conf *c, struct nm_conf_var **v)
{
	char *str = nm_jp_getstr(*r, c->pool);
	int vcmd = 0;

	if (str == NULL || (str[0] != '?' && str[0] != '$'))
		return 0;

	vcmd = *str++;
	*v = nm_conf_var_search(c, str);

	switch (vcmd) {
	case '?':
		if (*v == NULL) {
			*v = nm_conf_var_create(c, str);
			if (*v == NULL) {
				*r = nm_jp_error(c->pool, "out of variables");
				return -1;
			}
		}
		break;
	case '$':
		if (*v == NULL) {
			*r = nm_jp_error(c->pool, "not found: '%s'", str);
			return -1;
		}
		*r = (*v)->value;
		break;
	}
	return vcmd;
}

static struct _jpo
nm_jp_dump(struct nm_jp *jp, struct nm_conf *c)
{
	struct _jpo rv;
	struct nm_conf_var *v;
	int vcmd = nm_jp_parse_var(&rv, c, &v);

	if (vcmd < 0)
		return rv;

	nm_jp_bracket(jp, NM_JPB_ENTER, c);
	rv = jp->dump(jp, c);
	nm_jp_bracket(jp, NM_JPB_LEAVE, c);

	if (vcmd == '?')
		v->value = rv;

	return rv;
}

static struct _jpo
nm_jp_interp(struct nm_jp *jp, struct _jpo r, struct nm_conf *c)
{
	struct _jpo rv;
	struct nm_conf_var *v;
	int vcmd = nm_jp_parse_var(&r, c, &v);

	if (vcmd < 0)
		return r;

	nm_jp_bracket(jp, NM_JPB_ENTER, c);
	if (vcmd == '?' || jp->interp == NULL)
		rv = jp->dump(jp, c);
	else
		rv = jp->interp(jp, r, c);
	nm_jp_bracket(jp, NM_JPB_LEAVE, c);

	if (vcmd == '?')
		v->value = rv;
	
	return rv;
}

static int
nm_jp_lgetcmd(char *pool, struct _jpo r, struct _jpo *arg)
{
	struct _jpo *cmd = jslr_get_object(pool, r);
	const char *s;

	if (cmd  == NULL || cmd->len != 1)
		return -1;

	cmd++;
	s = jslr_get_string(pool, *cmd);
	*arg = *cmd;
	if (!strcmp(s, "+") && !strcmp(s, "-"))
		return -1;
	return s[0];
}

struct _jpo
nm_jp_linterp(struct nm_jp *jp, struct _jpo r, struct nm_conf *c)
{
	struct _jpo *pi, *po, ro, *err, r1;
	int i, j = 0, len, ty = r.len;
	struct nm_jp_list *l = (struct nm_jp_list *)jp;
	char *pool = c->pool;
	struct nm_jp *jpe = NULL;
	struct nm_jp_liter it, *save = c->cur_iter;

	if (r.ty != JPO_PTR || (ty != JPO_ARRAY && ty != JPO_OBJECT) ) {
		ro = nm_jp_error(pool, "need array or object");
		if (c->matching)
			c->mismatch = 1;
		goto out;
	}

	if (ty == JPO_ARRAY) {
		pi = jslr_get_array(pool, r);
		if (pi == NULL || pi->ty != ty) {
			ro = nm_jp_error(pool, "internal error");
			goto out;
		}

		len = pi->len;
		pi++;
	} else {
		len = 1;
		pi = &r;
	}

	ro = jslr_new_array(pool, len);
	if (ro.ty == JPO_ERR) {
		ND("len %d, creation failed", len);
		goto out;
	}
	po = jslr_get_array(pool, ro);

	po++; /* move to first entry */
	err = NULL;
	nm_jp_liter_beg(&it);
	for (i = 0; i < len; i++) {
		struct nm_jp_liter stop, last;
		struct _jpo arg, search = *pi;
		int cmd;

		if (err) {
			r1 = *err;
			goto next;
		}

		cmd = nm_jp_lgetcmd(c->pool, *pi, &arg);
		D("cmd %d", cmd);
		switch (cmd) {
		case '+':
			if (l->insert == NULL) {
				r1 = nm_jp_error(c->pool, "insert not supported");
				goto next;
			}
			r1 = l->insert(l, &it, arg, c);
			nm_jp_liter_beg(&it);
			goto next;
		case '-':
			if (l->remove == NULL) {
				r1 = nm_jp_error(c->pool, "remove not supported");
				goto next;
			}
			search = arg;
			break;
		default:
			break;
		}

		for (stop = it, last = it, jpe = l->next(l, &it, c);
		     !nm_jp_liter_eq(&it, &stop);
		     last = it, jpe = l->next(l, &it, c))
		{
			D("jpe %p", jpe);
			if (jpe) {
				c->matching++;
				c->mismatch = 0;
				c->cur_iter = &it;
				r1 = nm_jp_interp(jpe, search, c);
				c->matching--;
				if (!c->mismatch) {
					D("match!");
					if (cmd == '-') {
						r1 = l->remove(l, &it, c);
						nm_jp_liter_beg(&it);
					} else {
						r1 = nm_jp_interp(jpe, search, c);
					}
					goto next;
				}
			}

			if (nm_jp_liter_is_end(&it)) {
				D("reached end");
				if (jpe == NULL) {
					D("should be empty");
					r1 = nm_jp_error(pool, "empty list");
					err = &r1;
					goto next;
				}
				/* restart and continue */
				D("restarting search from beginning");
				continue;
			}

		}
		r1 = nm_jp_error(pool, "no match");
		if (c->matching) {
			c->mismatch = 1;
			err = &r1;
		}
	next:
		*po++ = r1; pi++; /* move to next entry */
	}

out:
	if (j > l->n)
		l->n = j;
	c->cur_iter = save;
	return ro;
}

struct _jpo
nm_jp_ldump(struct nm_jp *jp, struct nm_conf *c)
{
	char *pool = c->pool;
	struct _jpo *po, r;
	struct nm_jp_list *l = (struct nm_jp_list *)jp;
	struct nm_jp *jpe;
	int j;
	struct nm_jp_liter it, *save;

	r = jslr_new_array(pool, l->n);
	if (r.ty == JPO_ERR)
		return r;
	po = jslr_get_array(pool, r);
	po++;
	nm_jp_liter_beg(&it);
	save = c->cur_iter;
	for (j = 0; (jpe = l->next(l, &it, c)) ; j++) {
		D("j %d", j);
		if (j >= l->n) {
			l->n = j + 1;
			r = jslr_realloc_array(pool, r, l->n);
			if (r.ty == JPO_ERR)
				return r;
			po = jslr_get_array(pool, r);
			po += j + 1;
		}
		c->cur_iter = &it;
		*po++ = nm_jp_dump(jpe, c);
	}
	l->n = j;
	jslr_realloc_array(pool, r, l->n);
	c->cur_iter = save;
	return r;
}

void
nm_jp_linit(struct nm_jp_list *l, int n,
		struct nm_jp *(*next)(struct nm_jp_list *,
			struct nm_jp_liter *i, struct nm_conf *),
		void (*bracket)(struct nm_jp *, int, struct nm_conf *))
{
	l->up.interp = nm_jp_linterp;
	l->up.dump = nm_jp_ldump;
	l->up.bracket = bracket;

	l->n = n;
	l->next = next;
}

void
nm_jp_oluninit(struct nm_jp_olist *l)
{
	nm_os_free(l->list);
	memset(l, 0, sizeof(*l));
}

struct nm_jp *
nm_jp_olnext(struct nm_jp_list *l, struct nm_jp_liter *it, struct nm_conf *c)
{
	struct nm_jp_olist *ol = (struct nm_jp_olist *)l;
	union nm_jp_union **e = (union nm_jp_union **)&it->it;
	struct nm_jp *rv;
	
	if (ol->nextfree == 0) {
		nm_jp_liter_end(it);
	}

	if (nm_jp_liter_is_end(it)) {
		nm_jp_liter_beg(it);
		return NULL;
	}

	if (nm_jp_liter_is_beg(it)) {
		*e = ol->list;
	}

	rv = (struct nm_jp *)*e;

	if (*e == ol->list + ol->nextfree - 1) {
		nm_jp_liter_end(it);
	} else {
		(*e)++;
	}

	return rv;
}

int
nm_jp_olinit(struct nm_jp_olist *l, int n, void (*bracket)(struct nm_jp *, int, struct nm_conf *))
{
	nm_jp_linit(&l->up, n, nm_jp_olnext, bracket);

	l->list = nm_os_malloc(sizeof(*l->list) * n);
	if (l->list == NULL)
		return ENOMEM;
	l->minelem = l->nelem = n;
	l->nextfree = 0;
	return 0;
}

union nm_jp_union *
nm_jp_olnew_elem(struct nm_jp_olist *l)
{
	/* possibly make more room */
	if (l->nextfree >= l->nelem) {
		u_int newnelem = l->nelem * 2;
		union nm_jp_union *newlist = nm_os_realloc(l->list,
				sizeof(*l->list) * newnelem,
				sizeof(*l->list) * l->nelem);
		if (newlist == NULL)
			return NULL;
		l->list = newlist;
		l->nelem = newnelem;
	}
	return &l->list[l->nextfree++];
}

int
nm_jp_oldel_elem(struct nm_jp_olist *l, int i)
{
	union nm_jp_union *u1, *u2;

	l->nextfree--;
	u1 = &l->list[i];
	u2 = &l->list[l->nextfree];
	if (u1 != u2) {
		memcpy(u1, u2, sizeof(*u2));
	}
	memset(u2, 0, sizeof(*u2));
	if (l->nelem > l->minelem && l->nextfree < l->nelem / 2) {
		union nm_jp_union *newlist;
		u_int newnelem = l->nelem / 2;
		if (newnelem < l->minelem)
			newnelem = l->minelem;
		newlist = nm_os_realloc(l->list, sizeof(*l->list) * newnelem,
				sizeof(*l->list) * l->nelem);
		if (newlist == NULL) {
			D("out of memory when trying to release memory?");
			return 0; /* not fatal */
		}
		l->list = newlist;
		l->nelem = newnelem;
	}
	return 0;
}

void
nm_jp_union_set_ptr(union nm_jp_union *u, void *p, struct nm_jp *t)
{
	u->ptr.up.interp = nm_jp_pinterp;
	u->ptr.up.dump   = nm_jp_pdump;
	u->ptr.up.bracket = NULL;
	u->ptr.arg = p;
	u->ptr.type = t;
	u->ptr.flags = 0;
}

int
nm_jp_oladd_ptr(struct nm_jp_olist *l, void *p, struct nm_jp *t)
{
	union nm_jp_union *u = nm_jp_olnew_elem(l);
	if (u == NULL)
		return ENOMEM;
	
	nm_jp_union_set_ptr(u, p, t);
	return 0;
}

int
nm_jp_oldel_ptr(struct nm_jp_olist *l, void *p)
{
	int i;

	for (i = 0; i < l->nextfree; i++) {
		if (l->list[i].ptr.arg == p) {
			nm_jp_oldel_elem(l, i);
			return 0;
		}
	}
	return ENOENT;
}

static struct nm_jp*
nm_jp_dget(struct nm_jp_delem *e)
{
	return (e->flags & NM_JP_D_EXTERNAL) ? e->u.external : &e->u.jp;
}

#if 0
static struct _jpo
nm_jp_ddelete(struct nm_jp_dict *d, struct nm_jp_delem *e,
		char *pool)
{
	if (d->delete == NULL)
		return nm_jp_error(pool, "'delete' not supported");
	if (!e->flags & NM_JP_D_HAVE_REF)
		return nm_jp_error(pool, "busy");
	d->delete(d, e);
	e->flags &= ~NM_JP_D_HAVE_REF;
	return jslr_new_object(pool, 0);
}
#endif

static struct nm_jp_delem *
nm_jp_dsearch(struct nm_jp_dict *d, const char *name);

#if 0
static struct _jpo
nm_jp_dnew(struct nm_jp_dict *d, struct _jpo *pi, struct _jpo *po, struct nm_conf *c)
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
	error = d->new(d, e);
	if (error) {
		o = nm_jp_error(c->pool, "error: %d", error);
		goto out;
	}
	/* the new element is guaranteed to be at the end, while
	 * search returns the first
	 */
	if (nm_jp_dsearch(d, e->name) != e) {
		/* it must be a duplicate */
		nm_jp_ddel_elem(d, e);
		o = nm_jp_error(c->pool, "duplicate entry: %s", e->name);
		goto out;
	}
	*po++ = jslr_new_string(c->pool, e->name);
	jp = nm_jp_dget(e);
	nm_jp_bracket(jp, NM_JPB_ENTER, c);
	if (jp->interp) {
		struct _jpo r = *pi;
		struct nm_conf_var *v;
		int vcmd = nm_jp_parse_var(&r, c, &v);
		if (vcmd < 0) {
			o = r;
			goto leave_;
		}
		o = jp->interp(jp, r, c);
		nm_jp_bracket(jp, NM_JPB_MIDDLE, c);
		if (vcmd == '?')
			v->value = o;
	}
	o = jp->dump(jp, c);
leave_:
	nm_jp_bracket(jp, NM_JPB_LEAVE, c);
	e->flags |= NM_JP_D_HAVE_REF;
out:
	return o;
}
#endif



struct _jpo
nm_jp_dinterp(struct nm_jp *jp, struct _jpo r, struct nm_conf *c)
{
	struct _jpo *pi, *po, ro;
	int i, len, ty = r.len;
	struct nm_jp_dict *d = (struct nm_jp_dict *)jp;
	char *pool = c->pool;

	if (r.ty != JPO_PTR || ty != JPO_OBJECT) {
		ro = nm_jp_error(pool, "need object");
		goto out;
	}

	pi = jslr_get_object(pool, r);
	if (pi == NULL || pi->ty != ty) {
		ro = nm_jp_error(pool, "internal error");
		goto out;
	}

	len = pi->len;
	ro = jslr_new_object(pool, len);
	if (ro.ty == JPO_ERR) {
		ND("len %d, creation failed", len);
		return ro;
	}
	po = jslr_get_object(pool, ro);

	pi++; po++; /* move to first entry */
	for (i = 0; i < len; i++) {
		struct _jpo r1;
		const char *name = jslr_get_string(pool, *pi);
		struct nm_jp_delem *e;

		if (name == NULL) {
			r = nm_jp_error(pool, "internal error");
			goto out;
		}
		if (name[0] == '$') {
			struct nm_conf_var *v;
			const char *new_name;

			v = nm_conf_var_search(c, name + 1);
			if (v && (new_name = jslr_get_string(pool, v->value))) {
				ND("found '%s', replacing with '%s'", name, new_name);
				name = new_name;
			} else {
				if (!v)
					D("'%s' not found", name);
				else
					D("v->value = (%u, %u, %u) not a string",
							v->value.ty, v->value.len, v->value.ptr);
			}
		}
		/* copy and skip the name */
		*po++ = *pi++;
		e = nm_jp_dsearch(d, name);
		if (e == NULL) {
			r1 = nm_jp_error(pool, "not found");
			c->mismatch = 1;
			goto next;
		}
		ND("found %s", name);
		r1 = nm_jp_interp(nm_jp_dget(e), *pi, c);
	next:
		*po++ = r1; pi++; /* move to next entry */
	}

out:
	return ro;
}

static int
nm_jp_dgetlen(struct nm_jp_dict *d)
{
	int rv = 0;
	do {
		rv += d->nextfree;
		d = d->parent;
	} while (d);
	return rv;
}

struct _jpo
nm_jp_ddump(struct nm_jp *jp, struct nm_conf *c)
{
	struct _jpo *po, r;
	struct nm_jp_dict *d = (struct nm_jp_dict *)jp;
	int i, len = nm_jp_dgetlen(d);
	char *pool = c->pool;

	r = jslr_new_object(pool, len);
	if (r.ty == JPO_ERR)
		return r;
	po = jslr_get_object(pool, r);
	po++;
	do {
		for (i = 0; i < d->nextfree; i++) {
			struct nm_jp_delem *e = &d->list[i];
			ND("name %s jp %p", e->name, nm_jp_dget(e));
			*po = jslr_new_string(pool, e->name);
			if (po->ty == JPO_ERR)
				return *po;
			po++;
			*po = nm_jp_dump(nm_jp_dget(e), c);
			if (po->ty == JPO_ERR)
				return *po;
			po++;
		}
		d = d->parent;
	} while (d);
	return r;
}

int
nm_jp_dinit(struct nm_jp_dict *d, const struct nm_jp_delem *list, u_int nelem,
		void (*bracket)(struct nm_jp *, int, struct nm_conf *))
{

	d->up.interp = nm_jp_dinterp;
	d->up.dump   = nm_jp_ddump;
	d->up.bracket = bracket;
	d->minelem = nelem;
	ND("nelem %u", nelem);
	d->list = nm_os_malloc(sizeof(*d->list) * nelem);
	if (d->list == NULL)
		return ENOMEM;
	d->nelem = nelem;
	if (list) {
		u_int i;
		for (i = 0; i < nelem; i++) {
			ND("%u: %s", i, list[i].name);
			d->list[i] = list[i];
		}
		d->nextfree = nelem;
	} else {
		d->nextfree = 0;
	}
	return 0;
}

void
nm_jp_dinit_class(struct nm_jp_dict *d, const struct nm_jp_delem *e1,
		const struct nm_jp_delem *e2,
		void (*bracket)(struct nm_jp *, int, struct nm_conf *))
{
	d->up.interp = nm_jp_dinterp;
	d->up.dump   = nm_jp_ddump;
	d->up.bracket = bracket;

	if (e2 < e1) {
		const struct nm_jp_delem *c = e2;
		e2 = e1;
		e1 = c;
	}
	e1++;
	d->list = (struct nm_jp_delem *)e1;
	d->minelem = d->nelem = d->nextfree = e2 - e1;
}

void
nm_jp_duninit(struct nm_jp_dict *d)
{
	nm_os_free(d->list);
	memset(d, 0, sizeof(*d));
}

/* add a new element to the dictionary */
struct nm_jp_delem *
nm_jp_dnew_elem(struct nm_jp_dict *d)
{
	/* possibly make more room */
	if (d->nextfree >= d->nelem) {
		u_int newnelem = d->nelem * 2;
		struct nm_jp_delem *newlist = nm_os_realloc(d->list,
				sizeof(*d->list) * newnelem,
				sizeof(*d->list) * d->nelem);
		if (newlist == NULL)
			return NULL;
		d->list = newlist;
		d->nelem = newnelem;
	}
	return &d->list[d->nextfree++];
}

int
nm_jp_ddel_elem(struct nm_jp_dict *d, struct nm_jp_delem *e1)
{
	struct nm_jp_delem *e2;

	d->nextfree--;
	e2 = &d->list[d->nextfree];
	if (e1 != e2) {
		memcpy(e1, e2, sizeof(*e2));
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
nm_jp_dsearch(struct nm_jp_dict *d, const char *name)
{
	int i;
	for (i = 0; i < d->nextfree; i++) {
		struct nm_jp_delem *e = &d->list[i];
		if (strncmp(name, e->name, NETMAP_CONFIG_MAXNAME) == 0)
			break;
	}
	if (i == d->nextfree) {
		if (d->parent)
			return nm_jp_dsearch(d->parent, name);
		return NULL;
	}
	return &d->list[i];
}

static int
nm_jp_dvsetname(struct nm_jp_dict *d, struct nm_jp_delem *e, const char *fmt, va_list ap)
{
	int n = vsnprintf(e->name, NETMAP_CONFIG_MAXNAME, fmt, ap);
	if (n >= NETMAP_CONFIG_MAXNAME)
		return ENAMETOOLONG;
	if (nm_jp_dsearch(d, e->name) != e)
		return EEXIST;
	return 0;
}

int
nm_jp_delem_setname(struct nm_jp_dict *d, struct nm_jp_delem *e, const char *fmt, ...)
{
	va_list ap;
	int rv;

	va_start(ap, fmt);
	rv = nm_jp_dvsetname(d, e, fmt, ap);
	va_end(ap);

	return rv;
}

void
nm_jp_delem_set_ptr(struct nm_jp_delem *e, void *p, struct nm_jp *t)
{
	nm_jp_union_set_ptr(&e->u, p, t);
}

static int
_nm_jp_dadd(struct nm_jp_dict *d, struct nm_jp_delem **e, const char *fmt, va_list ap)
{
	int rv;

	*e = nm_jp_dnew_elem(d);
	if (*e == NULL)
		return ENOMEM;
	rv = nm_jp_dvsetname(d, *e, fmt, ap);
	if (rv) {
		nm_jp_ddel_elem(d, *e);
		return rv;
	}
	D("%s: e %p", (*e)->name, *e);
	return 0;
}

int
nm_jp_dadd_ptr(struct nm_jp_dict *d, void *p, struct nm_jp *t, const char *fmt, ...)
{
	struct nm_jp_delem *e;
	va_list ap;
	int rv;

	va_start(ap, fmt);
	rv = _nm_jp_dadd(d, &e, fmt, ap);
	va_end(ap);
	if (rv)
		return rv;

	nm_jp_delem_set_ptr(e, p, t);
	return 0;
}

int
nm_jp_dadd_external(struct nm_jp_dict *d, struct nm_jp *jp, const char *fmt, ...)
{
	struct nm_jp_delem *e;
	va_list ap;
	int rv;

	va_start(ap, fmt);
	rv = _nm_jp_dadd(d, &e, fmt, ap);
	va_end(ap);
	if (rv)
		return rv;

	e->flags = NM_JP_D_EXTERNAL;
	e->u.external = jp;
	
	return 0;
}

int
nm_jp_ddel(struct nm_jp_dict *d, const char *name)
{
	struct nm_jp_delem *e = nm_jp_dsearch(d, name);

	if (e == NULL)
		return ENOENT;

	return nm_jp_ddel_elem(d, e);
}

static int64_t
nm_jp_ngetvar(struct nm_jp_num *in, void *cur_obj)
{
	void *base;
	if (in->size & NM_JP_NUM_REL)
		base = (void *)((char *)cur_obj + (size_t)in->var);
	else
		base = in->var;

	switch (in->size & NM_JP_NUM_SZMSK) {
	case 0:
		return ((nm_jp_nreader)base)(in, cur_obj);
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
		base = (void *)((char *)cur_obj + (size_t)in->var);
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
		if (c->matching)
			c->mismatch = 1;
		goto done;
	}

	nv = jslr_get_num(pool, r);
	v = nm_jp_ngetvar(in, c->cur_obj);
	if (v == nv)
		goto done;
	if (c->matching) {
		c->mismatch = 1;
		goto done;
	}
	if (in->update == NULL) {
		r = nm_jp_error(pool, "read-only");
		goto done;
	}
	error = in->update(in, nv, c->cur_obj);
	if (error)
		r = nm_jp_error(pool, "invalid: %ld (error: %d)", nv, error);
	else
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

static char *
nm_jp_sgetstr(struct nm_jp_str *s, void *cur_obj)
{
	char *str;

	if (s->flags & NM_JP_STR_REL)
		str = (char *)cur_obj + (size_t)s->str;
	else
		str = s->str;
	if (s->flags & NM_JP_STR_IND) {
		str = *(char **)str;
	}

	return str;
}

struct _jpo
nm_jp_sinterp(struct nm_jp *jp, struct _jpo r, struct nm_conf *c)
{
	struct nm_jp_str *s = (struct nm_jp_str *)jp;
	char *nstr, *str;
	char *pool = c->pool;

	if (r.ty != JPO_STRING) {
		r = nm_jp_error(pool, "need number");
		if (c->matching)
			c->mismatch = 1;
		goto done;
	}

	nstr = jslr_get_string(pool, r);
	str = nm_jp_sgetstr(s, c->cur_obj);
	if (strcmp(nstr, str) && c->matching) {
		c->mismatch = 1;
	}
	r = jp->dump(jp, c);
done:
	return r;
}

struct _jpo
nm_jp_sdump(struct nm_jp *jp, struct nm_conf *c)
{
	struct nm_jp_str *s = (struct nm_jp_str *)jp;
	char *str = nm_jp_sgetstr(s, c->cur_obj);

	return jslr_new_string(c->pool, str);
}

static void *
nm_jp_pnewcurobj(struct nm_jp_ptr *p, void *cur_obj)
{
	void *obj;

	if (p->flags & NM_JP_PTR_REL)
		obj = (void *)((char *)cur_obj + (size_t)p->arg);
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
