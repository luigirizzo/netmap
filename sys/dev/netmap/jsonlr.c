/*
 * (C) 2015 Universita di Pisa
 */

#if defined(__FreeBSD__)
#include <sys/cdefs.h> /* prerequisite */

#include <sys/types.h>
#include <sys/errno.h>
#include <sys/selinfo.h>
#include <sys/socket.h>
#include <net/if.h>
#include <machine/bus.h>
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

#include <net/netmap.h>
#include <dev/netmap/netmap_kern.h>
#include <dev/netmap/netmap_mem2.h>
#include "jsonlr.h"

#define JSLR_SLOPPY
#define JSLR_DOT

struct _jp {
	/* fields used during the parse phase */
	struct _jp_stream *stream;
	int indot;
        uint32_t depth, max_depth; /* control stack depth */

	/* persistent after a parse */
        struct _jpo *pool;      /* memory pool */
        uint32_t pool_len;      /* pool size in bytes */
	uint32_t pool_tail;	/* first busy byte */
        uint32_t pool_next;     /* next object index to allocate.
				 * free pool_next < pool_tail >> 2
				 */
};

static inline uint32_t pool_inuse(struct _jp *p)
{
	return (p->pool_tail + sizeof(struct _jpo) - 1) / sizeof(struct _jpo);
}

static inline uint32_t pool_avail(struct _jp *p)
{
	return p->pool_next - pool_inuse(p);
}

static inline uint32_t pool_max(struct _jp *p)
{
	return p->pool_len / sizeof(struct _jpo);
}

static int
in_map(const char *s, int c)
{
	while (*s && *s != c)
		s++;
	return *s;
}

#if 0
static const char *_jpo_names[] = {
	"JPO_ERR", "JPO_CHAR",
	"JPO_NUM", "JPO_STRING", "JPO_ARRAY",
	"JPO_OBJECT", "JPO_PTR"};

static const char *
pr_obj(struct _jpo r)
{
	static char buf[128];

	buf[0] = 0;
	snprintf(buf, sizeof(buf),
		".ty %s .len %d .ptr %d",
		_jpo_names[r.ty], (int)r.len, (int)r.ptr);
	return buf;
}
#endif


static const struct _jpo _r_EINVAL = { .ty = JPO_ERR, .ptr = JSLR_EINVAL, .len = 0};
static const struct _jpo _r_ENOMEM = { .ty = JPO_ERR, .ptr = JSLR_ENOMEM, .len = 0};
static const struct _jpo _r_NUL = { .ty = JPO_CHAR, .ptr = 0, .len = 0};
static const struct _jpo _r_ARRAY = { .ty = JPO_ARRAY, .ptr = 0, .len = 0};
static const struct _jpo _r_OBJECT = { .ty = JPO_OBJECT, .ptr = 0, .len = 0};

/* allocate an object */
static struct _jpo *
jslr_alloc(struct _jp *p, struct _jpo val)
{
	struct _jpo *r = NULL;
	if ((p->pool_next - 1) * sizeof(struct _jpo) < p->pool_tail) {
		D("--- EEE --- failed to allocate at %d", (int) p->pool_next);
	} else {
		r = &p->pool[--p->pool_next];
		*r = val;
	}
	return r;
}

/*
 * push an object of size l to the stack.
 */
static int32_t
jslr_push(struct _jp *p, const char *src, uint32_t l)
{
	int i;
	char *dst = (char *)p->pool;
	if ((p->pool_tail + l) > p->pool_next * sizeof(struct _jpo)) {
		D("no space in stack");
		return -1;
	}
	dst += p->pool_tail;
	p->pool_tail += l;
	for (i = 0; i < l; i++)
		dst[i] = src[i];
	return p->pool_tail;
}

static int32_t
jslr_vspushf(struct _jp *p, const char *fmt, va_list ap)
{
	char *dst = (char *)p->pool;
	int s, n;

	s = p->pool_next * sizeof(struct _jpo) - p->pool_tail;
	if (s < 1) {
		D("no space in stack");
		return -1;
	}
	n = vsnprintf(dst + p->pool_tail, s - 1, fmt, ap);
	if (n < 0 || n >= s) {
		D("no space in stack");
		return -1;
	}
	p->pool_tail += n + 1;
	return p->pool_tail;
}
	

/* add n slots after position x, moving up the rest */
static int
jslr_expand(struct _jp *p, struct _jpo *r, uint32_t n)
{
	int i = p->pool_next;
	ssize_t x = r - p->pool;
	struct _jpo *pp = p->pool; /* shorthand */

	ND("expand at %d by %d", (int)x, (int)n);
	if (n > pool_avail(p)) {/* no memory */
		D("out of memory");
		return 1;
	}
	if (x < i || x > pool_max(p)) {
		D("invalid offset %d min is %d", (int)x, i);
		return 1;
	}
	ND("move slots %d .. %d up", i, x - 1);
	for ( ; i < x; i++) {
		pp[i-n] = pp[i];
		ND("%d: %s", (int)(i+n), pr_obj(pp[i+n]) );
	}
	for (i = x-n; i < x; i++) {
		pp[i] = _r_EINVAL;
	}
	p->pool_next -= n;
	/* adjust pointers */
	for (i = p->pool_next; i < pool_max(p); i++) {
		int p1 = pp[i].ptr;
		if (pp[i].ty == JPO_PTR && p1 < x) {
			int p2 = p1 - n;
			ND("at %d adjust %d to %d %s",
				i, p1, p2, pr_obj(p->pool[i]));
			pp[i].ptr = p2;
		}
	}
	return 0;
}

static struct _jpo jslr_1(struct _jp *);

static void
jslr_space(struct _jp *p)
{
	int c;
	struct _jp_stream *s = p->stream;

	while ( (c = s->peek(s)) != 0 && in_map(" \t\r\n", c))
		s->consume(s);
}


/* match a string after the opening quote */
static struct _jpo
jslr_string(struct _jp *p)
{
	int c, start = p->pool_tail, end = start;
	struct _jp_stream *s = p->stream;

	ND("  start at %d '%c'",  start, p->buf[start]);
	s->consume(s); // consume the first '"'
	while ( (c = s->peek(s)) != 0 && c != '"') {
		// XXX missing escapes and \uXXXX
		s->consume(s);
		end = jslr_push(p, (const char *)&c, 1);
		if (end < 0)
			return _r_ENOMEM;
	}
	if (c != '"')
		return _r_EINVAL;
	s->consume(s);
	/* terminate string */
	if (jslr_push(p, "\0", 1) < 0)
		return _r_ENOMEM;
	ND("STRING \"%.*s\"", (end - start), (char *)p->pool + start);
	return (struct _jpo) { .ty = JPO_STRING, .ptr = start, .len = (end - start)};
}

static struct _jpo
jslr_unquoted_string(struct _jp *p)
{
	int c, start = p->pool_tail, end;
	struct _jp_stream *s = p->stream;
	struct _jpo r;

	ND("  start at %d '%c'",  start, p->buf[start]);
	c = s->peek(s);
	do {
		end = jslr_push(p, (const char *)&c, 1);
		if (end < 0)
			return _r_ENOMEM;
		s->consume(s);
	} while ( (c = s->peek(s)) != 0 && 
		  ( (c >= '0' && c <= '9') ||
		    (c >= 'a' && c <= 'z') ||
		    (c >= 'A' && c <= 'Z') ||
		    in_map("_-+*/$@%!", c)
		  )
		);
	/* terminate string */
	if (jslr_push(p, "\0", 1) < 0)
		return _r_ENOMEM;
	r = (struct _jpo) { .ty = JPO_STRING, .ptr = start, .len = (end - start)};
	ND("STRING \"%.*s\"", c, p->buf + start);
	return r;
}

static struct _jpo
jslr_dot(struct _jp *p)
{
	struct _jpo *rp = jslr_alloc(p, _r_EINVAL),
		    *rn = jslr_alloc(p, _r_EINVAL),
		    *ro = jslr_alloc(p, _r_OBJECT), x;
	struct _jp_stream *s = p->stream;

	if (rp == NULL || rn == NULL || ro == NULL)
		return _r_ENOMEM;

	/* consume the dot */
	s->consume(s);

	ro->len = 1;
	/* wait for string or number */
	x = jslr_1(p);
	if (x.ty != JPO_STRING && x.ty != JPO_NUM)
		return _r_EINVAL;
	if (x.ty == JPO_NUM) {
		int64_t n;
		D("got num, (%d, %d, %d)", x.ty, x.ptr, x.len);
	        n = jslr_get_num((const char *)p, x);
		x = jslr_new_string((char *)p, "%ld", n);
		if (x.ty == JPO_ERR)
			return x;
	}
	*rn = x;
	/* wait for either :/= or dot */
	x = jslr_1(p);
	if (x.ty == JPO_PTR && x.len == JPO_DOT) {
		x.len = JPO_OBJECT;
		goto out;
	}
	if (x.ty != JPO_CHAR || (x.ptr != ':' && x.ptr != '='))
		return _r_EINVAL;
	/* wait for object (not dot) */
	x = jslr_1(p);
	if (x.ty <= JPO_CHAR || (x.ty == JPO_PTR && x.len == JPO_PTR))
		return _r_EINVAL;
out:
	*rp = x;
	return (struct _jpo) { .ty = JPO_PTR, .ptr = (ro - p->pool), .len = JPO_DOT };
}

/*
 * only parse integers
 */
static struct _jpo
jslr_num(struct _jp *p)
{
	int start = p->pool_tail, c, len, end;
	int64_t sign, d;
	struct _jp_stream *s = p->stream;

	ND("  start at %d '%c'",  start, c);
	c = s->peek(s);
	sign = (c == '-') ? -1 : 1;
	if (c >= '0' && c <= '9') {
		d = c - '0';
		len = 1;
	} else {
		d = 0;
		len = 0;
	}
	s->consume(s);

	while ((c = s->peek(s)) != 0 && (c >= '0' && c <= '9')) {
		d = d * 10 + (c - '0');
		if (d < 0) {/* int overflow ? */
			D("integer overflow %lld", (long long)d);
			return _r_EINVAL;
		}
		s->consume(s);
		len++;
	}
	if (len == 0) {
		D("short number ?");
		return _r_EINVAL;
	}
	d = d*sign;
	end = jslr_push(p, (const char *)&d, 8);
	if (end < 0)
		return _r_ENOMEM;
	else
		return (struct _jpo) { .ty = JPO_NUM, .ptr = start, .len = 8};
}

static struct _jpo
jslr_object(struct _jp *p)
{
	int state = 0, ofs;
	struct _jpo name, x, *r = jslr_alloc(p, _r_OBJECT);
	struct _jp_stream *s = p->stream;

	if (r == NULL)
		return _r_ENOMEM;
	s->consume(s); // consume the '{'
	ND("  START OBJ at %d '%c' base %d", p->pos - 1, p->buf[ p->pos - 1], base);
	for (;;) {
		x = jslr_1(p);
		if (state == 0) { /* need a name */
			if (x.ty == JPO_STRING) {
				name = x;
				state = 1; /* wait for : */
			} else if (r->len == 0 && x.ty == JPO_CHAR && x.ptr == '}') {
				break;
			} else {
				return _r_EINVAL;
			}
		} else if (state == 1) { /* need : or dot */
			if (x.ty == JPO_CHAR && x.ptr == ':') {
				state = 2; /* wait for object */
			} else if (x.ty == JPO_PTR && x.len == JPO_DOT) {
				state = 2;
				x.len = JPO_OBJECT;
				goto obj;
			} else {
				return _r_EINVAL;
			}
		} else if (state == 2) { /* need object */
	obj:
			if (x.ty > JPO_CHAR) {
				if (r->len >= JSLR_MAXLEN) {
					D("too many fields in object");
					return _r_EINVAL;
				}
				r->len++;
				state = 3;
				ND("valid object %s", pr_obj(x));
				ofs = 2 * (r->len - 1) + 1;
				if (jslr_expand(p, r + ofs, 2))
					return _r_ENOMEM;
				r -= 2;
				*(r + ofs) = name;
				if (x.ty == JPO_PTR)
					x.ptr -= 2; /* allocated past us */
				*(r + ofs + 1) = x;
			} else {
				return _r_EINVAL;
			}
		} else { /* need end or comma */
			if (x.ty == JPO_CHAR && x.ptr == '}') {
				break;
			} else if (x.ty == JPO_CHAR && x.ptr == ',') {
				state = 0;
			} else {
				return _r_EINVAL;
			}
		}
	}
	ND("OBJECT at %d has %d elements up to %d", base, r->len,
		base + 2*r->len);
	return (struct _jpo) {.ty = JPO_PTR, .ptr = (r - p->pool), .len = JPO_OBJECT};
}

static struct _jpo
jslr_array(struct _jp *p)
{
	int state = 0;
	struct _jpo x, *r = jslr_alloc(p, _r_ARRAY);
	struct _jp_stream *s = p->stream;

	if (r == NULL)
		return _r_ENOMEM;
	s->consume(s); // consume the '['
	ND("START ARRAY at %d '%c' base %d %s",  start, p->buf[p->pos - 1], base, pr_obj(*r));
	for (;;) {
		x = jslr_1(p);
		if (state == 0) { /* need object */
			if (x.ty > JPO_CHAR) { /* object */
				if (r->len >= JSLR_MAXLEN) {
					D("too many elements in array");
					return _r_EINVAL;
				}
				r->len++;
				ND("base %d len %d prev obj at %d %s", base, (int)r->len,
					 ofs, pr_obj(p->pool[ofs]));
				if (jslr_expand(p, r + r->len, 1))
					return _r_ENOMEM;
				if (x.ty == JPO_PTR)
					x.ptr -= 1; /* allocated past us */
				r--; /* the array has been moved */
				*(r + r->len) = x;
				ND("new obj at %d %s", ofs, pr_obj(p->pool[ofs]));
				state = 1;
			} else if (r->len == 0 && x.ty == JPO_CHAR && x.ptr == ']') {
				break; /* empty array */
			} else {
				return _r_EINVAL;
			}
		} else { /* need comma or endarray */
			if (x.ty == JPO_CHAR && x.ptr == ']') {
				break;
			} else if (x.ty == JPO_CHAR && x.ptr == ',') {
				state = 0;
			} else {
				return _r_EINVAL;
			}
		}
	}
	ND("ARRAY at %d has %d elements up to %d", base, r->len,
		base + r->len);
	//{ int i; for (i=base; i <= base + r->len; i++) D("%d : %s", i, pr_obj(p->pool[i]) ); }
	return (struct _jpo){.ty = JPO_PTR, .ptr = (r - p->pool), .len = JPO_ARRAY};
}

/*
 * the parse routine returns <0 on error, or an offset to the object
 */
static struct _jpo
jslr_1(struct _jp *p)
{
	int c;
	struct _jpo r = _r_NUL; /* NUL or any token */
	struct _jp_stream *s = p->stream;

	p->depth++;
	if (p->depth > p->max_depth) {
		p->max_depth = p->depth;
		if (p->max_depth > JSLR_MAXDEPTH) {
			D("too many nesting levels");
			r = _r_EINVAL;
			goto out;
		}
		ND("max depth %d", p->max_depth);
	}
	ND("start at %d '%c'",  (int)p->pos, p->buf[p->pos]);
	/* skip leading space */
	jslr_space(p);
	c = s->peek(s);
	if (c == 0 || in_map("]}:,=", c)) { /* NUL or tokens */
		r.ptr = c;
		if (c)
			s->consume(s);
#ifdef JSLR_DOT
	} else if (c == '.') {
		r = jslr_dot(p);
#endif
	} else if (c == '"') { /* start string */
		r = jslr_string(p);
#ifdef JSLR_SLOPPY
	} else if (c == '_' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')) {
		r = jslr_unquoted_string(p);
#endif /* JSLR_SLOPPY */
	} else if (c == '{') { /* start object */
		r = jslr_object(p);
	} else if (c == '[') { /* start array */
		r = jslr_array(p);
	} else if (in_map("-+0123456789", c)) {
		r = jslr_num(p);
	} else {
		D("invalid char '%c'",  c);
		r = _r_EINVAL;
	}
out:
	p->depth--;
	return r;
}

struct _jpo
jslr_parse(struct _jp_stream *s, char *pool, uint32_t pool_len)
{
	struct _jp *p;
	struct _jpo r1;
	uint32_t nobjs;

	if (pool == NULL || pool_len < sizeof(*p))
		goto bad_size;
	p = (struct _jp *)pool;
	p->stream = s;
	p->pool = (struct _jpo *)(p+1);
	pool_len -= sizeof(*p);
	if (pool_len >= JSLR_MAXSIZE)
		goto bad_size;
	nobjs = pool_len / sizeof(r1);
	if (nobjs == 0)
		goto bad_size;
	p->pool_len = nobjs * sizeof(r1);
	p->pool_next = nobjs;
	p->pool_tail = 0;
	p->depth = p->max_depth = 0;

	r1 = jslr_1(p); /* first pass */
	if (r1.ty > JPO_CHAR) {
		/* skip trailing space */
		jslr_space(p);
		if (s->peek(s)) {
			D("--- extra data at the end");
			r1 = _r_EINVAL;
		}
	}
	if (r1.ty == JPO_PTR && r1.len == JPO_DOT)
		r1.len = JPO_OBJECT;
	return r1;

bad_size:
	D("bad pool length %u (min %zu, max %zu)", pool_len,
			sizeof(*p), JSLR_MAXSIZE + sizeof(*p));
	return _r_ENOMEM;
}

const char *
jslr_get_string(const char *pool, struct _jpo r)
{
	struct _jp *p = (struct _jp *)pool;
	const char *d = (const char *)(p->pool);

	if (r.ty != JPO_STRING)
		return NULL;
	return d + r.ptr;
}

int64_t
jslr_get_num(const char *pool, struct _jpo r)
{
	struct _jp *p = (struct _jp *)pool;
	const char *d = (const char *)(p->pool);

	if (r.ty != JPO_NUM)
		return 0;
	return *(int64_t *)(d + r.ptr);
}

struct _jpo *
jslr_get_array(const char *pool, struct _jpo r)
{
	struct _jp *p = (struct _jp *)pool;

	if (r.ty != JPO_PTR && r.len != JPO_ARRAY)
		return NULL;
	return &p->pool[r.ptr];
}

struct _jpo *
jslr_get_object(const char *pool, struct _jpo r)
{
	struct _jp *p = (struct _jp *)pool;

	if (r.ty != JPO_PTR && r.len != JPO_OBJECT)
		return NULL;
	return &p->pool[r.ptr];
}

struct _jpo
jslr_new_string(char *pool, const char *fmt, ...)
{
	struct _jp *p = (struct _jp *)pool;
	int32_t start = p->pool_tail, end;
	va_list ap;

	va_start(ap, fmt);
	end = jslr_vspushf(p, fmt, ap);
	va_end(ap);
	return (end < 0 ? _r_ENOMEM :
			(struct _jpo) {.ty = JPO_STRING, .len = (end - start), .ptr = start});
}

struct _jpo
jslr_new_num(char *pool, int64_t num)
{
	struct _jp *p = (struct _jp *)pool;
	int start = p->pool_tail, end;

	end = jslr_push(p, (const char *)&num, 8);
	return (end < 0 ? _r_ENOMEM :
			(struct _jpo) {.ty = JPO_NUM, .len = 8, .ptr = start});
}

struct _jpo
jslr_new_array(char *pool, int n)
{
	struct _jp *p = (struct _jp *)pool;
	struct _jpo *a;
	int i;

	if (n > JSLR_MAXLEN)
		return _r_EINVAL;

	for (i = 0; i < n; i++) {
		struct _jpo *r = jslr_alloc(p, _r_EINVAL);
		if (r == NULL)
			return _r_ENOMEM;
	}
	a = jslr_alloc(p, _r_ARRAY);
	if (a == NULL)
		return _r_ENOMEM;
	a->len = n;
	return (struct _jpo) {.ty = JPO_PTR, .ptr = (a - p->pool), .len = JPO_ARRAY};
}

struct _jpo
jslr_new_object(char *pool, int n)
{
	struct _jp *p = (struct _jp *)pool;
	struct _jpo *a;
	int i;

	if (n > JSLR_MAXLEN)
		return _r_EINVAL;

	for (i = 0; i < 2 * n; i++) {
		struct _jpo *r = jslr_alloc(p, _r_EINVAL);
		if (r == NULL)
			return _r_ENOMEM;
	}
	a = jslr_alloc(p, _r_OBJECT);
	if (a == NULL)
		return _r_ENOMEM;
	a->len = n;
	return (struct _jpo) {.ty = JPO_PTR, .ptr = (a - p->pool), .len = JPO_OBJECT};
}

#if 0
void
jslr_dump1(struct _jp *p, struct _jpo r)
{
	int i, ri = -1 /* index in pool */;
	const char *d = (const char *)(p->pool);

	/* find first object */
	while (r.ty == JPO_PTR && r.ptr >= pool_inuse(p))
		r = p->pool[ri = r.ptr];

	switch (r.ty) {
	case JPO_NUM:
		printf("%ld", (long)*(int64_t *)(d + r.ptr) );
		break;
	case JPO_STRING:
		printf("\"%.*s\"", r.len, d + r.ptr);
		break;
	case JPO_ARRAY:
		printf("[");
		for (i = 0; i < r.len; i++) {
		    if (i > 0)
			printf(", ");
		    jslr_dump1(p, p->pool[ri+1+i]);
		}
		printf("]");
		break;
	case JPO_OBJECT:
		printf("{");
		for (i = 0; i < 2*r.len; i += 2) {
		    struct _jpo r1 = p->pool[ri +i +1]; /* name */
		    if (i > 1)
			printf(", ");
		    printf("\"%*.*s\" : ", r1.len, r1.len, d + r1.ptr);
		    jslr_dump1(p, p->pool[ri+2+i]);
		}
		printf("}");
		break;

	default:
		PP(0, "%4d: unknown type %d", ri, r.ty);
		break;
	}
}

void
jslr_dump(struct _jp *p, struct _jpo r, int ind)
{
	int i, ri = -1 /* index in pool */;
	const char *d = (const char *)(p->pool);

	while (r.ty == JPO_PTR && r.ptr >= pool_inuse(p))
		r = p->pool[ri = r.ptr];

	switch (r.ty) {
	case JPO_NUM:
		PP(ind, "NUM %ld", (long)*(int64_t *)(d + r.ptr));
		break;
	case JPO_STRING:
		PP(ind, "STRING '%.*s'", r.len, d + r.ptr);
		break;
	case JPO_ARRAY:
		PP(ind, "ARRAY at %d len %d", ri, r.len);
		for (i = 0; i < r.len; i++)
		    jslr_dump(p, p->pool[ri+1+i], ind+4);
		break;
	case JPO_OBJECT:
		PP(ind, "OBJECT at %d len %d", ri, r.len);
		for (i = 0; i < 2*r.len; i += 2) {
		    struct _jpo r1 = p->pool[ri +i +1]; /* name */
		    PP(ind+4, "'%*.*s' :", r1.len, r1.len, d + r1.ptr);
		    jslr_dump(p, p->pool[ri+2+i], ind+8);
		}
		break;

	default:
		PP(ind, "%4d: unknown type %d", ri, r.ty);
		break;
	}
}

struct _jpo
jslr_search(struct _jp *p, struct _jpo x)
{
	return x;
}

int
main(int ac, char *av[])
{
	struct _jpo r;
	int len = ac > 2 ? atoi(av[2]) : 8192;
	char *pool = calloc(1, len);

	ND("jpo has len %d", (int)sizeof(struct _jpo));
	r = jslr_parse(av[1], pool, len);
	ND("r is %d", r.ty);
	jslr_dump((struct _jp *)pool, r, 0);
	jslr_dump1((struct _jp *)pool, r);
	return 0;
}
#endif
