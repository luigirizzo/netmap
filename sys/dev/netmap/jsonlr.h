/*
 * header for json parsing library
 */

#ifndef NETMAP_JSONLR_H
#define NETMAP_JSONLR_H

enum _jpo_type {
	JPO_ERR = 0,
	JPO_CHAR,	/* also bool and null */
	JPO_NUM,
	JPO_STRING,
	JPO_ARRAY,
	JPO_OBJECT,
	JPO_PTR,
	JPO_DOT
};

/* JPO_MISC values */
enum _jp_err {
	JSLR_NULL = 0,
	JSLR_EMPTY,
	JSLR_FALSE,
	JSLR_TRUE,
	JSLR_COMMA,
	JSLR_COLON,
	JSLR_ENDOBJ,
	JSLR_ENDARRAY,
	JSLR_ERROR, /* first errro */
	JSLR_ENOMEM,
	JSLR_EINVAL
};

#define JSLR_MAXLEN ((1<<13)-1)
#define JSLR_MAXSIZE (1<<16)
#define JSLR_MAXDEPTH 16

struct _jpo { /* object */
	unsigned int ty:3;
	unsigned int len:13;
	unsigned int ptr:16;	/* offset in the pool */
};

struct _jp;

struct _jp_stream {
	int (*peek)(struct _jp_stream *);
	void (*consume)(struct _jp_stream *);
};

/*
 * external functions
 */
struct _jpo jslr_parse(struct _jp_stream *js, char *pool, uint32_t pool_len);
const char *	jslr_get_string(const char *pool, struct _jpo);
int64_t		jslr_get_num(const char *pool, struct _jpo);
struct _jpo*	jslr_get_array(const char *pool, struct _jpo);
struct _jpo*	jslr_get_object(const char *pool, struct _jpo);
struct _jpo	jslr_new_string(char *pool, const char *fmt, ...);
struct _jpo	jslr_new_num(char *pool, int64_t);
struct _jpo	jslr_new_array(char *pool, int n);
struct _jpo	jslr_new_object(char *pool, int n);

#endif /* NETMAP_JSONLR_H */
