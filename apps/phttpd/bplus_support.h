#ifndef __PASTE_BPLUSSUPPORT__H__
#define __PASTE_BPLUSSUPPORT__H__

#include <sys/types.h>
#include <stdint.h>

#define TREE_BSIZE 4096
#define TREE_BSHIFT 12
#define TREE_O2B(X) (X ? ((X) >> 12) : 0)
#define TREE_B2O(X) ((X) << 12)
#define TREE_GROW_SIZE (64 * TREE_BSIZE)

typedef int32_t vbn_t;

typedef struct {

	int					v_fd;
	size_t				v_size;
	size_t				v_used;
	caddr_t				v_base;
	int					v_bufIDX;

} gfile_t;

#define B_VALID			0x01
#define B_INUSE			0x02
#define B_DIRTY			0x04
#define B_ERROR			0x08

typedef struct {

	gfile_t				*b_vp;
	vbn_t				b_blkno;
	int					b_flags;
	caddr_t				b_data;
	
} gbuf_t;

gfile_t *util_load_vp (const char *path);
void util_unload_vp (gfile_t *);\
int map (gfile_t *);
vbn_t alloc_block (gfile_t *);
gbuf_t *bread (gfile_t *, vbn_t);
void brelse (gbuf_t *);
void bdwrite (gbuf_t *);

#endif

