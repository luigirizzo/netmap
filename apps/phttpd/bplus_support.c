#include <sys/types.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>

#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <assert.h>
#include <x86intrin.h>

#include <bplus_support.h>
#ifdef WITH_CLFLUSHOPT
#define _mm_clflush(p) _mm_clflushopt(p)
#endif


#define MAX_BUFFERS 64
gbuf_t buffer_table[MAX_BUFFERS];

gfile_t *
util_load_vp (const char *path)
{
	gfile_t *vp;
	int error;
	struct stat stx;
	int rc;
	int fd;

	fd = open (path, O_CREAT | O_RDWR, S_IRUSR | S_IWUSR);
	if (fd < 0)
		return NULL;

	rc = fstat (fd, &stx);
	if (rc) 
	{
		close (fd);
		return NULL;
	}

	vp = (gfile_t *) malloc (sizeof (gfile_t));
	memset (vp, 0, sizeof (gfile_t));
	vp->v_fd = fd;
	vp->v_used = vp->v_size = stx.st_size;

	if (stx.st_size == 0) 
	{
		/*
		 * We assume we're creating a new B+ tree.
		 *
		 */

		rc = ftruncate (vp->v_fd, (off_t) TREE_GROW_SIZE);
		if (rc) 
		{
			close (vp->v_fd);
			free (vp);
			return NULL;
		}

		rc = fstat (vp->v_fd, &stx);
		if (rc) 
		{
			close (vp->v_fd);
			free (vp);
			return NULL;
		}

		vp->v_size = stx.st_size;
		vp->v_used = 0ll;
	}

	error = map (vp);
	if (error)
	{
		close (vp->v_fd);
		free (vp);
		return NULL;
	}

	return vp;
}

void
util_unload_vp (gfile_t *vp)
{
	ftruncate (vp->v_fd, vp->v_used);

	munmap (vp->v_base, vp->v_size);
	close (vp->v_fd);
	free (vp);
}

int
map (gfile_t *vp)
{
	vp->v_base = (caddr_t) mmap (
				vp->v_base, 
				vp->v_size, 
				PROT_READ | PROT_WRITE,
				MAP_SHARED | MAP_FILE, 
				vp->v_fd, 
				0);

	if (vp->v_base == (caddr_t) -1) 
		return errno;

	return 0;
}

vbn_t
alloc_block (gfile_t *vp)
{
	vbn_t blkno = 0;
	int error;
	int rc;
	int i = 0;

	blkno = TREE_O2B (vp->v_used);
	vp->v_used += TREE_BSIZE;

	if (vp->v_used < vp->v_size)
		return blkno;

	caddr_t old_base = vp->v_base;
	munmap (vp->v_base, vp->v_size);
	vp->v_size <<= 1;

	rc = ftruncate (vp->v_fd, vp->v_size);
	if (rc) 
		return -errno;

	error = map (vp);
	if (error)
		return -errno;

	if (old_base == NULL || old_base == vp->v_base)
		return blkno;

	/*
	 * The OS has changed our mapping.  Move the buffer pointers.
	 *
	 */
	for (i = 0; i < MAX_BUFFERS; ++i)
		if (buffer_table[i].b_flags & B_VALID)
			buffer_table[i].b_data = vp->v_base +
									TREE_B2O (buffer_table[i].b_blkno);

	return blkno;
}

gbuf_t *
bread (gfile_t *vp, vbn_t blkno)
{
	gbuf_t *bp;
	off_t off;

	bp = &buffer_table[vp->v_bufIDX & (MAX_BUFFERS - 1)];
	assert ((bp->b_flags & B_INUSE) == 0);
	++vp->v_bufIDX;

	off = TREE_B2O (blkno);

	if (off >= vp->v_size)
		return NULL;

	bp->b_vp = vp;
	bp->b_blkno = blkno;
	bp->b_flags = B_INUSE | B_VALID;
	bp->b_data = vp->v_base + off;

	return bp;
}

void 
brelse (gbuf_t *bp)
{
	bp->b_flags &= ~B_INUSE;
}

void 
bdwrite (gbuf_t *bp)
{
	/*
	 * Nothing to do except release buffer.  bp->b_data points at
	 * mmaped pages, and we assume a DIO file system for NVM.
	 *
	 */

	int i;
	for (i = 0; i < 4096; i+=64) {
		_mm_clflush(bp->b_data+i);
	}
	brelse (bp);
}

