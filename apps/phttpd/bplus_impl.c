/*
 * Copyright (C) 2004 Douglas Santry
 * All rights reserved.
 *
 */

#include <string.h>
#include <assert.h>
#include <errno.h>
#include <unistd.h>

#include <bplus_support.h>
#include <bplus_common.h>

#define xmove(SRC, DEST, X) memmove (DEST, SRC, X)

#ifndef TREE_LOCK
#define TREE_LOCK(X)
#define TREE_UNLOCK(X)
#endif

typedef enum {
    BINSERT, 
	BPUSHLEFT, 
	BLPIVOT, 
	BPULLLEFT,
	BPUSHRIGHT, 
	BRPIVOT, 
	BPULLRIGHT,
	BSPLIT, 
	BSCREATE, 
	BUPDATE, 
	BHEIGHT,
	BDELETE
} btree_lastop;

#define BTREE_ROOT_ADDR	0xffffffff	/* uint32_t infinity	 */
#define BTREE_ROOT_FBN	0

#define BTREE_HDR_MAGIC         0xa55a5aa5

/*
 * Each block in the tree has one of these headers describing it.
 *
 */
typedef struct {

	uint32_t 		bm_magic;
	uint32_t 		bm_fbn;
	uint32_t 		bm_serialno;
	uint16_t		bm_nkeys;
	uint16_t		bm_level;
	
	vbn_t	bm_next;
	vbn_t	bm_prev;
	btree_lastop	bm_lop;
	btree_key	bm_keys[1];
} btree_meta;

typedef union {

	TREE_TYPE	*bu_data;
	vbn_t	*bu_children;
} btree_data;

/*
 * Anchor for the linked list of interior nodes in a B+ tree (NULL fbn)
 *
 */
#define NODE_ANCHOR 	0xffffffff

/*
 * N is the maximum numnber of keys in a node.
 *
 */

#define BTREE_N0 ((TREE_BSIZE - sizeof(btree_meta) - sizeof(TREE_TYPE)) / \
		(sizeof(btree_key) + sizeof(TREE_TYPE)))

#define BTREE_NX ((TREE_BSIZE - sizeof(btree_meta) - sizeof(vbn_t)) / \
		(sizeof(btree_key) + sizeof(vbn_t)))

#define BTREE_N(X) ((X)->bm_level == 0 ? BTREE_N0 : BTREE_NX)

#define OVERFLOW_PRED(X) ((X)->bm_nkeys == BTREE_N(X))

/*
 * Threshold that determines the choice between splitting and shifting
 * on the insert case for an interior node.
 *
 * We shift if the amount of free space is 11% or greater
 *
 */
#define SHIFT_PRED0(X) ((BTREE_N0 / (BTREE_N0 - (X)->bm_nkeys)) <= 9)
#define SHIFT_PREDX(X) ((BTREE_NX / (BTREE_NX - (X)->bm_nkeys)) <= 9)
#define SHIFT_PRED(X) ((X)->bm_level == 0 ? SHIFT_PRED0(X) : SHIFT_PREDX(X))

#define INIT_BTREE_NODE(BP, HDR, TABLE) { \
	HDR = ((btree_meta *) (BP)->b_data); \
	TABLE.bu_data = ((TREE_TYPE *) (HDR->bm_keys + BTREE_N(HDR))); }

static uint32_t serialno = 0;

static int 
btree_lookup_work(vbn_t, btree_lookup_args *);

static vbn_t
btree_split_node(gbuf_t *original_bp, btree_key *new_key);

static void
btree_increase_height(gbuf_t *root, vbn_t, btree_key key);

static int
btree_shift_right(gbuf_t *left_bp, btree_lookup_args *);

static int
btree_shift_left(gbuf_t *left_bp, btree_lookup_args *);

static int
btree_intra_lookup(gbuf_t *, btree_key);

static void
btree_insert_modify(btree_lookup_args *, btree_key, TREE_TYPE *, int);

static void
btree_delete_modify(btree_lookup_args *, int);

static int
btree_entry (btree_lookup_args *);

#ifdef BTREE_OVERWRITE
static int
btree_overwrite(btree_lookup_args *);
#endif

#if 0
static void
btree_collapse_node(gbuf_t *);
#endif

#if 0
#define D printf("%d\t@%d\n", ME, __LINE__)
#endif
#define D

extern int busy_bufs[];

static vbn_t
btree_grow(gfile_t *);

#ifdef BTREE_ITER
static void btree_traverse_reset (gfile_t *vp);
static TREE_TYPE *btree_traverse_next (gfile_t *vp);
#endif

int
btree_entry (btree_lookup_args *cookie)
{
	int rc;

	(void)rc;
	TREE_LOCK(cookie->bt_vp);

	if ((cookie->bt_intent & BTREE_LFLAG_LOOKUP) == 0) serialno++;

	cookie->bt_rc = BTREE_RC_NA;
	cookie->bt_bp = 0;
	cookie->bt_index = -1;

	rc = btree_lookup_work(BTREE_ROOT_FBN, cookie);
	ASSERT(cookie->bt_rc != BTREE_RC_NA);

#if 0
	ASSERT(busy_bufs[ME] == 0);
#endif

	TREE_UNLOCK(cookie->bt_vp);

	return cookie->bt_rc;
}

int
btree_lookup_work(vbn_t bno, btree_lookup_args *cookie)
{
	gbuf_t *bp;
	btree_meta *b_hdr;
	btree_data b_table;
	vbn_t fbn;
	int cursor;
	int rc = 0;
	int keep_bp_ref = 0;
#ifdef PARANOID
	int i;
#endif

	bp = bread(cookie->bt_vp, bno);
	INIT_BTREE_NODE(bp, b_hdr, b_table);
	ASSERT(b_hdr->bm_magic == BTREE_HDR_MAGIC);

	/*
	 * Mark top of path.
	 *
	 */
	if (bno == BTREE_ROOT_FBN) {

		cookie->bt_path[b_hdr->bm_level+1].pt_index = BTREE_ROOT_ADDR;
		cookie->bt_path[b_hdr->bm_level+1].pt_bno = BTREE_ROOT_ADDR;
	}

	cookie->bt_path[b_hdr->bm_level].pt_bno = bno;

	cursor = btree_intra_lookup(bp, cookie->bt_key);
	ASSERT((0 <= cursor) && (cursor <= b_hdr->bm_nkeys));
	cookie->bt_path[b_hdr->bm_level].pt_index = cursor;

	if (b_hdr->bm_level) {

		fbn = b_table.bu_children[cursor];

		brelse(bp);
		rc = btree_lookup_work(fbn, cookie);
	} else {

		if (cursor < b_hdr->bm_nkeys &&
		    b_hdr->bm_keys[cursor] == cookie->bt_key) {

			if (cookie->bt_intent & BTREE_LFLAG_BUFFER) {

				cookie->bt_bp = bp;
				cookie->bt_index = cursor;
				keep_bp_ref = 1;
			}

			if (cookie->bt_intent & BTREE_LFLAG_DELETE) {

				brelse(bp);
				btree_delete_modify(cookie, 0);
				cookie->bt_rc = BTREE_RC_DELETED;

			} else if (cookie->bt_intent & BTREE_LFLAG_UPDATE) {

				b_table.bu_data[cursor] = cookie->bt_data;
				cookie->bt_rc = BTREE_RC_DONE;
				bdwrite(bp);

			} else if (cookie->bt_intent & BTREE_LFLAG_FAST) {

				/*
				 * We are returning a pointer to buffer
				 * memory.  Only safe in single-threaded
				 * applications with no intervening 
				 * non-idempotent operations.
				 *
				 */
				cookie->bt_datap = &b_table.bu_data[cursor];
				if (!keep_bp_ref) brelse(bp);
				cookie->bt_rc = BTREE_RC_FOUND;
			} else {

				cookie->bt_data = b_table.bu_data[cursor];
				cookie->bt_rc = BTREE_RC_FOUND;
				if (!keep_bp_ref) brelse(bp);
			}
		} else if (cookie->bt_intent & BTREE_LFLAG_INSERT) {

			brelse(bp);
			btree_insert_modify(cookie, 
						cookie->bt_key,
						&cookie->bt_data,
						0);
			cookie->bt_rc = BTREE_RC_INSERTED;
		} else if (cookie->bt_intent & BTREE_LFLAG_RANGE &&
				b_hdr->bm_nkeys) {

			cookie->bt_rc = BTREE_RC_RANGE;

			if (cookie->bt_intent & BTREE_LFLAG_BUFFER) {

				cookie->bt_bp = bp;
				cookie->bt_index = cursor;
				keep_bp_ref = 1;
			}

			cookie->bt_key = b_hdr->bm_keys[cursor];

			if (cookie->bt_intent & BTREE_LFLAG_FAST)
				cookie->bt_datap = &b_table.bu_data[cursor];
			else
				cookie->bt_data = b_table.bu_data[cursor];

			if (cursor == 0) {

				fbn = b_hdr->bm_prev;
				if (!keep_bp_ref) brelse(bp);
				if (fbn == NODE_ANCHOR) {

					cookie->bt_rangep = 0;
					return rc;
				}
				bp = bread(cookie->bt_vp, fbn);
				INIT_BTREE_NODE(bp, b_hdr, b_table);
				ASSERT(b_hdr->bm_magic == BTREE_HDR_MAGIC);
				cursor = b_hdr->bm_nkeys - 1;
			} else cursor--;

			if (cookie->bt_intent & BTREE_LFLAG_FAST)
				cookie->bt_rangep = &b_table.bu_data[cursor];
			else
				cookie->bt_range = b_table.bu_data[cursor];

			if (!keep_bp_ref) brelse(bp);
		} else {

			cookie->bt_rc = BTREE_RC_NOTFOUND;
			brelse(bp);
		}
	}

	return rc;
}

/*
 * This routine recursively propagates changes from leaves to the root
 * of a tree.  It keeps splitting and shifting its way up until we hit
 * the root or a node absorbs the insertion without overflowing.
 *
 */

void
btree_insert_modify(btree_lookup_args *cookie,
				btree_key key, 
				TREE_TYPE *payload,
				int level)
{
#if 0
	extern int nleaves;
#endif 
	gbuf_t *left_bp=0, *right_bp=0;
	gbuf_t *bp;
	vbn_t greater_bno;
	btree_meta *b_hdr, *fixup_hdr;
	btree_data b_table, fixup_table;
	btree_key new_key;
	int stop_here;
	int rc;

	(void)fixup_table;
	bp = bread(cookie->bt_vp, cookie->bt_path[level].pt_bno);
	stop_here = cookie->bt_path[level].pt_index;

	VERIFY(bp);
	INIT_BTREE_NODE(bp, b_hdr, b_table);
	ASSERT(b_hdr->bm_magic == BTREE_HDR_MAGIC);
	ASSERT(b_hdr->bm_level == level);

	if (b_hdr->bm_nkeys == 0) {

		VERIFY(bp->b_blkno == BTREE_ROOT_FBN);

		b_hdr->bm_nkeys = 1;
		b_hdr->bm_keys[0] = key;
		b_table.bu_data[0] = *payload;

		bdwrite(bp);

		return;
	}

	/*
	 * We keep the keys in sorted order.  Having found the
	 * appropriate point to insert (stop_here) we shift everything
	 * over to make room.
	 *
	 */

	xmove(b_hdr->bm_keys + stop_here, 
		b_hdr->bm_keys + stop_here + 1,
		sizeof(btree_key) * (b_hdr->bm_nkeys - stop_here));

	b_hdr->bm_keys[stop_here] = key;

	if (level > 0) {
		xmove(b_table.bu_children + stop_here + 1, 
			b_table.bu_children + stop_here + 2,
			sizeof(vbn_t) * (b_hdr->bm_nkeys - stop_here));
		b_table.bu_children[stop_here + 1] = *(vbn_t *) payload;
	} else {
		xmove(b_table.bu_data + stop_here, 
			b_table.bu_data + stop_here + 1,
			sizeof(TREE_TYPE) * (b_hdr->bm_nkeys - stop_here));
		b_table.bu_data[stop_here] = *payload;
	}

	b_hdr->bm_nkeys++;

	b_hdr->bm_lop = BINSERT;
	b_hdr->bm_serialno = serialno;

	if (OVERFLOW_PRED(b_hdr)) {

		if (b_hdr->bm_prev != NODE_ANCHOR) {

			left_bp = bread(cookie->bt_vp, b_hdr->bm_prev); 
			INIT_BTREE_NODE(left_bp, fixup_hdr, fixup_table);

			if (SHIFT_PRED(fixup_hdr)) {

				brelse(left_bp);
				rc = btree_shift_left(bp, cookie);
				if (rc == 0) return;
			} else brelse(left_bp);
		} 

		if (b_hdr->bm_next != NODE_ANCHOR) {

			right_bp = bread(cookie->bt_vp, b_hdr->bm_next);
			INIT_BTREE_NODE(right_bp, fixup_hdr, fixup_table);

			if (SHIFT_PRED(fixup_hdr)) {

				brelse(right_bp);
				rc = btree_shift_right(bp, cookie);
				if (rc == 0) return;
			} else brelse(right_bp);
		} 

		greater_bno = btree_split_node(bp, &new_key);

		if (cookie->bt_path[level+1].pt_index != BTREE_ROOT_ADDR)
			btree_insert_modify(cookie, 
					new_key,
					(TREE_TYPE *) &greater_bno,
				    	level + 1);
		else /* we are the root */
			btree_increase_height(bp, greater_bno, new_key);
	} 

	bdwrite(bp);
}

vbn_t
btree_split_node(gbuf_t *original_bp, 
			btree_key *new_key)
{
	gfile_t *vp;
	gbuf_t *sibling_bp;
	gbuf_t *right_bp;
	btree_meta *original_hdr;
	btree_data original_table;
	btree_meta *sibling_hdr;
	btree_data sibling_table;
	int lesser_length;
	int greater_length;
	vbn_t new_bno;

	vp = original_bp->b_vp;
	new_bno = btree_grow(vp);

	INIT_BTREE_NODE(original_bp, original_hdr, original_table);
	ASSERT(original_hdr->bm_magic == BTREE_HDR_MAGIC);
	original_hdr->bm_lop = BSPLIT;
	original_hdr->bm_serialno = serialno;

	sibling_bp = bread(vp, new_bno);
	VERIFY(sibling_bp);
	INIT_BTREE_NODE(sibling_bp, sibling_hdr, sibling_table);

	if (original_hdr->bm_next != NODE_ANCHOR) {

		right_bp = bread(vp, original_hdr->bm_next);

		((btree_meta *) (right_bp->b_data))->bm_prev = 
							sibling_bp->b_blkno;
		((btree_meta *) (right_bp->b_data))->bm_serialno = serialno;
		((btree_meta *) (right_bp->b_data))->bm_lop = BUPDATE;
		bdwrite(right_bp);
	}

	*sibling_hdr = *original_hdr;
	INIT_BTREE_NODE(sibling_bp, sibling_hdr, sibling_table);
	original_hdr->bm_next = sibling_bp->b_blkno;
	sibling_hdr->bm_prev = original_bp->b_blkno;
	sibling_hdr->bm_fbn = sibling_bp->b_blkno;
	sibling_hdr->bm_lop = BSCREATE;

	lesser_length = original_hdr->bm_nkeys >> 1;
	greater_length = original_hdr->bm_nkeys - lesser_length;

	xmove(original_hdr->bm_keys + lesser_length, 
		sibling_hdr->bm_keys, greater_length * sizeof(btree_key));

	if (original_hdr->bm_level) {

		xmove(original_table.bu_children + lesser_length,
			sibling_table.bu_children, 
			(greater_length + 1) * sizeof(vbn_t));
		
		lesser_length--;
		*new_key = original_hdr->bm_keys[lesser_length];
	} else {
		xmove(original_table.bu_data + lesser_length,
			sibling_table.bu_data, 
			greater_length * sizeof(TREE_TYPE));

		*new_key = sibling_hdr->bm_keys[0];
	}
	

	original_hdr->bm_nkeys = lesser_length;
	sibling_hdr->bm_nkeys = greater_length;

	bdwrite(sibling_bp);

	return new_bno;
}

/*
 * If the root node of the tree overflows we can't just split it.  We need
 * to increase the height of the tree.  We keep the root of the tree fbn 0.
 *
 */
void
btree_increase_height(gbuf_t *root, 
				vbn_t greater_bno, 
				btree_key key)
{
	vbn_t new_bno;
	gbuf_t *greater_bp;
	gbuf_t *will_be_lesser_bp;
	btree_meta *b_hdr;
	btree_data b_table;

	new_bno = btree_grow(root->b_vp);

	will_be_lesser_bp = bread(root->b_vp, new_bno);
	greater_bp = bread(root->b_vp, greater_bno);

	/*
	 * DJS_debug - this needs to be a page flip.
	 *
	 */
	xmove(root->b_data, will_be_lesser_bp->b_data, TREE_BSIZE);
	INIT_BTREE_NODE(greater_bp, b_hdr, b_table);
	b_hdr->bm_prev = will_be_lesser_bp->b_blkno;
	b_hdr->bm_serialno = serialno;

	INIT_BTREE_NODE(will_be_lesser_bp, b_hdr, b_table);
	b_hdr->bm_fbn = will_be_lesser_bp->b_blkno;
	b_hdr->bm_serialno = serialno;

	INIT_BTREE_NODE(root, b_hdr, b_table);
	ASSERT(b_hdr->bm_magic == BTREE_HDR_MAGIC);
	b_hdr->bm_level++;
	if (b_hdr->bm_level == 1)
		INIT_BTREE_NODE(root, b_hdr, b_table);
	b_hdr->bm_lop = BHEIGHT;
	b_hdr->bm_serialno = serialno;

#if 0
	/*
	 * Leaves look subtly different from interior nodes.  Their
	 * key/payload ratios differ.  We determine if we are growing
	 * from a one node tree here and inflect the format of the
	 * the node.
	 *
	 */
	if (b_hdr->bm_level == 1) {

		/*
		 * Get every thing pointing to the proper area and
		 *
		 */
		INIT_BTREE_NODE(root, b_hdr, b_table);
	}
#endif

	b_hdr->bm_nkeys = 1;
	b_hdr->bm_next = NODE_ANCHOR;
	ASSERT(b_hdr->bm_prev == NODE_ANCHOR);

	b_hdr->bm_keys[0] = key;
	b_table.bu_children[0] = will_be_lesser_bp->b_blkno;
	b_table.bu_children[1] = greater_bp->b_blkno;

	bdwrite(will_be_lesser_bp);
	bdwrite(greater_bp);
}

int
btree_shift_left(gbuf_t *right_bp, btree_lookup_args *cookie) 
{
	gbuf_t *parent_bp;
	gbuf_t *left_bp;
	btree_meta *left_hdr, *right_hdr, *parent_hdr;
	btree_data left_table, right_table, parent_table;
	int space;
	int level;
	int index;
	int non_leaf=1;

	(void)parent_table;
	INIT_BTREE_NODE(right_bp, right_hdr, right_table);
	ASSERT(right_hdr->bm_magic == BTREE_HDR_MAGIC);

	right_hdr->bm_lop = BPUSHLEFT;

	level = right_hdr->bm_level + 1;

        parent_bp = bread(cookie->bt_vp, cookie->bt_path[level].pt_bno);
        INIT_BTREE_NODE(parent_bp, parent_hdr, parent_table);
        ASSERT(parent_hdr->bm_magic == BTREE_HDR_MAGIC);

        index = cookie->bt_path[level].pt_index;

	if (index == 0) {

		brelse(parent_bp);
		return -1; /* leaves do not have a common parent */
	}

	parent_hdr->bm_serialno = serialno;
	parent_hdr->bm_lop = BLPIVOT;

	/*
	 * This index is relative to children;  Needs to be translated
	 * to the key name space.
	 *
	 */
	if (index) index--;

	left_bp = bread(cookie->bt_vp, right_hdr->bm_prev);
	VERIFY(left_bp);
	INIT_BTREE_NODE(left_bp, left_hdr, left_table);
	ASSERT(left_hdr->bm_magic == BTREE_HDR_MAGIC);
	left_hdr->bm_lop = BPULLLEFT;
	left_hdr->bm_serialno = serialno;

	/*
	 * We'll take half of the space to shift in.
	 *
	 */
	space = (right_hdr->bm_nkeys - left_hdr->bm_nkeys) >> 1;

	if (right_hdr->bm_level == 0) non_leaf = 0;

	/*
	 * Move the keys over.
	 *
	 *   i) demote the parent key to the left-most position on the left
	 *  ii) move the keys from the right
	 * iii) promote the left-most key in the right node
	 *  iv) shift every thing in the right node to the beginning
	 *
	 */

	left_hdr->bm_keys[left_hdr->bm_nkeys] = parent_hdr->bm_keys[index];

	xmove(right_hdr->bm_keys, 
		left_hdr->bm_keys + left_hdr->bm_nkeys + non_leaf, 
		(space - non_leaf) * sizeof(btree_key));

	parent_hdr->bm_keys[index] = right_hdr->bm_keys[space - non_leaf];

	xmove(right_hdr->bm_keys + space,
		right_hdr->bm_keys,
		(right_hdr->bm_nkeys - space) * sizeof(btree_key));

	/* 
	 * Move the data
	 *
	 *  i) inter-node shift data right to left
	 * ii) intra-node shift remaining data left
	 *
	 */

	if (non_leaf) {

		xmove(right_table.bu_children,
			left_table.bu_children + left_hdr->bm_nkeys + 1,
			space * sizeof(vbn_t));

		xmove(right_table.bu_children + space,
			right_table.bu_children,
			(right_hdr->bm_nkeys + 1 - space) * sizeof(vbn_t));
	} else {

		xmove(right_table.bu_data,
			left_table.bu_data + left_hdr->bm_nkeys,
			space * sizeof(TREE_TYPE));

		xmove(right_table.bu_data + space,
			right_table.bu_data,
			(right_hdr->bm_nkeys - space) * sizeof(TREE_TYPE));

	}

	left_hdr->bm_nkeys += space;
	right_hdr->bm_nkeys -= space;

	bdwrite(right_bp);
	bdwrite(left_bp);
	bdwrite(parent_bp);

	return 0;
}

int
btree_shift_right(gbuf_t *left_bp, btree_lookup_args *cookie)
{
	gbuf_t *parent_bp;
	gbuf_t *right_bp;
	btree_meta *left_hdr, *right_hdr, *parent_hdr;
	btree_data left_table, right_table, parent_table;
	int space;
	int level;
	int index;
	int non_leaf=1;

	(void)parent_table;
	INIT_BTREE_NODE(left_bp, left_hdr, left_table);
	ASSERT(left_hdr->bm_magic == BTREE_HDR_MAGIC);

	left_hdr->bm_lop = BPUSHRIGHT;

	level = left_hdr->bm_level + 1;

	parent_bp = bread(cookie->bt_vp, cookie->bt_path[level].pt_bno);
	INIT_BTREE_NODE(parent_bp, parent_hdr, parent_table);
	ASSERT(parent_hdr->bm_magic == BTREE_HDR_MAGIC);

	index = cookie->bt_path[level].pt_index;

	if (index == parent_hdr->bm_nkeys) {

		brelse(parent_bp);
		return -1; /* different parents */
	}

	parent_hdr->bm_serialno = serialno;
	parent_hdr->bm_lop = BRPIVOT;

        /*
         * This index is relative to children;  Needs to be translated
         * to the key name space.
         *
         */

	right_bp = bread(cookie->bt_vp, left_hdr->bm_next);
	INIT_BTREE_NODE(right_bp, right_hdr, right_table);
	ASSERT(right_hdr->bm_magic == BTREE_HDR_MAGIC);
	right_hdr->bm_lop = BPULLRIGHT;
	right_hdr->bm_serialno = serialno;

	space = (left_hdr->bm_nkeys - right_hdr->bm_nkeys) >> 1;

	if (left_hdr->bm_level == 0) non_leaf = 0;

	/*
	 * shift the keys over.
	 *
	 *   i) intra-shift to make space for keys coming from the left
	 *  ii) demote key from parent
	 * iii) inter-shift of keys from left, right node now full
	 *  iv) promote keys from left in to the ancestors
	 *
	 */
	xmove(right_hdr->bm_keys, right_hdr->bm_keys + space, 
			right_hdr->bm_nkeys * sizeof(btree_key));

	if (non_leaf)
		right_hdr->bm_keys[space - 1] = parent_hdr->bm_keys[index];

	xmove(left_hdr->bm_keys + left_hdr->bm_nkeys - space + non_leaf,
		right_hdr->bm_keys,
		(space - non_leaf) * sizeof(btree_key));

	if (non_leaf) parent_hdr->bm_keys[index] = 
		left_hdr->bm_keys[left_hdr->bm_nkeys - space];
	else parent_hdr->bm_keys[index] = right_hdr->bm_keys[0];

	/*
	 * Shift children/payload over.  Parent is not touched here.
	 *
	 *   i) Make room in the right
	 *  ii) shift from left
	 *
	 */


	if (non_leaf) {

		xmove(right_table.bu_children, 
			right_table.bu_children + space,
			(right_hdr->bm_nkeys + 1) * sizeof(vbn_t));
		xmove(left_table.bu_children + left_hdr->bm_nkeys + 1 - space,
			right_table.bu_children,
			space * sizeof(vbn_t));
	} else {
		xmove(right_table.bu_data, 
			right_table.bu_data + space,
			right_hdr->bm_nkeys * sizeof(TREE_TYPE));
		xmove(left_table.bu_data + left_hdr->bm_nkeys - space,
			right_table.bu_data,
			space * sizeof(TREE_TYPE));
	}


	right_hdr->bm_nkeys += space;
	left_hdr->bm_nkeys -= space;

	bdwrite(right_bp);
	bdwrite(left_bp);
	bdwrite(parent_bp);

	return 0;
}

/*
 * Crappy little binary search.  All keys to the left of a key
 * are greater than it, that is, key[i] < key[i+1] for all i
 *
 * If key is not found then returns where it would insert
 * the key.  This is IMPORTANT and callers rely on this
 * property.
 *
 */

int
btree_intra_lookup(gbuf_t *bp, btree_key key)
{
	btree_meta *b_hdr;
	btree_data b_table;
	btree_key *table;
	int right, left;
	int cursor;

	(void)b_table;
	INIT_BTREE_NODE(bp, b_hdr, b_table);

	table = b_hdr->bm_keys;

	right = b_hdr->bm_nkeys - 1;
	left = 0;
	while (1) {

		if (left > right) {

			if (right >= 0 && table[right] > key) 
				cursor = right;
			else 
				cursor = left;

			break; /* while(1) search loop */
		}

		cursor = (right + left) >> 1;

		if (key == table[cursor]) {

			if (b_hdr->bm_level) cursor++;

			break; /* while(1) search loop */
		}

		if (key < table[cursor])
			right = cursor - 1;
		else
			left = cursor + 1;
	}

	ASSERT(cursor >= 0 && cursor <= b_hdr->bm_nkeys);
	ASSERT((cursor == b_hdr->bm_nkeys) || (table[cursor] >= key));

	return cursor;
}

int btree_create_btree(char *path, gfile_t **btree)
{
	gfile_t *vp;
    btree_meta *b_hdr;
    btree_data b_table;
	gbuf_t *bp;
	vbn_t blkno;

	(void)b_table;
	unlink (path);

	vp = util_load_vp (path);
	if (vp == NULL) 
		return -errno;

	blkno = btree_grow (vp);
	assert (blkno == BTREE_ROOT_FBN);

	TREE_LOCK(vp);
	*btree = vp;

	bp = bread (*btree, BTREE_ROOT_FBN);
	memset (bp->b_data, 0, TREE_BSIZE);
	INIT_BTREE_NODE(bp, b_hdr, b_table);

	b_hdr->bm_next = b_hdr->bm_prev = NODE_ANCHOR;
	b_hdr->bm_magic = BTREE_HDR_MAGIC;

	bdwrite(bp);

	TREE_UNLOCK(vp);

	return 0;
}


#if 0
static int population;

void
btree_paranoid(gfile_t *vp, vbn_t fbn, btree_key upper_bound)
{
	extern int insertions, deletions;
	extern btree_key keys[];
	btree_key last_key, cursor;
	gbuf_t *bp;
        btree_meta *b_hdr;
        btree_data b_table;
	int i;

	if (fbn == BTREE_ROOT_FBN) {

		population = 0;
	}

	bp = bread(vp, fbn);
	INIT_BTREE_NODE(bp, b_hdr, b_table);
	ASSERT(b_hdr->bm_magic == BTREE_HDR_MAGIC);
	ASSERT(b_hdr->bm_fbn == fbn);

	ASSERT(b_hdr->bm_keys[0] < upper_bound);
	ASSERT(b_hdr->bm_keys[b_hdr->bm_nkeys - 1] < upper_bound);

	if (b_hdr->bm_level == 0)
		population += b_hdr->bm_nkeys;

	for (i = 1; i < b_hdr->bm_nkeys - 1; i++) {

		ASSERT(b_hdr->bm_keys[i-1] < b_hdr->bm_keys[i]);
	}

	for (i=0; i <= b_hdr->bm_nkeys; i++) {

		if (b_hdr->bm_level == 0) {

			if (i == b_hdr->bm_nkeys) continue;

			ASSERT(b_hdr->bm_keys[i] == b_table.bu_data[i].key);
			ASSERT(keys[b_hdr->bm_keys[i]] == b_hdr->bm_keys[i]);
			ASSERT(atoi(b_table.bu_data[i].name) == 
							b_hdr->bm_keys[i]);

			if (i == 0) last_key = b_hdr->bm_keys[0];
			else {

				for (cursor = last_key + 1; 
				     cursor < b_hdr->bm_keys[i];
				     cursor++) {
					if (keys[cursor] != 0LL)
						printf("\n*\t%d\n",
							(int) keys[cursor]);
				}
				last_key = b_hdr->bm_keys[i];
			}
		} else
			btree_paranoid(vp, b_table.bu_children[i], 
						(i == b_hdr->bm_nkeys ? 
						   BTREE_KEY_MAX : 
						   b_hdr->bm_keys[i]));
	}

	brelse(bp);

	if (fbn == BTREE_ROOT_FBN)
		ASSERT(population == insertions - deletions);
}
#endif

#ifdef PARANOID
btree_key dkey=0LL;
int32_t dcursor=-1;
vbn_t fbn=0;
uint32_t dserialno;
#endif

void
btree_delete_modify(btree_lookup_args *cookie, int level)
{
	gbuf_t *bp;
    btree_meta *b_hdr;
    btree_data b_table;
#if 0
	gbuf_t *right_bp=0, *left_bp=0;
        btree_meta *right_hdr=0;
        btree_meta *left_hdr=0;
        TREE_TYPE *right_table;
        TREE_TYPE *left_table;
	int rc;
#endif
	int cursor;

	bp = bread(cookie->bt_vp, cookie->bt_path[level].pt_bno);
	INIT_BTREE_NODE(bp, b_hdr, b_table);
	ASSERT(b_hdr->bm_magic == BTREE_HDR_MAGIC);

	cursor = cookie->bt_path[level].pt_index;

#ifdef PARANOID
	ASSERT(level == 0);
	ASSERT(b_hdr->bm_keys[cursor] == cookie->bt_key);
	ASSERT(b_table[cursor] == (TREE_TYPE) cookie->bt_key);

	dkey = cookie->bt_key;
	dcursor = cursor;
	fbn = bp->b_blkno;
	dserialno = serialno;
#endif

	if (level > 0) {

		if (cursor > 0)
			xmove(b_hdr->bm_keys + cursor, 
				b_hdr->bm_keys + cursor - 1, 
				(b_hdr->bm_nkeys - cursor) * sizeof(btree_key));
		else
			xmove(b_hdr->bm_keys + 1, 
				b_hdr->bm_keys, 
				b_hdr->bm_nkeys * sizeof(btree_key));

		xmove(b_table.bu_children + cursor + 1, 
			b_table.bu_children + cursor,
			(b_hdr->bm_nkeys - cursor) * sizeof(vbn_t));
	} else if (cursor < b_hdr->bm_nkeys - 1) {

		xmove(b_hdr->bm_keys + cursor + 1, b_hdr->bm_keys + cursor, 
			(b_hdr->bm_nkeys - cursor) * sizeof(btree_key));

		xmove(b_table.bu_data + cursor + 1, 
			b_table.bu_data + cursor,
			(b_hdr->bm_nkeys - cursor) * sizeof(TREE_TYPE));
	}

	b_hdr->bm_nkeys--;
	b_hdr->bm_serialno = serialno;
	b_hdr->bm_lop = BDELETE;

	bdwrite(bp);

	return;

#if 0
	/*
	 * If we are the root of the tree then there is nothing
	 * that we can do so bail early.
	 *
	 */
	if (bp->b_blkno == BTREE_ROOT_FBN)
		return;

	/*
	 * Determine if an underflow has occured.
	 *
	 */
	if (b_hdr->bm_nkeys > (BTREE_N >> 1))
		return;

	/*
	 * An underflow will occur.  We now consult our neighbours
	 * and determine upon a choice of action from the following
	 * selection.  Excepting the case where we are the last node
	 * left one of the following is guaranteed to be possible.
	 *
	 * 1) Shift in to a neighbour
	 *
	 * 2) Accept keys from a neighbour
	 * 
	 */
	if (b_hdr->bm_next != NODE_ANCHOR) {

		right_bp = bread(cookie->bt_vp, b_hdr->bm_next);
		INIT_BTREE_NODE(right_bp, right_hdr, right_table);
		ASSERT(right_hdr->bm_magic == BTREE_HDR_MAGIC);

		if (right_hdr->bm_nkeys + b_hdr->bm_nkeys < BTREE_N) {

			/*
		 	 * We have room in our neighbour so we will shift and
			 * delete the node.
		 	 *
		 	 */
			brelse(right_bp);
			rc = btree_shift_right(bp, cookie);
			if (rc == 0) {

				btree_delete_modify(cookie, level + 1);
				btree_collapse_node(bp);
				return;
			}

		} else brelse(right_bp);
	}

	if (b_hdr->bm_prev != NODE_ANCHOR) {

		left_bp = bread(cookie->bt_vp, b_hdr->bm_prev);
		INIT_BTREE_NODE(left_bp, left_hdr, left_table);
		ASSERT(left_hdr->bm_magic == BTREE_HDR_MAGIC);

		/*
		 * We have room in our neighbour so we will shift and
		 * delete.
		 *
		 */
		if (left_hdr->bm_nkeys + b_hdr->bm_nkeys < BTREE_N) {

			brelse(left_bp);
			rc = btree_shift_left(bp, cookie);
			if (rc == 0) {

				btree_delete_modify(cookie, level + 1);
				btree_collapse_node(bp);
				return;
			} 

		} else brelse(left_bp);
	}
#endif /* if 0 */
}

#if 0
void
btree_collapse_node(gbuf_t *bp)
{
	extern int nleaves;
	gbuf_t *right_bp=0, *left_bp=0;
        btree_meta *b_hdr;
        btree_meta *right_hdr=0;
        btree_meta *left_hdr=0;
        TREE_TYPE *b_table;
        TREE_TYPE *right_table;
        TREE_TYPE *left_table;

	INIT_BTREE_NODE(bp, b_hdr, b_table);
	ASSERT(b_hdr->bm_magic == BTREE_HDR_MAGIC);

	if (b_hdr->bm_next != NODE_ANCHOR) {

		right_bp = bread(bp->b_vp, b_hdr->bm_next);
		INIT_BTREE_NODE(right_bp, right_hdr, right_table);
		ASSERT(right_hdr->bm_magic == BTREE_HDR_MAGIC);

		right_hdr->bm_prev = b_hdr->bm_prev;
		bdwrite(right_bp);
	}

	if (b_hdr->bm_prev != NODE_ANCHOR) {

		left_bp = bread(bp->b_vp, b_hdr->bm_prev);
		INIT_BTREE_NODE(left_bp, left_hdr, left_table);
		ASSERT(left_hdr->bm_magic == BTREE_HDR_MAGIC);

		left_hdr->bm_next = b_hdr->bm_next;
		bdwrite(left_bp);
	}

	nleaves--;
	spensa_punch_hole(bp->b_vp, (vbn_t) bp->b_blkno);
}
#endif

vbn_t btree_grow(gfile_t *vp)
{
	vbn_t blkno;

	blkno = alloc_block (vp);

	return blkno;
}

#ifdef BTREE_OVERWRITE
int btree_overwrite(btree_lookup_args *cookie)
{
	btree_meta *b_hdr;
	btree_data b_table;

	INIT_BTREE_NODE(cookie->bt_bp, b_hdr, b_table);
	ASSERT(b_hdr->bm_magic == BTREE_HDR_MAGIC);

	b_hdr->bm_keys[cookie->bt_index] = cookie->bt_key;
	b_table.bu_data[cookie->bt_index] = cookie->bt_data;


	bdwrite(cookie->bt_bp);

	return 0;
}
#endif

#ifdef BTREE_ITER

static int tblkno;
static int tcurrent_index;

void btree_traverse_reset (gfile_t *vp)
{
	btree_meta *b_hdr;
	btree_data b_table;
	gbuf_t *bp;

	tblkno = BTREE_ROOT_FBN;

	while (1) {

		bp = bread (vp, tblkno);
		INIT_BTREE_NODE(bp, b_hdr, b_table);
		ASSERT(b_hdr->bm_magic == BTREE_HDR_MAGIC);
		ASSERT(b_hdr->bm_fbn == tblkno);

		if (b_hdr->bm_level == 0) break;

		tblkno = b_table.bu_children[0];
		brelse (bp);
	}

	brelse (bp);
	tcurrent_index = 0;

	return;
}

TREE_TYPE *btree_traverse_next (gfile_t *vp)
{
	btree_data b_table;
	btree_meta *b_hdr;
	TREE_TYPE *datap;
	gbuf_t *bp;
	int try_again;

retry:
	try_again=0;

	if (tblkno == NODE_ANCHOR) return 0;

	bp = bread (vp, tblkno);
	INIT_BTREE_NODE(bp, b_hdr, b_table);
	ASSERT(b_hdr->bm_magic == BTREE_HDR_MAGIC);
	ASSERT(b_hdr->bm_fbn == tblkno);

	if (b_hdr->bm_nkeys == 0) {

		try_again = 1;
		goto empty;
	}

	datap = &b_table.bu_data[tcurrent_index];

	tcurrent_index++;
	if (tcurrent_index == b_hdr->bm_nkeys) {

empty:
		tblkno = b_hdr->bm_next;
		tcurrent_index = 0;
	}

	brelse (bp);

	if (try_again)
		goto retry;

	return datap;
}

#endif /* BTREE_ITER */

int
btree_lookup (gfile_t *vp, btree_key key, TREE_TYPE *datum)
{
	btree_lookup_args cookie;
	int rc;

	cookie.bt_vp = vp;
	cookie.bt_key = key;
	cookie.bt_intent = BTREE_LFLAG_LOOKUP | BTREE_LFLAG_FAST;

	rc = btree_entry (&cookie);
	if (rc == BTREE_RC_NOTFOUND)
		return ENOENT;

	*datum = *cookie.bt_datap;
	return 0;
}

int
btree_insert (gfile_t *vp, btree_key key, TREE_TYPE datum)
{
	btree_lookup_args cookie;
	int rc;

	cookie.bt_vp = vp;
	cookie.bt_key = key;
	cookie.bt_data = datum;
	cookie.bt_intent = BTREE_LFLAG_INSERT | BTREE_LFLAG_UPDATE;

	rc = btree_entry (&cookie);
	if (rc == BTREE_RC_FOUND)
		return EEXIST;

	if (rc == BTREE_RC_INSERTED || rc == BTREE_RC_DONE)
		return 0;

	assert (0);

	return 0;
}

