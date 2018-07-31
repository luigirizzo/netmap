/*
 * Copyright (C) 2004 Douglas Santry
 * All rights reserved.
 *
 */

#ifndef __BTREE__H__
#define __BTREE__H__

#include <bplus_support.h>

#define TREE_TYPE uint64_t

#define ASSERT assert
#define VERIFY assert

#define BTREE_MAX_DEPTH 6               /* Maximum depth of tree */

typedef uint64_t 		btree_key;
#define BTREE_KEY_MAX	((btree_key) 0x7fffffffffffffffll)

/*
 * Type for path through the tree...
 *
 */

typedef struct {

	vbn_t		pt_bno;
	uint32_t	 	pt_index;

} path_node;

/*
 * This is the type used in tree lookups.  All trees will have
 * to include this as the first entry in their lookup type.
 *
 */
typedef struct {

	/* IN */
	btree_key	bt_key;		/* Looking for... */
	TREE_TYPE	bt_data;	/* For insert     */
	TREE_TYPE	bt_range;	/* For range     */
	uint32_t		bt_intent;	/* Plans for key, if found */
	gfile_t  	*bt_vp;		/* inode for tree		*/

 	/* Stack of nodes traversed; do not touch */
	path_node 	bt_path[BTREE_MAX_DEPTH];

	/* OUT */
	int32_t		bt_rc;
	gbuf_t 		*bt_bp;
	int		bt_index;
	TREE_TYPE	*bt_datap; 	/* Only valid when LFLAG_FAST is set */
	TREE_TYPE	*bt_rangep; 	/* Only valid when LFLAG_FAST is set */
} btree_lookup_args;

#define	BTREE_LFLAG_LOOKUP	0x0001	/* No change of state planned    */
#define BTREE_LFLAG_INSERT	0x0002	/* We are inserting an element   */
#define BTREE_LFLAG_DELETE	0x0004	/* Deleteing an element          */
#define BTREE_LFLAG_RANGE	0x0010	/* Range search, reverse on fail */
#define BTREE_LFLAG_UPDATE	0x0020  /* Update entry			 */
#define BTREE_LFLAG_BUFFER	0x0040  /* Return locked buffer		 */
#define BTREE_LFLAG_FAST	0x0080  /* No buffer locking		 */

#define BTREE_ARGS_SET_LOOKUP(X, KEY, VP) { (X).bt_key = (btree_key) KEY; \
				(X).bt_intent = BTREE_LFLAG_LOOKUP; \
				(X).bt_vp = VP; }

#define BTREE_ARGS_SET_INSERT(X, KEY, DATA, VP) { (X).bt_key = (btree_key) KEY; \
				(X).bt_data = DATA;		  \
				(X).bt_intent = BTREE_LFLAG_INSERT; \
				(X).bt_vp = VP; }

#define BTREE_ARGS_SET_UPDATE(X, KEY, DATA, VP) { (X).bt_key = (btree_key) KEY; \
				(X).bt_data = DATA;		  \
				(X).bt_intent = BTREE_LFLAG_UPDATE; \
				(X).bt_vp = VP; }

#define BTREE_ARGS_SET_DELETE(X, KEY, VP) { (X).bt_key = (btree_key) KEY; \
				(X).bt_intent = BTREE_LFLAG_DELETE; \
				(X).bt_vp = VP; }

#define BTREE_RC_FOUND		0
#define BTREE_RC_NOTFOUND	2
#define BTREE_RC_INSERTED	-2
#define BTREE_RC_DELETED	-3
#define BTREE_RC_DONE		-4
#define BTREE_RC_ERROR		EIO
#define BTREE_RC_RANGE		-6
#define BTREE_RC_NA		-7

int btree_lookup (gfile_t *, btree_key, TREE_TYPE *);
int btree_insert (gfile_t *, btree_key, TREE_TYPE);
int btree_create_btree (char *, gfile_t **);

void
btree_paranoid(gfile_t *, vbn_t, btree_key);

#endif /* header inclusion */
