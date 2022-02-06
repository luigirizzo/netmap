#include <unistd.h>

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <assert.h>
#include <time.h>

#include <bplus_support.h>
#include <bplus_common.h>

//#define TESTS	1
#define TESTS 100000

btree_key record[TESTS];

void verify_existence (btree_key, int);

int main (int argc, char *argv[])
{
	gfile_t *vp;
	btree_key key;
	TREE_TYPE datum;
	int rc;
	int i;
	int unique = 0;
	long seed;

	seed = time (0);
	printf ("Using seed %d\n", (int) seed);
	srand (seed);

	rc = btree_create_btree (argv[1], &vp);

	for (i = 0; i < TESTS; ++i)
	{
		key = rand () % (10 * TESTS);
		//key = 0xffffff0000000001;
		key = key << 32;
		printf("key %lu\n", key);
		record[i] = key;
		rc = btree_insert (vp, key, key);
		if (rc == 0)
			++unique;
		else
			verify_existence (key, i);
	}

	for (i = 0; i < TESTS; ++i)
	{
		rc = btree_lookup (vp, record[i], &datum);
		assert (rc == 0);
		assert (record[i] == datum);
	}

	printf ("Inserted %d unique items.\n", unique);

	return 0;
}

void verify_existence (btree_key key, int from)
{
	int i;

	for (i = from - 1; i >= 0; --i)
		if (record[i] == key)
			return;

	assert (0);

	return;
}
