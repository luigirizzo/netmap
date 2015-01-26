#include <stdio.h>

#include "testnetmap.h"


int
main(int argc, char **argv)
{
	if (argc != 2) {
		printf("Usage: %s <ifname>\n", argv[0]);
		return (1);
	}


	test_device(argv[1]);

	test_userspace(argv[1]);

	test_speed(argv[1]);

	return (0);
}
