#ifndef _NETMAP_TEST_H_
#define _NETMAP_TEST_H_

#include <errno.h>
#include <stdlib.h> /* exit */

#define VERBOSE 1

#define ASSERT(x)							\
	do {								\
		if (!(x)) {						\
			printf("In function '%s':\n", __func__);	\
			printf("%s:%d: fail: " #x ": %s\n",		\
			       __FILE__, __LINE__, strerror(errno));	\
			exit(1);					\
		}							\
	} while (0)

#define SUCCESSF(...)							\
	do {								\
		if (VERBOSE) {						\
			printf("Success: %s", __func__);		\
			printf(__VA_ARGS__);				\
		}							\
	} while (0)

#define SUCCESS() SUCCESSF("\n")


void test_device(const char *ifname);
void test_speed(const char *ifname);
void test_userspace(const char *ifname);

#endif /* _NETMAP_TEST_H_ */
