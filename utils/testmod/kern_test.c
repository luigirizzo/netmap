/*
 * (C) 2012 Luigi Rizzo
 *
 * Some glue to run performance testing of kernel code.
 * You can define functions that run repeatedly some code (locks, etc.)
 * in a tight loop, and drive the execution and timestamp it
 * through sysctl variables.
 * The module is very simple so it can be loaded/unloaded and
 * modified as needed.
 * Some of the functions can also run in userspace, so the code can
 * be built in two versions. For the userspace case, the first two
 * arguments represent the number of loops and test to run.
 */

#ifndef _KERNEL
/*
 * glue code to build this in userspace
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <inttypes.h>
#define	SYSCTL_HANDLER_ARGS	struct oidp *oidp, struct req *req
#define SYSCTL_NODE(_1, _2, _3, _4, _5, _6)
#define SYSCTL_ULONG(_1, _2, _3, _4, _5, _6, _7)	\
	uint64_t *_1 ## _ ## _3 = _5

#define SYSCTL_STRING(_1, _2, _3, _4, _5, _6, _7)
#define SYSCTL_PROC(_1, _2, _3, _4, _5, _6, _7, _8, _9)	\
	void *_1 ## _ ## _3 = _7

struct oidp {
	char *name;
	int oldint;
};

struct req {
	void *newptr;
};

int sysctl_handle_int(struct oidp *o, int *value, int mode, struct req *r)
{
	printf("%s o %p val %p mode %d req %p\n",
		__FUNCTION__, o, value, mode, r);
	*value = o->oldint;
	return 0;
}
// kern_test.c

// amd64 version
static __inline uint64_t
rdtsc(void)
{
        uint32_t low, high;

        __asm __volatile("rdtsc" : "=a" (low), "=d" (high));
        return (low | ((uint64_t)high << 32));
}
#else
/* kernel version */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/conf.h>
#include <sys/uio.h>
#include <sys/kernel.h>
#include <sys/module.h>
#include <sys/bus.h>
#include <machine/bus.h>
#include <machine/resource.h>
#include <sys/rman.h>
#include <sys/time.h>
#include <sys/joystick.h>
#include <dev/joy/joyvar.h>

#endif


#include <sys/sysctl.h>
static uint64_t test_count, t_start, t_end, t_delta;
static char test_name[128];

static int test_run(SYSCTL_HANDLER_ARGS);

// SYSCTL_DECL(_kern);
SYSCTL_NODE(_kern, OID_AUTO, test, CTLFLAG_RW, 0, "kernel testing");
SYSCTL_ULONG(_kern_test, OID_AUTO, count,
    CTLFLAG_RW, &test_count, 0, "number of test cycles");
SYSCTL_ULONG(_kern_test, OID_AUTO, cycles,
    CTLFLAG_RW, &t_delta, 0, "runtime");
SYSCTL_STRING(_kern_test, OID_AUTO, name,
	CTLFLAG_RW, &test_name, sizeof(test_name), "name of the test");
SYSCTL_PROC(_kern_test, OID_AUTO, run,
    CTLTYPE_U64 | CTLFLAG_RW, 0, 0, test_run,
    "U64", "run the test");


struct targ {
	uint64_t count;
};
struct entry {
        void (*fn)(struct targ *);
        char *name;
        uint64_t scale;
};

static void test_nop(struct targ *a) {
	uint64_t i, count = a->count;
	volatile int x = 0;
	for (i = 0; i < count; i++) {
		x = i;
	}
}
struct entry tests[] = {
#if 0
        { test_sel, "select", 1 },
        { test_poll, "poll", 1 },
        { test_usleep, "usleep", 1 },
        { test_time, "time", 1 },
        { test_gettimeofday, "gettimeofday", 1 },
        { test_bcopy, "bcopy", 1 },
        { test_add, "add", ONE_MILLION },
        { test_atomic_add, "atomic-add", ONE_MILLION },
        { test_cli, "cli", ONE_MILLION },
        { test_rdtsc, "rdtsc", ONE_MILLION },   // unserialized
        { test_rdtsc1, "rdtsc1", ONE_MILLION }, // serialized
        { test_atomic_cmpset, "cmpset", ONE_MILLION },
#endif
	{ test_nop, "nop", 1 },
	{ NULL, NULL, 0 }
};

static int test_run_val;
static int
test_run(SYSCTL_HANDLER_ARGS)
{
        int error, value;
	struct entry *i;

        value = test_run_val;
	printf("%s starting with rn %p\n", __FUNCTION__, req->newptr);
        error = sysctl_handle_int(oidp, &value, 0, req);
	printf("%s handle_int returns with %d\n", __FUNCTION__, error);
        if (error != 0 || req->newptr == NULL)
                return (error);
        printf("new value is %d, string %s\n", value, test_name);
        test_run_val = value;
	for (i = tests; i->name; i++) {
		printf("compare .%s. .%s.\n", test_name, i->name);
		if (!strcmp(test_name, i->name)) {
			printf("success\n");
			break;
		}
	}
	if (i->name) {
		struct targ a;
		a.count = test_run_val;
		printf("try to run test %s\n", test_name);
		t_start = rdtsc();
		i->fn(&a);
		t_end = rdtsc();
		t_delta = t_end - t_start;
		printf("%s took %lu ticks\n", test_name, (u_long)t_delta);
	}
        return (0);
}

#ifndef _KERNEL
int main(int argc, char *argv[])
{
	struct oidp o;
	struct req r;

	if (argc < 3)
		return 0;
	o.oldint = 0;
	r.newptr = &o.oldint;
	test_count = atoi(argv[1]);
	strncpy(test_name, argv[2], sizeof(test_name) - 1);
	test_run(&o, &r);
	return 0;
}
#endif
