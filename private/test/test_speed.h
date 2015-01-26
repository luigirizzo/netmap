#ifndef _NETMAP_TEST_SPEED_H
#define _NETMAP_TEST_SPEED_H

#include <sys/types.h>

/* Enumerate describing the type of method to use for timimng */
enum timing_type {
	TIMING_GTD, /* gettimeofday(2) */
	TIMING_CGT /* clock_gettime(2) */
};

/* Descriptor of timing methods */
struct timing_method {
	char label[128]; /* label/message associated with the method */
	enum timing_type type; /* type of timing method */
	clockid_t clock_id; /* clock identifier used with clock_gettime() */
};


#define RESULTS(label, value)						\
	SUCCESSF(": %0.6f usec\t%s\n", (value), (label));

#define TIMEIT(type, clock, x, ravg, n)					\
	do {								\
		switch ((type)) {					\
		case TIMING_GTD:					\
			TIMEIT_GTD(x, ravg, n);				\
			break;						\
									\
		case TIMING_CGT:					\
			TIMEIT_CGT(clock, x, ravg, n);			\
			break;						\
									\
		default:						\
			break;						\
		}							\
	} while (0)

#define TIMEIT_GTD(x, ravg, n)						\
	do {								\
		int _i;							\
		double _tmp;						\
		struct timeval _start, _end;				\
									\
		gettimeofday(&_start, NULL);				\
		for (_i = 0; _i < (n); _i++)				\
			x;						\
		gettimeofday(&_end, NULL);				\
		_tmp = (_end.tv_usec - _start.tv_usec) +		\
				1000000 * (_end.tv_sec - _start.tv_sec);\
		(ravg) = _tmp / (double) (n);				\
	} while (0)

#define TIMEIT_CGT(clock, x, ravg, n)					\
	do {								\
		int _i;							\
		double _tmp;						\
		struct timespec _start, _end;				\
		clock_gettime((clock), &_start);			\
		for (_i = 0; _i < (n); _i++)				\
			x;						\
		clock_gettime((clock), &_end);				\
		_tmp = (_end.tv_nsec - _start.tv_nsec) / (double) 1000 +\
			1000000 * (_end.tv_sec - _start.tv_sec);	\
		(ravg) = _tmp / (double) (n);				\
	} while (0)

#endif /* _NETMAP_TEST_SPEED_H */
