/*
 * test checksum
 *
 * General
 * - on new cpus (AMD X2, i5, i7) alignment is not very important.
 * - on old P4, the unrolling is not very useful
 * - the assembly version is uniformly slower
 *
 * In summary the 32-bit version with unrolling is quite fast.

Data on i7-2600

checksums for 1518 bytes on i7-2600 at 3400

bufs    ns/cycle

1       80
128     85
1024    90
2048    91
3000    90
3500    92
3800    95
3900    100
4096    119
8192    141

freq    bufs    ns/cy
200     1       1658
200     2048    1923
200     8192    2331
3400    1       78
3400    8192    141

For short packets

bufs    size    ns/cy
1       64      7
3900    64      16
8192    64      33


 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <sys/time.h>


volatile uint16_t res;

#define REDUCE16(_x)	({ uint32_t x = _x;	\
	x = (x & 0xffff) + (x >> 16);		\
	x = (x & 0xffff) + (x >> 16);		\
	x; } )

#define REDUCE32(_x)	({ uint64_t x = _x;	\
	x = (x & 0xffffffff) + (x >> 32);	\
	x = (x & 0xffffffff) + (x >> 32);	\
	x; } )

uint32_t
dummy(const unsigned char *addr, int count)
{
	(void)addr;
	(void)count;
	return 0;
}

/*
 * Base mechanism, 16 bit at a time, not unrolled
 */
uint32_t
sum16(const unsigned char *addr, int count)
{
	uint32_t sum = 0;
	uint16_t *d = (uint16_t *)addr;

	for (;count >= 2; count -= 2)
		sum += *d++;

	/* Add left-over byte, if any */
	if (count & 1)
		sum += *(uint8_t *)d;
	return REDUCE16(sum);
}

/*
 * Better mechanism, 32 bit at a time, not unrolled
 */
uint32_t
sum32(const unsigned char *addr, int count)
{
	uint64_t sum = 0;
	const uint32_t *d = (const uint32_t *)addr;

	for (; count >= 4; count -= 4)
		sum += *d++;
	addr = (const uint8_t *)d;
	if (count >= 2) {
		sum += *(const uint16_t *)addr;
		addr += 2;
	}
	/* Add left-over byte, if any */
	if (count & 1)
		sum += *addr;
	sum = REDUCE32(sum);
	return REDUCE16(sum);
}

uint32_t
sum32u(const unsigned char *addr, int count)
{
	uint64_t sum = 0;
	const uint32_t *p = (uint32_t *)addr;

	for (; count >= 32; count -= 32) {
		sum += (uint64_t)p[0] + p[1] + p[2] + p[3] + p[4] + p[5] + p[6] + p[7];
		p += 8;
	}
	if (count & 0x10) {
		sum += (uint64_t)p[0] + p[1] + p[2] + p[3];
		p += 4;
	}
	if (count & 8) {
		sum += (uint64_t)p[0] + p[1];
		p += 2;
	}
	if (count & 4)
		sum += *p++;
	addr = (const unsigned char *)p;
	if (count & 2) {
		sum += *(uint16_t *)addr;
		addr += 2;
	}
	if (count & 1)
		sum += *addr;
	sum = REDUCE32(sum);
	return REDUCE16(sum);
}

uint32_t
sum32a(const unsigned char *addr, int count)
{
        uint32_t sum32 = 0;
        uint64_t sum;
	const uint32_t *p = (const uint32_t *)addr;

	for (;count >= 32; count -= 32) {
	    __asm(
		"add %1, %0\n"
		"adc %2, %0\n"
		"adc %3, %0\n"
		"adc %4, %0\n"
		"adc %5, %0\n"
		"adc %6, %0\n"
		"adc %7, %0\n"
		"adc %8, %0\n"
		"adc $0, %0"
		: "+r" (sum32)
		: "g" (p[0]),
		  "g" (p[1]),
		  "g" (p[2]),
		  "g" (p[3]),
		  "g" (p[4]),
		  "g" (p[5]),
		  "g" (p[6]),
		  "g" (p[7])
		: "cc"
	    );
	    p += 8;
	}
	sum = sum32;
	for (;1 &&  count >= 16; count -= 16) {
		sum += (uint64_t)p[0] + p[1] + p[2] + p[3];
		p += 4;
	}
	for (; count >= 4; count -= 4) {
		sum += *p++;
	}
	addr = (unsigned char *)p;
	if (count > 1) {
		sum += *(uint16_t *)addr;
		addr += 2;
	}
	if (count & 1)
		sum += *addr;
	sum = REDUCE32(sum);
	return REDUCE16(sum);
}


struct ftab {
	char *name;
	uint32_t (*fn)(const unsigned char *, int);
};

struct ftab f[] = {
	{ "dummy", dummy },
	{ "sum16", sum16 },
	{ "sum32", sum32 },
	{ "sum32u", sum32u },
	{ "sum32a", sum32a },
	{ NULL, NULL }
};

int
main(int argc, char *argv[])
{
	int i, j, n;
	int lim = argc > 1 ? atoi(argv[1]) : 100;
	int len = argc > 2 ? atoi(argv[2]) : 1024;
	char *fn = argc > 3 ? argv[3] : "sum16";
	int ring_size = argc > 4 ? atoi(argv[4]) : 0;
	unsigned char *buf0, *buf;
#define	MAXLEN 2048
#define NBUFS	65536	/* 128MB */
	uint32_t (*fnp)(const unsigned char *, int) = NULL;
	struct timeval ta, tb;

	if (ring_size < 1 || ring_size > NBUFS)
		ring_size = 1;

	buf0 = calloc(1, MAXLEN * NBUFS);
	if (!buf0)
		return 1;

	for (i = 0; f[i].name; i++) {
		if (!strcmp(f[i].name, fn)) {
			fnp = f[i].fn;
			break;
		}
	}
	if (fnp == NULL) {
		fnp = sum16;
		fn = "sum16-default";
	}
	if (len > MAXLEN)
		len = MAXLEN;
	for (n = 0; n < NBUFS; n++) {
		buf = buf0 + n*MAXLEN;
		for (i = 0; i < len; i++)
			buf[i] = i *i - i + 5;
	}
	fprintf(stderr, "function %s len %d count %dM ring_size %d\n",
		fn, len, lim, ring_size);
	gettimeofday(&ta, NULL);
	for (n = 0; n < lim; n++) {
		for (i = j = 0; i < 1000000; i++) {
			const unsigned char *x = buf0 + j*MAXLEN;
			__builtin_prefetch(x + MAXLEN);
			__builtin_prefetch(x + MAXLEN + 64);
			res = fnp(x, len);
			if (++j == ring_size)
				j = 0;
		}
	}
	gettimeofday(&tb, NULL);
	tb.tv_sec -= ta.tv_sec;
	tb.tv_usec -= ta.tv_usec;
	if (tb.tv_usec < 0) {
		tb.tv_sec--;
		tb.tv_usec += 1000000;
	}
	n = tb.tv_sec * 1000000 +  tb.tv_usec;
	fprintf(stderr, "%dM cycles in %d.%06ds, %dns/cycle\n",
		lim, (int)tb.tv_sec, (int)tb.tv_usec, n/(lim*1000) );
	fprintf(stderr, "%s %u sum16 %u sum32 %d sum32u %u\n",
		fn, res,
		sum16((unsigned char *)buf0, len),
		sum32((unsigned char *)buf0, len),
		sum32u((unsigned char *)buf0, len));
	return 0;
}
