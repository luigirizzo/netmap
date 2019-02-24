/*
 * test minimum select time
 *
 *	./prog usec [method [duration]]
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/time.h>
#include <poll.h>
#include <inttypes.h>

enum { M_SELECT = 0 , M_POLL, M_USLEEP };
static const char *names[] = { "select", "poll", "usleep" };

int
main(int argc, char *argv[])
{
	struct timeval ta, tb, prev;
	int usec = 1, total = 0, method = M_SELECT;
	uint32_t *vals = NULL;
	uint32_t i, count = 0;
#define LIM 1000000

	if (argc > 1)
		usec = atoi(argv[1]);
	if (usec <= 0)
		usec = 1;
	else if (usec > 500000)
		usec = 500000;
	if (argc > 2) {
		if (!strcmp(argv[2], "poll"))
			method = M_POLL;
		else if (!strcmp(argv[2], "usleep"))
			method = M_USLEEP;
	}
	if (argc > 3)
		total = atoi(argv[3]);
	if (total < 1)
		total = 1;
	else if (total > 10)
		total = 10;
	fprintf(stderr, "testing %s for %dus over %ds\n",
		names[method], usec, total);

	gettimeofday(&ta, NULL);
	prev = ta;
	vals = calloc(LIM, sizeof(uint32_t));
	for (;;) {
		if (method == M_SELECT) {
			struct timeval to = { 0, usec };
			select(0, NULL, NULL, NULL, &to);
		} else if (method == M_POLL) {
			poll(NULL, 0, usec/1000);
		} else {
			usleep(usec);
		}
		gettimeofday(&tb, NULL);
		timersub(&tb, &prev, &prev);
		if (count < LIM)
			vals[count] = prev.tv_usec;
		count++;
		prev = tb;
		timersub(&tb, &ta, &tb);
		if (tb.tv_sec > total)
			break;
	}
	fprintf(stderr, "%dus actually took %dus\n",
		usec, (int)(tb.tv_sec * 1000000 + tb.tv_usec) / count );
	for (i = 0; i < count && i < LIM; i++)
		fprintf(stdout, "%d\n", vals[i]);
	return 0;
}
