#include <stdio.h>
#include <inttypes.h>
int f_0(int x)
{
	return x + 1;
}

int f_100(int x);
int main(int ac, char *av[])
{
	int i, cnt, lim = atoi(av[1]);
	volatile uint64_t res;
	for (cnt = 0; cnt < lim; cnt++) {
		uint64_t n = 0;
		for (n = 0; n < 1000000; n++)
			n += f_100(n);
		res = n;
	}
}

