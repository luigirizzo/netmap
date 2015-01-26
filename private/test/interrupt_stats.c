#include <stdio.h>
#include <err.h>

#include <sys/types.h>
#include <sys/param.h>
#include <sys/sysctl.h> /* sysctl* */
#include <sys/selinfo.h> /* selinfo */
#include <sys/socket.h> /* sockaddr */
#include <sys/mbuf.h>
#include <machine/bus.h> /* bus_addr_t */
#include <sys/bus_dma.h> /* dma*tag */

#include <net/if.h>

#include <net/netmap.h>
#include <dev/netmap/netmap_kern.h>


int
main(int argc, char **argv)
{
	struct stats statz;
	size_t slen;
	char cmd[256];
	int i;

	if (argc < 2) {
		fprintf(stderr, "Usage: %s driver"
				"\n"
				"supported drivers: lem, ixgbe\n"
				"",
				argv[0]);
		return 1;
	}

	snprintf(cmd, sizeof(cmd), "dev.%s.stats", argv[1]);

	slen = sizeof(statz);
	if (sysctlbyname(cmd, &statz, &slen, NULL, 0)) {
		warn("unable to read %s", cmd);
		return 1;
	}

	for (i = 0; i < NETMAP_MAX_STATS; i++)
		fprintf(stdout, "%llu %u %u\n",
				statz.statsdata[i].tsc,
				statz.statsdata[i].unit,
				statz.statsdata[i].queue);
	return 0;
}
