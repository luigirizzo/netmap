#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <net/if.h>
#include <net/netmap.h>
#include <net/netmap_user.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <unistd.h>


/*
 * example usage of the extmem feature. The feature is disabled by default.
 * To enable it, add --enable-extmem to the ./configure command when you
 * build netmap.
 */
int main(int argc, char *argv[])
{
	struct nmreq_header hdr;
	struct nmreq_register req;
	struct nmreq_opt_extmem ext;
	struct netmap_if *nif;
	void *addr;
	int mem_fd, netmap_fd;
	const char *ifname, *filename;
	off_t filesize;

	if (argc != 3) {
		fprintf(stderr, "usage: %s <netmap-port> <file>\n", argv[0]);
		exit(1);
	}

	ifname = argv[1];
	filename = argv[2];

	/* with extmem, the netmap port(s) data structures
	 * (if, rings and buffers) will be allocated from a
	 * user-provied memory area. This can be, for example,
	 * a pseudo-file in the hugetlbfs.
	 */

	/* open and mmap the file */
	mem_fd = open(filename, O_RDWR);
	if (mem_fd < 0) {
		perror(filename);
		exit(1);
	}

	filesize = lseek(mem_fd, 0, SEEK_END);
	if (filesize < 0) {
		perror("lseek");
		exit(1);
	}

	addr = mmap(NULL, filesize, PROT_READ | PROT_WRITE, MAP_SHARED, mem_fd, 0);
	if (addr == MAP_FAILED) {
		perror("mmap");
		exit(1);
	}

	/* the new netmap API has a NIOCCTRL ioctl() for all kinds
	 * of netmap control requests (opening a port, creating
	 * persistent vale ports, etc.). All requests are made up
	 * of a common header (struct nmreq_header) which points
	 * to a request-specific body (struct nmreq_register for
	 * opening ports). The header may also point to a list of
	 * options. Extmem is one such option.
	 */

	/* create an option with type EXTMEM, passing the address
	 * of the mmap()ed memory and its size
	 */
	memset(&ext, 0, sizeof(ext));
	ext.nro_opt.nro_reqtype = NETMAP_REQ_OPT_EXTMEM;
	ext.nro_usrptr          = (uintptr_t)addr;
	ext.nro_info.nr_memsize = filesize;

	/* initialize the register request */
	memset(&req, 0, sizeof(req));
	req.nr_mode = NR_REG_ALL_NIC; /* or whatever */

	/* initialize the header */
	memset(&hdr, 0, sizeof(hdr));
	hdr.nr_version = NETMAP_API;
	/* NOTE: this is the ifname without the 'netmap:' prefix,
	 * but possibly including the '{' or '}' symbol for opening
	 * a netmap pipe. The pipe identifier can be any alphanumeric
	 * string, not just numbers. For VALE ports, use the entire
	 * valeXXX:yyy name.
	 */
	strncpy(hdr.nr_name, ifname, sizeof(hdr.nr_name) - 1);
	hdr.nr_reqtype = NETMAP_REQ_REGISTER;
	/* link the request body */
	hdr.nr_body    = (uintptr_t)&req;
	/* and the head of the options list */
	hdr.nr_options = (uintptr_t)&ext;

	/* now pass everything to the kernel */
        netmap_fd = open("/dev/netmap", O_RDWR);
	if (netmap_fd < 0) {
		perror("/dev/netmap");
		exit(1);
	}

	if (ioctl(netmap_fd, NIOCCTRL, &hdr) < 0) {
		/* EOPNOTSUPP if extmem was not compiled in */
		perror(ifname);
		exit(1);
	}

	/* now we can use the mmap()ed area (NOTE: mmap() of "/dev/netmap" will
	 * fail, so we must use the 'addr' obtained above.)
	 *
	 * Other processes can share the memory (e.g., to open other ports in
	 * the same region) but they must mmap() the original file and go
	 * through the same procedure as above.
	 */

	nif = NETMAP_IF(addr, req.nr_offset);

	/* and so on ... */
	(void)nif;
	return 0;
}
