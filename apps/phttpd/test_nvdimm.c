/*
 * Copyright (C) 2016-2017 Michio Honda. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *   1. Redistributions of source code must retain the above copyright
 *      notice, this list of conditions and the following disclaimer.
 *   2. Redistributions in binary form must reproduce the above copyright
 *      notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <inttypes.h>
#include <sys/poll.h>
#include <sys/epoll.h>
#include <sys/stat.h>

#include <sys/socket.h>
#include <sys/mman.h>
#include <net/if.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <stddef.h>	// typeof
#include <x86intrin.h>
#include <time.h>

#include <sys/ioctl.h>
#include <signal.h>
#include <fcntl.h>
#include <time.h>	// clock_gettime()
#include <netinet/tcp.h>
#ifdef WITH_SQLITE
#include <sqlite3.h>
#endif /* WITH_SQLITE */
#include <pthread.h>
#include <net/netmap.h>
#include <net/netmap_user.h>

#include<sched.h>
#include "nmlib.h"

#define STMNAME	"stack:0"
#define STMNAME_MAX	64

#define MAX_PAYLOAD	1400
#define min(a, b) (((a) < (b)) ? (a) : (b)) 

#ifndef D
#define D(fmt, ...) \
	printf(""fmt"\n", ##__VA_ARGS__)
#endif

#define MAXDUMBSIZE	204800

static char *
_do_mmap(int fd, int len)
{
	char *p;

	if (lseek(fd, len -1, SEEK_SET) < 0) {
		perror("lseek");
		return NULL;
	}
	if (write(fd, "", 1) != 1) {
		perror("write");
		return NULL;
	}
	p = mmap(0, len, PROT_WRITE, MAP_SHARED | MAP_FILE, fd, 0);
	if (p == MAP_FAILED) {
		perror("mmap");
		return NULL;
	}
	return p;
}

int
main(int argc, char **argv)
{
	struct nm_garg g;
	struct netmap_pools_info *pi;
	int extmem_fd = 0;

	bzero(&g, sizeof(g));

	g.nmr_config= "";
	g.nthreads = 1;
	g.td_privbody = NULL;
	g.polltimeo = 2000;
	g.dev_type = DEV_NETMAP;

	strcpy(g.ifname, argv[1]);
	D("ifname %s", g.ifname);
	g.td_type = TD_TYPE_DUMMY;

	extmem_fd = open(DEFAULT_EXT_MEM, O_RDWR|O_CREAT, S_IRWXU);
        if (extmem_fd < 0) {
		perror("open");
		return 0;
	}
	g.extmem = _do_mmap(extmem_fd, DEFAULT_EXT_MEM_SIZE);
	if (g.extmem == NULL) {
		D("mmap failed");
		goto close_ext;
	}

	pi = (struct netmap_pools_info *)g.extmem;
	pi->memsize = DEFAULT_EXT_MEM_SIZE;
	if (nm_start(&g) < 0) {
		D("nm_open failed");
	} else {
		D("nm_open success");
	}
	if (g.extmem)
		munmap(g.extmem, DEFAULT_EXT_MEM_SIZE);
close_ext:
	close(extmem_fd);
	//free(dbi.g.extmem);
	return (0);
}
