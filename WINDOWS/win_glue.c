/*
 * Copyright (C) 2015 Universita` di Pisa. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *   1. Redistributions of source code must retain the above copyright
 *      notice, this list of conditions and the following disclaimer.
 *   2. Redistributions in binary form must reproduce the above copyright
 *      notice, this list of conditions and the following disclaimer in the
 *      documentation and/or other materials provided with the distribution.
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

#include <win_glue.h>

#include <net/netmap.h>
#include <dev/netmap/netmap_kern.h>
#include <dev/netmap/netmap_mem2.h>

/*
 * implementation of some FreeBSD/Linux kernel functions used by netmap.
 */

/*
 *	TIME FUNCTIONS (COPIED FROM DUMMYNET)
 */
void
do_gettimeofday(struct timeval *tv)
{
	static LARGE_INTEGER prevtime; //system time in 100-nsec resolution
	static LARGE_INTEGER prevcount; //RTC counter value
	static LARGE_INTEGER freq; //frequency

	LARGE_INTEGER currtime;
	LARGE_INTEGER currcount;
	if (prevtime.QuadPart == 0) { //first time we ask for system time
		KeQuerySystemTime(&prevtime);
		prevcount = KeQueryPerformanceCounter(&freq);
		currtime.QuadPart = prevtime.QuadPart;
	} else {
		KeQuerySystemTime(&currtime);
		currcount = KeQueryPerformanceCounter(&freq);
		if (currtime.QuadPart == prevtime.QuadPart) {
			//time has NOT changed, calculate time using ticks and DO NOT update
			LONGLONG difftime = 0; //difference in 100-nsec
			LONGLONG diffcount = 0; //clock count difference
			//printf("time has NOT changed\n");
			diffcount = currcount.QuadPart - prevcount.QuadPart;
			diffcount *= 10000000;
			difftime = diffcount / freq.QuadPart;
			currtime.QuadPart += difftime;
		} else {
			//time has changed, update and return SystemTime
			//printf("time has changed\n");
			prevtime.QuadPart = currtime.QuadPart;
			prevcount.QuadPart = currcount.QuadPart;
		}
	}
	currtime.QuadPart /= 10; //convert in usec
	tv->tv_sec = currtime.QuadPart / (LONGLONG)1000000;
	tv->tv_usec = currtime.QuadPart % (LONGLONG)1000000;
	//printf("sec %d usec %d\n",tv->tv_sec, tv->tv_usec);
}



/*
 *	SYSCTL emulation (copied from dummynet/glue.h)
 *
 * This was a mechanism used in dummynet (and early netmap versions)
 * to configure parameters. It is being replaced by other mechansism
 * so the following block of code will likely go away.
 */
static struct sysctltable GST;

void sysctl_addgroup_main_init();
void sysctl_addgroup_vars_pipes();
void sysctl_addgroup_vars_vale();

#if 0
int
kesysctl_emu_get(struct sockopt* sopt)
{
	struct dn_id* oid = sopt->sopt_val;
	struct sysctlhead* entry;
	int sizeneeded = sizeof(struct dn_id) + GST.totalsize +
		sizeof(struct sysctlhead);
	unsigned char* pstring;
	unsigned char* pdata;
	int i;

	if (sopt->sopt_valsize < sizeneeded) {
		// this is a probe to retrieve the space needed for
		// a dump of the sysctl table
		oid->id = sizeneeded;
		sopt->sopt_valsize = sizeof(struct dn_id);
		return 0;
	}

	entry = (struct sysctlhead*)(oid + 1);
	for (i = 0; i<GST.count; i++) {
		entry->blocklen = GST.entry[i].head.blocklen;
		entry->namelen = GST.entry[i].head.namelen;
		entry->flags = GST.entry[i].head.flags;
		entry->datalen = GST.entry[i].head.datalen;
		pdata = (unsigned char*)(entry + 1);
		pstring = pdata + GST.entry[i].head.datalen;
		bcopy(GST.entry[i].data, pdata, GST.entry[i].head.datalen);
		bcopy(GST.entry[i].name, pstring, GST.entry[i].head.namelen);
		entry = (struct sysctlhead*)
			((unsigned char*)(entry)+GST.entry[i].head.blocklen);
	}
	sopt->sopt_valsize = sizeneeded;
	return 0;
}

int
kesysctl_emu_set(void* p, int l)
{
	struct sysctlhead* entry;
	unsigned char* pdata;
	unsigned char* pstring;
	int i = 0;

	entry = (struct sysctlhead*)(((struct dn_id*)p) + 1);
	pdata = (unsigned char*)(entry + 1);
	pstring = pdata + entry->datalen;

	for (i = 0; i<GST.count; i++) {
		if (strcmp(GST.entry[i].name, pstring) != 0)
			continue;
		printf("%s: match found! %s\n", __FUNCTION__, pstring);
		//sanity check on len, not really useful now since
		//we only accept int32
		if (entry->datalen != GST.entry[i].head.datalen) {
			printf("%s: len mismatch, user %d vs kernel %d\n",
				__FUNCTION__, entry->datalen,
				GST.entry[i].head.datalen);
			return -1;
		}
		// check access (at the moment flags handles only the R/W rights
		//later on will be type + access
		if ((GST.entry[i].head.flags & 3) == CTLFLAG_RD) {
			printf("%s: the entry %s is read only\n",
				__FUNCTION__, GST.entry[i].name);
			return -1;
		}
		bcopy(pdata, GST.entry[i].data, GST.entry[i].head.datalen);
		return 0;
	}
	printf("%s: match not found\n", __FUNCTION__);
	return 0;
}
#endif /* not complete yet */

/* convert all _ to . until the first . */
static void
underscoretopoint(char* s)
{
	for (; *s && *s != '.'; s++)
		if (*s == '_')
			*s = '.';
}

static int
formatnames(void)
{
	int i;
	int size = 0;
	char* name;

	for (i = 0; i<GST.count; i++)
		size += GST.entry[i].head.namelen;
	GST.namebuffer = nm_os_malloc(size);
	if (GST.namebuffer == NULL)
		return -1;
	name = GST.namebuffer;
	for (i = 0; i<GST.count; i++) {
		bcopy(GST.entry[i].name, name, GST.entry[i].head.namelen);
		underscoretopoint(name);
		GST.entry[i].name = name;
		name += GST.entry[i].head.namelen;
	}
	return 0;
}

static void
dumpGST(void)
{
	int i;

	for (i = 0; i<GST.count; i++) {
		printf("SYSCTL: entry %i\n", i);
		printf("name %s\n", GST.entry[i].name);
		printf("namelen %i\n", GST.entry[i].head.namelen);
		printf("type %i access %i\n",
			GST.entry[i].head.flags >> 2,
			GST.entry[i].head.flags & 0x00000003);
		printf("data %i\n", *(int*)(GST.entry[i].data));
		printf("datalen %i\n", GST.entry[i].head.datalen);
		printf("blocklen %i\n", GST.entry[i].head.blocklen);
	}
}

void
keinit_GST(void)
{
	int ret;
	int i = 0;

	sysctl_addgroup_main_init();
	sysctl_addgroup_vars_pipes();
	sysctl_addgroup_vars_vale();
	ret = formatnames();
	if (ret != 0)
		printf("conversion of names failed for some reason\n");
	//dumpGST();
	printf("*** Global Sysctl Table entries = %i, total size = %i ***\n",
		GST.count, GST.totalsize);
	for (i = 0; i < GST.count; i++) {
		printf("*** GST[%i]: %s\n", i, GST.entry[i].name);
	}
}

void
keexit_GST()
{
	if (GST.namebuffer != NULL)
		nm_os_free(GST.namebuffer);
	bzero(&GST, sizeof(GST));
}

void
sysctl_pushback(char* name, int flags, int datalen, void* data)
{
	if (GST.count >= GST_HARD_LIMIT) {
		printf("WARNING: global sysctl table full, this entry will not be added,"
			"please recompile the module increasing the table size\n");
		return;
	}
	GST.entry[GST.count].head.namelen = strlen(name) + 1; //add space for '\0'
	GST.entry[GST.count].name = name;
	GST.entry[GST.count].head.flags = flags;
	GST.entry[GST.count].data = data;
	GST.entry[GST.count].head.datalen = datalen;
	GST.entry[GST.count].head.blocklen =
		((sizeof(struct sysctlhead) + GST.entry[GST.count].head.namelen +
		GST.entry[GST.count].head.datalen) + 3) & ~3;
	GST.totalsize += GST.entry[GST.count].head.blocklen;
	GST.count++;
}

static NTSTATUS
netmap_ctl_h(struct sockopt *s, int cmd, int dir, int len, void __user *user)
{
	thread t;
	NTSTATUS ret = STATUS_DEVICE_CONFIGURATION_ERROR;

	memset(s, 0, sizeof(*s));
	s->sopt_name = cmd;
	s->sopt_dir = dir;
	s->sopt_valsize = len;
	s->sopt_val = user;

	/* sopt_td is not used but it is referenced */
	memset(&t, 0, sizeof(t));
	s->sopt_td = &t;

	printf("%s called with cmd %d len %d sopt %p user %p\n", __FUNCTION__, cmd, len, s, user);


	return ret;
}


/*
 * setsockopt hook has no return value other than the error code.
 */
NTSTATUS
do_netmap_set_ctl(struct sock *sk, int cmd, void __user *user, unsigned int len)
{
	struct sockopt s;	/* pass arguments */
	(void)sk;		/* UNUSED */
	return netmap_ctl_h(&s, cmd, SOPT_SET, len, user);
}

/*
 * getsockopt can can return a block of data in response.
 */
NTSTATUS
do_netmap_get_ctl(struct sock *sk, int cmd, void __user *user, int *len)
{
	struct sockopt s;	/* pass arguments */
	NTSTATUS ret = netmap_ctl_h(&s, cmd, SOPT_GET, *len, user);

	(void)sk;		/* UNUSED */
	*len = s.sopt_valsize;	/* return length back to the caller */
	return ret;
}
