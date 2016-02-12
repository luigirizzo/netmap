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
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h> /* memcpy */
#include "rpcap.h"

#include <sys/mman.h>

#define NS_SCALE 1000000000UL	/* nanoseconds in 1s */

#if 0
Read a pcap file, create a memory structure with the expanded packets.
#endif

/*
 * a simple library to read from a pcap file into a list
 * of packets in memory.
 */
#ifdef TEST_MODE


int main(int argc, char *argv[])
{
    int file = open("file.cap", O_RDONLY);
    if (file < 0) {
        fprintf(stderr, "Error opening file\n");
    }
    struct nm_pcap_file *fpc = readpcap(file);
    printf("Hello world!\n");
    destroy_pcap_list(&fpc);
    return 0;
}


/* The packets are organized in a list inside the pcap file structure. Each list
   element has the following members:
   - A packet header
   - packet payload
   - Pointer to the next packet
*/
struct pkt_list_element {
    struct pcap_pkthdr hdr;
    unsigned char *data;
    struct pkt_list_element* p;
};

#endif /* TEST_MODE */

packet_data *new_packet_data(void)
{
    packet_data *pkt = (packet_data *)calloc(sizeof(packet_data), 1);
    return pkt;
}


// Destroy a pcap list
void destroy_pcap_list(struct nm_pcap_file **file)
{
    struct nm_pcap_file *f = file ? *file : NULL;
    packet_data *tmp;

    if (!f)
	return;

    if (f->ghdr) {
        free(f->ghdr);
        f->ghdr = NULL;
    }
    while (f->list) {
        tmp = f->list->p;
        if (f->list->data) {
            free(f->list->data);
            f->list->data = NULL;
        }
        free(f->list);
        f->list = tmp;
    }
    free(f);
    *file = NULL;
}

// Insert a packet in the pcap file struct ordered by timestamp
/*
 * XXX this is very inefficient.
 */
void insert_pkt(struct nm_pcap_file *file, packet_data *pkt)
{
    packet_data *a, *b = NULL;

    if (pkt == NULL)
	return;
    // Empty list
    if (file->list == NULL) {
        file->list = pkt;
        file->end = pkt;
        return;
    }
    a = file->list;
    while (a && (pkt->hdr.ts_sec >= a->hdr.ts_sec ||
    (pkt->hdr.ts_sec == a->hdr.ts_sec && pkt->hdr.ts_frac >= a->hdr.ts_frac))) {
        b = a;
        a = a->p;
    }
    // insert in head
    if (a == file->list) {
        pkt->p = file->list;
        file->list = pkt;
        return;
    }
    // insert at the end
    if (a == NULL) {
        file->end->p = pkt;
        file->end = pkt;
        return;
    }
    // insert in the middle
    pkt->p = a;
    b->p = pkt;
    return;
}

// Read file pcap's header info and swap the content if the file has a byte
// ordering different than system byte ordering
static uint32_t
cvt(const void *src, int size, char swap)
{
    uint32_t ret = 0;
    if (size != 2 && size != 4) {
	fprintf(stderr, "Invalid size %d\n", size);
	exit(1);
    }
    memcpy(&ret, src, size);
    if (swap) {
	unsigned char tmp, *data = (unsigned char *)&ret;
	int i;
        for (i = 0; i < size / 2; i++) {
            tmp = data[i];
            data[i] = data[size - (1 + i)];
            data[size - (1 + i)] = tmp;
        }
    }
    return ret;
}

static uint32_t
read_next_info(struct nm_pcap_file *pf, int size)
{
    const char *end = pf->cur + size;
    uint32_t ret;
    if (end > pf->lim) {
	pf->err = 1;
	ret = 0;
    } else {
	ret = cvt(pf->cur, size, pf->swap);
	pf->cur = end;
    }
    return ret;
}

/*
 * mmap the file, make sure timestamps are sorted, and count
 * packets and sizes
 */
struct nm_pcap_file *readpcap(const char *fn)
{
    struct nm_pcap_file _f, *pf = &_f;
    uint64_t prev_ts;

    bzero(pf, sizeof(*pf));
    pf->fd = open(fn, O_RDONLY);
    if (pf->fd < 0) {
	fprintf(stderr, "-- cannot open file %s, abort\n", fn);
	return NULL;
    }
    /* compute length */
    pf->filesize = lseek(pf->fd, 0, SEEK_END);
    lseek(pf->fd, 0, SEEK_SET);
    fprintf(stderr, "filesize is %d\n", (int)(pf->filesize));
    if (pf->filesize < sizeof(struct pcap_file_header)) {
	fprintf(stderr, "-- file too short %s, abort\n", fn);
	close(pf->fd);
	return NULL;
    }
    pf->data = mmap(NULL, pf->filesize, PROT_READ, MAP_SHARED, pf->fd, 0);
    if (pf->data == MAP_FAILED) {
	fprintf(stderr, "-- cannot mmap file %s, abort\n", fn);
	close(pf->fd);
	return NULL;
    }
    pf->ghdr = (void *)pf->data;
    switch (pf->ghdr->magic_number) {
        case 0xa1b2c3d4:
            pf->swap = 0;
            pf->resolution = 1000;
            break;
        case 0xd4c3b2a1:
            pf->swap = 0;
            pf->resolution = 1000;
            break;
        case 0xa1b23c4d:
            pf->swap = 0;
            pf->resolution = 1; /* nanoseconds */
            break;
        case 0x4d3cb2a1:
            pf->swap = 1;
            pf->resolution = 1; /* nanoseconds */
            break;
        default:
	    fprintf(stderr, "unknown magic 0x%x\n", pf->ghdr->magic_number);
            return NULL;
    }

    fprintf(stderr, "swap %d res %d\n", pf->swap, pf->resolution);
    pf->cur = pf->data + sizeof(struct pcap_file_header);
    pf->lim = pf->data + pf->filesize;
    pf->err = 0;
    prev_ts = 0;
    while (pf->cur < pf->lim && pf->err == 0) {
	uint32_t base = pf->cur - pf->data;
	uint64_t cur_ts = read_next_info(pf, 4) * NS_SCALE +
		read_next_info(pf, 4) * pf->resolution;
	uint32_t caplen = read_next_info(pf, 4);
	uint32_t len = read_next_info(pf, 4);

	if (pf->err) {
	    fprintf(stderr, "end of pcap file after %d packets\n",
		(int)pf->tot_pkt);
	    break;
	}
	if  (cur_ts < prev_ts) {
	    fprintf(stderr, "reordered packet %d\n",
		(int)pf->tot_pkt);
	}
	prev_ts = cur_ts;
	fprintf(stderr, "%5d: base 0x%x len %5d caplen %d ts 0x%llx\n",
		(int)pf->tot_pkt, base, len, caplen, (unsigned long long)cur_ts);
	pf->tot_pkt++;
	pf->tot_bytes += len;
	pf->cur += caplen;
    }
    return NULL;
}
