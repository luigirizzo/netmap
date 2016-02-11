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
#include "rpcap.h"

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
    struct pcap_file *fpc = readpcap(file);
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
    pcaprec_hdr_t hdr;
    unsigned char *data;
    struct pkt_list_element* p;
};

#endif /* TEST_MODE */

packet_data *new_packet_data(void)
{
    packet_data *pkt = (packet_data *)calloc(sizeof(packet_data), 1);
    return pkt;
}

struct pcap_file *new_fpcap(void)
{
    struct pcap_file *ret = (struct pcap_file *)calloc(1, sizeof(*ret));
    return ret;
}


// Destroy a pcap list
void destroy_pcap_list(struct pcap_file **file)
{
    struct pcap_file *f = file ? *file : NULL;
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
void insert_pkt(struct pcap_file *file, packet_data *pkt)
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
    (pkt->hdr.ts_sec == a->hdr.ts_sec && pkt->hdr.ts_usec >= a->hdr.ts_usec))) {
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
int read_next_info(FILE *fp, void *_data, int size, char swap)
{
    int i;
    unsigned char tmp, *data = _data;
    i = fread(data, 1, size, fp);
    if (i != size) {
        //fprintf("Error reading file pcap header\n");
        return i;
    }
    if (swap) {
        for (i = 0; i < size / 2; i++) {
            tmp = data[i];
            data[i] = data[size - (1 + i)];
            data[size - (1 + i)] = tmp;
        }
    }
    return size;
}

// Allocate a new pcap file structure, read infos from file and return
// structure's address
struct pcap_file *readpcap(FILE *fp)
{
    struct pcap_file *filepcap = new_fpcap();
    packet_data *pkt;
    int ret;
    // If the system's byte ordering is different than file's, swap = 1
    char swap;
    pcap_hdr_t *h;
    pcaprec_hdr_t *ph;
    const int L4 = sizeof(uint32_t); /* four, for all practical purposes */
    const int L2 = sizeof(uint16_t); /* two, for all practical purposes */

    h = filepcap->ghdr = (pcap_hdr_t *)calloc(1, sizeof(pcap_hdr_t));

    ret = fread(&(h->magic_number), 1, L4, fp);
    if (ret != L4) {
        goto fail;
    }
    switch (h->magic_number) {
        case 0xa1b2c3d4:
            swap = 0;
            filepcap->ghdr->resolution = 'm';
            break;
        case 0xd4c3b2a1:
            swap = 0;
            filepcap->ghdr->resolution = 'm';
            break;
        case 0xa1b23c4d:
            swap = 0;
            filepcap->ghdr->resolution = 'n';
            break;
        case 0x4d3cb2a1:
            swap = 1;
            filepcap->ghdr->resolution = 'n';
            break;
        default:
            goto fail;
    }

    if (read_next_info(fp, &(h->version_major), L2, swap) != L2 ||
        read_next_info(fp, &(h->version_minor), L2, swap) != L2 ||
        read_next_info(fp, &(h->thiszone), L4, swap) != L4 ||
        read_next_info(fp, &(h->stampacc), L4, swap) != L4 ||
        read_next_info(fp, &(h->snaplen), L4, swap) != L4 ||
        read_next_info(fp, &(h->network), L4, swap) != L4) {
            goto fail;
    }
    while(1) {
        pkt = new_packet_data();
	ph = &pkt->hdr;

        ret = read_next_info(fp, &(ph->ts_sec), L4, swap);
        if (ret != L4) {
            if (ret == 0) {
                // If no elements have been inserted in the data structure
                if (!filepcap->list) {
                    goto fail;
                }
                break;
            }
            goto fail;
        }
        if (read_next_info(fp, &(ph->ts_usec), L4, swap) != L4 ||
            read_next_info(fp, &(ph->incl_len), L4, swap) != L4 ||
            read_next_info(fp, &(ph->orig_len), L4, swap) != L4) {
                goto fail;
        }
	/* XXX we only grab the captured length, but actual lenght might be higher */
        pkt->data = (unsigned char *)malloc(ph->incl_len);
        if (fread(pkt->data, 1, ph->incl_len, fp) < ph->incl_len) {
            goto fail;
        }
        insert_pkt(filepcap, pkt);
        h->tot_len += pkt->hdr.incl_len;
        h->tot_pkt++;
    }

    return filepcap;

fail:
    fprintf(stderr, "Error reading pcap file\n");
    destroy_pcap_list(&filepcap);
    return NULL;
}
