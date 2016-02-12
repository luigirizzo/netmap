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
#ifndef RCAP_H_INCLUDED
#define RCAP_H_INCLUDED


/*
 * The header for a pcap file
 * This data structs need to be transfered in rpcap.c once debug is completed
 */
struct pcap_file_header {
    uint32_t magic_number;
	/*used to detect the file format itself and the byte
    ordering. The writing application writes 0xa1b2c3d4 with it's native byte
    ordering format into this field. The reading application will read either
    0xa1b2c3d4 (identical) or 0xd4c3b2a1 (swapped). If the reading application
    reads the swapped 0xd4c3b2a1 value, it knows that all the following fields
    will have to be swapped too. For nanosecond-resolution files, the writing
    application writes 0xa1b23c4d, with the two nibbles of the two lower-order
    bytes swapped, and the reading application will read either 0xa1b23c4d
    (identical) or 0x4d3cb2a1 (swapped)*/
    uint16_t version_major;
    uint16_t version_minor; /*the version number of this file format */
    int32_t thiszone;
	/*the correction time in seconds between GMT (UTC) and the
    local timezone of the following packet header timestamps. Examples: If the
    timestamps are in GMT (UTC), thiszone is simply 0. If the timestamps are in
    Central European time (Amsterdam, Berlin, ...) which is GMT + 1:00, thiszone
    must be -3600*/
    uint32_t stampacc; /*the accuracy of time stamps in the capture*/
    uint32_t snaplen;
	/*the "snapshot length" for the capture (typically 65535
    or even more, but might be limited by the user)*/
    uint32_t network;
	/*link-layer header type, specifying the type of headers
    at the beginning of the packet (e.g. 1 for Ethernet); this can be various
    types such as 802.11, 802.11 with various radio information, PPP, Token
    Ring, FDDI, etc.*/
};

#if 0 /* from pcap.h */
struct pcap_file_header {
        bpf_u_int32 magic;
        u_short version_major;
        u_short version_minor;
        bpf_int32 thiszone;     /* gmt to local correction */
        bpf_u_int32 sigfigs;    /* accuracy of timestamps */
        bpf_u_int32 snaplen;    /* max length saved portion of each pkt */
        bpf_u_int32 linktype;   /* data link type (LINKTYPE_*) */
} __attribute((packed));
struct pcap_pkthdr {
        struct timeval ts;      /* time stamp */
        bpf_u_int32 caplen;     /* length of portion present */
        bpf_u_int32 len;        /* length this packet (off wire) */
};
#endif /* from pcap.h */

struct pcap_pkthdr {
    uint32_t ts_sec; /* seconds from epoch */
    uint32_t ts_frac; /* microseconds or nanoseconds depending on sigfigs */
    uint32_t caplen;
	/*the number of bytes of packet data actually captured
    and saved in the file. This value should never become larger than orig_len
    or the snaplen value of the global header*/
    uint32_t len;	/* wire length */
};
/* Data needs to be transfered untill here*/


struct pkt_list_element {
    struct pcap_pkthdr hdr;
    unsigned char *data;
    struct pkt_list_element* p;
};

#define PKT_PAD         (32)    /* padding on packets */

static inline int pad(int x)
{
        return ((x) + PKT_PAD - 1) & ~(PKT_PAD - 1) ;
}



/* The pcap file structure has the following members:
   - A global header which is struct pcap_file_header
   - A list of packets with the following members:
       + A packet header
       + packet payload
       + Pointer to the next packet
   - A pointer to the last packet in the list
*/
struct nm_pcap_file {
    struct pcap_file_header *ghdr;

    int fd;
    uint64_t filesize;
    uint64_t tot_pkt;
    uint64_t tot_bytes;
    uint64_t tot_bytes_rounded;	/* need hdr + pad(len) */
    struct pcap_pkthdr *reorder; /* array of size tot_pkt for reordering */
    uint32_t resolution; /* 1000 for us, 1 for ns */
    int swap; /* need to swap fields ? */

    uint64_t first_ts;
    uint64_t file_len;
    const char *data; /* mmapped file */
    const char *cur;	/* running pointer */
    const char *lim;	/* data + file_len */
    int err;
};

struct nm_pcap_file *readpcap(const char *fn);
void destroy_pcap_list(struct nm_pcap_file *file);


#endif // RCAP_H_INCLUDED
