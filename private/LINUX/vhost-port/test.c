#include "buildpkt.h"

#include <stdio.h>
#include <stdint.h>
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <fcntl.h>
#include <string.h>
#include <pthread.h>
#include <semaphore.h>
#include <sys/select.h>
#include <sys/eventfd.h>
#include <sys/time.h>


#ifndef u16
#define u16 uint16_t
#endif
#include <linux/virtio_net.h>	/* struct virtio_net_hdr */

#include "tun_alloc.h"
#include "paravirt.h"
#include "v1000_user.h"


/* ========================== Useful macros =============================== */
typedef unsigned char bool;
#define false   0
#define true    1

/* GCC compiler barrier (from Wikipedia). */
#define compiler_barrier()  do { \
				asm volatile("" ::: "memory"); \
			    } while (0)
/* ======================================================================= */


#define RATE	/* Enable rating & statistics. */
bool check_rx_payload = 1;
bool use_resamplefd = 0;
bool tx_context_descriptor = 1;



/* The e1000 TX and RX descriptor rings. */
#define NUM_DESCRIPTORS 256
static struct e1000_tx_desc tx_desc_mem[NUM_DESCRIPTORS];
static struct e1000_rx_desc rx_desc_mem[NUM_DESCRIPTORS];

/* TX and RX vnet-hdr rings. The first NUM_DESCRIPTORS are for
   transmission, while the others are for reception. */
static struct virtio_net_hdr vnet_hdr_rings[2*NUM_DESCRIPTORS];

/* The packet buffers. The first TX_SKBUFFS are for transmission,
   while the others are for reception. */
#define NUM_SKBUFFS 1000
#define NUM_TX_SKBUFFS (NUM_SKBUFFS/2)
#define NUM_RX_SKBUFFS (NUM_SKBUFFS-NUM_TX_SKBUFFS)
static struct pkt skbuffs[NUM_SKBUFFS];
static int skb_tx = 0;
static int skb_rx = 0;
#define ETH_FRAME_SIZE	490U
#define ETH_FRAME_SIZE_STR  "490"
#define MAX_NUM_FRAGS   9

/* Fake physical base addresses. Please make sure they
   don't overlap. */
#define CSB_PHY		15000000
#define TXRING_PHY	22000000
#define RXRING_PHY	68000000
#define VNET_RING_PHY	101000000
#define SKBUFFS_PHY	258000000


/* The communication status block. */
static struct paravirt_csb csb_mem;


/* V1000 configuration. */
struct V1000Config config;

/* Flag to stop sender and receiver threads. */
static int stop = 0;

/* Create a new eventfd. */
static void new_eventfd(uint32_t * fdp)
{
    int efd;
    int initval = 0;
    int flags = 0;

    if ((efd = eventfd(initval, flags)) < 0) {
	perror("eventfd()\n");
	exit(EXIT_FAILURE);
    }
    *fdp = (uint32_t)efd;
}

/* Set the ring parameters. */
static void configure_ring(struct V1000RingConfig * rc, uint64_t phy, bool physical, uint64_t hdr_phy, void * hdr_virt)
{
    rc->phy = phy;
    if (physical)
        rc->hdr.phy = hdr_phy;
    else
        rc->hdr.virt = hdr_virt;
    rc->num = NUM_DESCRIPTORS;
    new_eventfd(&rc->ioeventfd);
    new_eventfd(&rc->irqfd);
    if (use_resamplefd)
        new_eventfd(&rc->resamplefd);
    else
        rc->resamplefd = ~0U;
}

/* Set a row of the translation table. */
static void configure_table(struct V1000Config * cfg, unsigned idx, uint64_t phy, uint64_t length, void * virt)
{
    if (idx >= MAX_TRANSLATION_ELEMENTS) {
	printf("idx too big (%d)\n", idx);
	exit(EXIT_FAILURE);
    }

    cfg->tr.table[idx].phy = phy;
    cfg->tr.table[idx].length = length;
    cfg->tr.table[idx].virt = virt;
}

/* Configure the v1000 device. */
static void configure(int vfd, const char * si, const char * ri,
			struct V1000Config * cfg)
{
    char tapname[IFNAMSIZ];
    int n;
    int tfd;

    configure_ring(&cfg->tx_ring, TXRING_PHY, false, 0, &vnet_hdr_rings);
    configure_ring(&cfg->rx_ring, RXRING_PHY, true, VNET_RING_PHY, NULL);

    cfg->rxbuf_size = sizeof(struct pkt);

    cfg->csb_phy = CSB_PHY;

    memset(&cfg->tr, 0, sizeof(struct V1000Translation));
    configure_table(cfg, 0, cfg->tx_ring.phy,
			cfg->tx_ring.num * sizeof(struct e1000_tx_desc),
			    &tx_desc_mem[0]);
    configure_table(cfg, 1, cfg->rx_ring.phy,
			cfg->rx_ring.num * sizeof(struct e1000_rx_desc),
			    &rx_desc_mem[0]);
    configure_table(cfg, 2, SKBUFFS_PHY, NUM_SKBUFFS * sizeof(struct pkt),
			&skbuffs[0]);
    configure_table(cfg, 3, cfg->csb_phy, NET_PARAVIRT_CSB_SIZE, &csb_mem);
    configure_table(cfg, 4, cfg->rx_ring.hdr.phy,
                    cfg->rx_ring.num * sizeof(struct virtio_net_hdr),
                    &vnet_hdr_rings[cfg->tx_ring.num]);
    cfg->tr.num = 5;

    strcpy(tapname, "tap");
    strcpy(tapname + 3, ri);
    tfd = tun_alloc(tapname, IFF_TAP | IFF_NO_PI | IFF_VNET_HDR);
    if (tfd < 0) {
	perror("tun_alloc()\n");
	exit(EXIT_FAILURE);
    }
    cfg->tapfd = tfd;

    /* Flush the configuration to the v1000 device. */
    n = write(vfd, cfg, sizeof(struct V1000Config));
    if (n != sizeof(struct V1000Config)) {
	perror("v1000 configuration failed!\n");
	printf("write returned %d\n", n);
	exit(EXIT_FAILURE);
    }
}

/* Closes all the file descriptors opened. */
static void cleanup(int vfd, struct V1000Config * cfg)
{
    close(cfg->tx_ring.ioeventfd);
    close(cfg->tx_ring.irqfd);
    if (use_resamplefd)
        close(cfg->tx_ring.resamplefd);
    close(cfg->rx_ring.ioeventfd);
    close(cfg->rx_ring.irqfd);
    if (use_resamplefd)
        close(cfg->rx_ring.resamplefd);
    close(cfg->tapfd);
    close(vfd);
}

/* CSB initialization. */
static void csb_init(struct paravirt_csb * csb)
{
    csb->guest_tdt = 0;
    csb->guest_need_txkick = 0;
    csb->guest_need_rxkick = 1;
    csb->guest_csb_on = 1;
    csb->guest_rdt = 0;
    csb->guest_txkick_at = ~0;
    csb->host_tdh = 0;
    csb->host_need_txkick = 1;
    csb->host_txcycles_lim = 1;
    csb->host_txcycles = 0;
    csb->host_rdh = 0;
    csb->host_need_rxkick = 1;
    csb->host_isr = 0;
    csb->host_rxkick_at = 0;
    csb->vnet_ring_high = 0;	//XXX
    csb->vnet_ring_low = 0; //XXX
}

/* Prefill all the TX frames. */
static void build_tx_frames(const char * si, const char * ri,
			    struct pkt * frames, int num)
{
#define NUM_ARGS 10
    char * argv[NUM_ARGS];
    char argc;
    uint32_t i;

    memset(frames, 0, num * sizeof(struct pkt));

    /* Some memory for the string arguments. */
    for (i=0; i<NUM_ARGS; i++)
	argv[i] = malloc(30);

    if (si) {
	strcpy(argv[0], "00:aa:bb:cc:de:");	/* DST MAC */
	strcpy(argv[0] + strlen("00:aa:bb:cc:de:"), si);
    } else {
	strcpy(argv[0], "62:86:71:33:38:9b");
    }

    strcpy(argv[1], "00:aa:bb:cc:de:");	/* SRC MAC */
    strcpy(argv[1] + strlen("00:aa:bb:cc:de:"), ri);

    if (si) {
	strcpy(argv[2], "10.1.1.");		/* DST IP */
	strcpy(argv[2] + strlen("10.1.1."), si);
    } else {
	strcpy(argv[2], "10.1.1.200");
    }

    strcpy(argv[3], "10.1.1.");		/* SRC IP */
    strcpy(argv[3] + strlen("10.1.1."), ri);

    strcpy(argv[4], "7778");			/* DST PORT */
    strcpy(argv[5], "7777");			/* SRC PORT */
    strcpy(argv[6], ETH_FRAME_SIZE_STR);	/* ETH FRAME SIZE */
    argc = 7;

    for (i=0; i<num; i++)
	build_packet_from_args(argc, argv, frames + i, i, !tx_context_descriptor);
}

static uint32_t clean_used_tx_descriptors(volatile struct e1000_tx_desc * tx_desc, uint32_t ntc)
{
    /* TODO implement next_to_watch! */
    while (tx_desc[ntc].upper.data & E1000_TXD_STAT_DD) {
	tx_desc[ntc].upper.data = 0;
	if (++ntc == NUM_DESCRIPTORS)
	    ntc = 0;
    }

    return ntc;
}

static inline uint32_t tx_descriptors_avail(uint32_t tdt, uint32_t ntc)
{
    return ((NUM_DESCRIPTORS + ntc) - tdt - 1) % NUM_DESCRIPTORS;

}

static void * sender(void * opaque)
{
    struct V1000Config * cfg = opaque;
    volatile struct e1000_tx_desc * tx_desc = &tx_desc_mem[0];
    volatile struct e1000_context_desc * txc_desc = (struct e1000_context_desc *)&tx_desc_mem[0];
    volatile struct paravirt_csb * csb = &csb_mem;
    uint32_t ntc = 0;
    uint32_t rate_txkicks = 0;
    uint32_t rate_txpkts = 0;
    struct pkt * frame; /* Only used for sizeof() calculation. */

    while (!stop) {
	uint64_t event = 1;
	uint32_t tdt;
	unsigned int frags = 1;
	unsigned int offset;
	unsigned int frag_size;

	/* Clean used descriptors. */
	ntc = clean_used_tx_descriptors(tx_desc, ntc);

	tdt = csb->guest_tdt;
        /* We need space for MAX_NUM_FRAGS and a context descriptor. */
	if (tx_descriptors_avail(tdt, ntc) < MAX_NUM_FRAGS+1) {
	    //printf("TX ring full\n");
	    csb->guest_need_txkick = 1;
	    compiler_barrier();
	    /* Doublecheck. */
	    ntc = clean_used_tx_descriptors(tx_desc, ntc);
	    if (tx_descriptors_avail(tdt, ntc) >= MAX_NUM_FRAGS+1)
		goto more_used;
	    if (read(cfg->tx_ring.irqfd, &event, sizeof(event))
		    != sizeof(event)) {
		perror("read(tx_ring.irqfd)\n");
		exit(EXIT_FAILURE);
	    }
more_used:
	    csb->guest_need_txkick = 0;
	    compiler_barrier();
	    continue;
	}

        /* Insert a context descriptor. */
        if (tx_context_descriptor) {
            txc_desc[tdt].lower_setup.ip_config = 0;
            txc_desc[tdt].upper_setup.tcp_fields.tucss = sizeof(frame->eh) + sizeof(frame->ip); /* 34 */
            txc_desc[tdt].upper_setup.tcp_fields.tucso = txc_desc[tdt].upper_setup.tcp_fields.tucss + 6;
            txc_desc[tdt].upper_setup.tcp_fields.tucse = 0; /* Checksum up to the end of the frame. */
            txc_desc[tdt].cmd_and_length = E1000_TXD_CMD_DEXT | E1000_TXD_DTYP_C
                                            | E1000_TXD_CMD_RS; /* TODO remove this flag when implement next-to-watch */
            txc_desc[tdt].tcp_seg_setup.data = 0;
	    if (++tdt == NUM_DESCRIPTORS)
		tdt = 0;
        }

	/* Insert a new frame in the ring, using as many TX descriptors
	   as needed. */
	offset = 0;
	frag_size = ETH_FRAME_SIZE / frags;
	if (frag_size > 0xffff) {
	    printf("Fragment too big (%d)\n", frag_size);
	    return NULL;
	}
	while (offset < ETH_FRAME_SIZE) {
	    tx_desc[tdt].upper.data = 0;
	    tx_desc[tdt].lower.data = E1000_TXD_DTYP_D | E1000_TXD_CMD_DEXT
                                        | E1000_TXD_CMD_RS; /* TODO remove this flag when implement next-to-watch */
	    if (ETH_FRAME_SIZE - offset <= frag_size) {
		frag_size = ETH_FRAME_SIZE - offset;
		tx_desc[tdt].lower.data |= E1000_TXD_CMD_EOP
					   | E1000_TXD_CMD_RS;
	    }
            /* Request the NIC to insert a TCP/UDP checksum by setting
               the proper bit in the POPTS field of the first data
               descriptor packet. */
            if (tx_context_descriptor && offset == 0)
                tx_desc[tdt].upper.data |= ((E1000_TXD_POPTS_TXSM) << 8);

	    tx_desc[tdt].buffer_addr = SKBUFFS_PHY + skb_tx
					* sizeof(struct pkt) + offset;
	    tx_desc[tdt].lower.data |= frag_size;
	    offset += frag_size;
	    //printf("[tdt=%u]: phy=%lu, lower.data=%u\n", tdt, tx_desc[tdt].buffer_addr, tx_desc[tdt].lower.data);
	    if (++tdt == NUM_DESCRIPTORS)
		tdt = 0;
	}
	rate_txpkts++;
	if (++skb_tx == NUM_TX_SKBUFFS)
	    skb_tx = 0;

	compiler_barrier();

	/* Kick the v1000 tx frontend (if is the case. */
	csb->guest_tdt = tdt;
	if (csb->host_need_txkick) {
	    write(cfg->tx_ring.ioeventfd, &event, sizeof(event));
	    rate_txkicks++;
	    //printf("TX kick\n");
	}
	/*printf("ntc=%d, tdt=%d\n", ntc, tdt);
	  printf("txpkts=%d, txkicks=%d\n", rate_txpkts, rate_txkicks);*/
    }

    return NULL;
}

struct sgvec {
    uint64_t phy;
    uint64_t len;
};

/* Prepare new available RX descriptors. */
static uint32_t prepare_rx_descriptors(volatile struct e1000_rx_desc* desc,
					uint32_t idx, int num)
{
    while (num) {
	desc[idx].buffer_addr = SKBUFFS_PHY + 
			(NUM_TX_SKBUFFS + skb_rx) * sizeof(struct pkt);
	desc[idx].length = 0;
	desc[idx].csum = 0;
	desc[idx].status = 0;
	desc[idx].errors = 0;
	desc[idx].special = 0;
	if (++idx == NUM_DESCRIPTORS)
	    idx = 0;
	if (++skb_rx == NUM_RX_SKBUFFS)
	    skb_rx = 0;
	num--;
    }

    return idx;
}

static int check_rx_header(volatile struct virtio_net_hdr * hdr)
{
   return hdr->flags || hdr->gso_type != VIRTIO_NET_HDR_GSO_NONE ||
	    hdr->hdr_len || hdr->gso_size || hdr->csum_start ||
	    hdr->csum_offset;
}

static void print_hex(const char * name, unsigned char * d, int size)
{
    int i;

    printf("%s: ", name);
    for (i=0; i<size; i++)
	printf("%02X", d[i]);
    printf("\n");
}

static void print_packet(const char * msg, struct pkt * p, int len)
{
    printf("%s len=%d\n", msg, len);
    if (len >= sizeof(p->eh))
	print_hex("ethernet", (unsigned char *)&p->eh, sizeof(p->eh));
    if (len >= sizeof(p->eh) + sizeof(p->ip))
	print_hex("ip", (unsigned char *)&p->ip, sizeof(p->ip));
    if (len >= sizeof(p->eh) + sizeof(p->ip) + sizeof(p->udp)) {
	print_hex("udp", (unsigned char *)&p->udp, sizeof(p->udp));
	print_hex("body", (unsigned char *)&p->body, len
		- (sizeof(p->eh) + sizeof(p->ip) + sizeof(p->udp)));
    }
    printf("\n");
}

static int check_received_packet(struct sgvec * sg, int sgcnt)
{
    struct pkt packet;
    struct pkt * p = &packet;
    uint32_t * d;
    int i;
    int offset = 0;
    int hdrlen = sizeof(p->eh) + sizeof(p->ip) + sizeof(p->udp);

    for (i=0; i<sgcnt; i++) {
	memcpy(p + offset, ((void *)&skbuffs[0]) + sg[i].phy - SKBUFFS_PHY,
		    sg[i].len);
	offset += sg[i].len;
    }

    if (offset < hdrlen + 4)
	print_packet("Bad length", p, offset);

    if (check_rx_payload) {
	d = (uint32_t *)&packet.body;
	i = 1;
	while ((i+1) * sizeof(uint32_t) - 1 < offset - hdrlen) {
	    if (d[i] != d[0]) {
		print_packet("Unknown payload", p, offset);
		break;
	    }
	    i++;
	}
    }

    return 0;
}

static void * receiver(void * opaque)
{
    struct V1000Config * cfg = opaque;
    volatile struct e1000_rx_desc * rx_desc = &rx_desc_mem[0];
    volatile struct virtio_net_hdr * rx_hdr = &vnet_hdr_rings[NUM_DESCRIPTORS];
    volatile struct paravirt_csb * csb = &csb_mem;
    uint32_t ntr = 0;
    struct sgvec sg[MAX_NUM_FRAGS];
    int sgcnt = 0;
    long long rate_rxpkts = 0;
    long rate_rxkicks = 0;
    long rate_rxintrs = 0;
#ifdef RATE
    struct timeval tb, te;
    long long overflow = 128;
    long long usecs;
#define RATE_LB_US	    1600000
#define RATE_UB_US	    2400000

    gettimeofday(&tb, NULL);
#endif	/* RATE */

    for (sgcnt = 0; sgcnt<MAX_NUM_FRAGS; sgcnt++)
	sg[sgcnt].phy = sg[sgcnt].len = 0;
    sgcnt = 0;

    while (!stop) {
	uint64_t event = 1;

	if (read(cfg->rx_ring.irqfd, &event, sizeof(event))
		!= sizeof(event)) {
	    perror("read(tx_ring.irqfd)\n");
	    exit(EXIT_FAILURE);
	}
	rate_rxintrs++;
again:
	/* Disable notifications. */
	csb->guest_need_rxkick = 0;
	compiler_barrier();

	/* Receive and clean used descriptors. */
	while (rx_desc[ntr].status & E1000_RXD_STAT_DD) {
	    //printf("Received packet [len=%u,ntr=%u,rdt=%u]\n", rx_desc[ntr].length, ntr, csb->guest_rdt);
	    if (sgcnt == MAX_NUM_FRAGS) {
		/* If this happens, there is a bug in the kernel code. */
		printf("BUG: oversized RX descriptors chain.\n");
		sgcnt = 0;  /* Force to 0 to avoid buffer overflow. */
	    }
	    if (!sgcnt) {
		/* First frame fragment. */
		if (check_rx_header(rx_hdr + ntr)) {
		    printf("Bad viritio-net header\n");
		}
	    }
	    sg[sgcnt].phy = rx_desc[ntr].buffer_addr;
	    sg[sgcnt].len = rx_desc[ntr].length;
	    sgcnt++;
	    if (rx_desc[ntr].status & E1000_RXD_STAT_EOP) {
                sg[sgcnt-1].len -= 4;  /* Remove FSC/CRC. */
		check_received_packet(&sg[0], sgcnt);
		rate_rxpkts++;
		sgcnt = 0;
#ifdef RATE
		if (rate_rxpkts == overflow) {
		    /* Rating report. */
		    gettimeofday(&te, NULL);
		    usecs = (te.tv_sec - tb.tv_sec) * 1000000 +
			te.tv_usec - tb.tv_usec;
		    printf("RX:	    %3.6f Mpps\n", rate_rxpkts/((double)usecs));
		    printf("RXINTR:	    %3.6f Mpps\n", rate_rxintrs/((double)usecs));
		    printf("\n");
		    rate_rxpkts = rate_rxintrs = 0;
		    if (usecs < RATE_LB_US)
			overflow *= 2;
		    else if (usecs > RATE_UB_US)
			overflow /= 2;
		    gettimeofday(&tb, NULL);
		}
#endif	/* RATE */
	    }
	    rx_desc[ntr].status = 0;
	    csb->guest_rdt = prepare_rx_descriptors(rx_desc, csb->guest_rdt, 1);
	    compiler_barrier();
	    if (csb->host_rxkick_at == ntr) {
		write(cfg->rx_ring.ioeventfd, &event, sizeof(event));
		rate_rxkicks++;
		//printf("RX kick\n");
	    }
	    if (++ntr == NUM_DESCRIPTORS)
		ntr = 0;
	}

	/* Reenable notifications. */
	csb->guest_need_rxkick = 1;
	compiler_barrier();
	/* Doublecheck. */
	if (rx_desc[ntr].status & E1000_RXD_STAT_DD) {
	    goto again;
	}
    }

    return NULL;
}

void usage()
{
    printf("CMD INDEX [s {INDEX,H}] [r]\n");
    exit(EXIT_FAILURE);
}

int main(int argc, char ** argv)
{
    pthread_t sender_thread;
    pthread_t receiver_thread;
    const char * ri;
    const char * si;
    int enable_sender = 0;
    int enable_receiver = 0;
    int vfd;
    int c;

    /* Program input parsing. */
    if (argc < 2)
	usage();
    ri = argv[1];
    si = NULL;
    for (c=2; c<argc; c++) {
	switch (argv[c][0]) {
	    case 's':
		enable_sender = 1;
		if (++c == argc)
		    usage();
		si = argv[c];
		if (si[0] == 'H')
		    si = NULL;
		break;
	    case 'r':
		enable_receiver = 1;
		break;
	    default:
		usage();
	};
    }
    if (!enable_sender && !enable_receiver)
	usage();


    /* Data structure initialization. */
    memset(&tx_desc_mem[0], 0, NUM_DESCRIPTORS
	    * sizeof(struct e1000_tx_desc));
    memset(&rx_desc_mem[0], 0, NUM_DESCRIPTORS
	    * sizeof(struct e1000_rx_desc));
    /* printf("TXR@%p, RXR@%p, CSB@%p\n", &tx_desc_mem[0], &rx_desc_mem[0], &csb_mem); */

    csb_init(&csb_mem);

    build_tx_frames(si, ri, &skbuffs[0], NUM_TX_SKBUFFS);

    csb_mem.guest_rdt = prepare_rx_descriptors(&rx_desc_mem[0],
			    csb_mem.guest_rdt, NUM_DESCRIPTORS - 1);

    if ((vfd = open("/dev/v1000", O_RDWR)) < 0) {
	perror("Cannot open '/dev/v1000'\n");
	exit(EXIT_FAILURE);
    }

    configure(vfd, si, ri, &config);

    if (enable_sender) {
	if (pthread_create(&sender_thread, NULL, &sender, &config)) {
	    perror("pthread_create(sender)\n");
	    exit(EXIT_FAILURE);
	}
    }

    if (enable_receiver) {
	if (pthread_create(&receiver_thread, NULL, &receiver, &config)) {
	    perror("pthread_create(receiver)\n");
	    exit(EXIT_FAILURE);
	}
    }

    c = 0;
    while (c != 'q') {
	c = getchar();
	/* Read the newline character. */
	getchar();
    }
    stop = 1;

    if (enable_sender) {
	if (pthread_join(sender_thread, NULL)) {
	    perror("pthread_join(sender)\n");
	    exit(EXIT_FAILURE);
	}
    }

    if (enable_receiver) {
	if (pthread_join(receiver_thread, NULL)) {
	    perror("pthread_join(receiver)\n");
	    exit(EXIT_FAILURE);
	}
    }

    cleanup(vfd, &config);

    return 0;
}

