#ifndef __VPT__USER__H
#define __VPT__USER__H

struct vPT_RingConfig {
    uint32_t ioeventfd;
    uint32_t irqfd;
    uint32_t resamplefd; //XXX
};

struct vPT_Config {
    struct vPT_RingConfig tx_ring;
    struct vPT_RingConfig rx_ring;
    uint32_t netmap_fd;
    void *csb;   /* CSB */
};
#endif /* __VPT__USER__H */
