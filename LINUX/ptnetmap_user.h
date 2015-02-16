#ifndef __PTNETMAP_VHOST_USER__H
#define __PTNETMAP_VHOST_USER__H

struct ptnetmap_config_ring {
    uint32_t ioeventfd;
    uint32_t irqfd;
    uint32_t resamplefd; //XXX
};

struct ptnetmap_config {
    struct ptnetmap_config_ring tx_ring;
    struct ptnetmap_config_ring rx_ring;
    uint32_t netmap_fd;
    void *csb;   /* CSB */
};
#endif /* __PTNETMAP_VHOST_USER_H */
