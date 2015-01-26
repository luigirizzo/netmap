#ifndef __V1000__USER__HH
#define __V1000__USER__HH


struct V1000TranslationElem {
    uint64_t phy;
    uint64_t length;
    void * virt;
};

struct V1000Translation {
#define MAX_TRANSLATION_ELEMENTS 64
    struct V1000TranslationElem table[MAX_TRANSLATION_ELEMENTS];
    unsigned num;
};

struct V1000RingConfig {
    uint64_t phy;
    union {
        uint64_t phy; /* For the RX ring. */
        void * virt;  /* For the TX ring. */
    } hdr;
    uint32_t num;
    uint32_t ioeventfd;
    uint32_t irqfd;
    uint32_t resamplefd;
};

struct V1000Config {
    struct V1000RingConfig tx_ring;
    struct V1000RingConfig rx_ring;
    uint32_t rxbuf_size;	/* RX buffer size. */
    uint64_t csb_phy;	/* CSB physical address. */
    uint32_t tapfd;		/* Backend file descriptor. */
    struct V1000Translation tr;
};


#include "e1000_regs.h"


#endif
