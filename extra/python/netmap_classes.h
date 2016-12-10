/*
 * Copyright (C) 2013-2015 Vincenzo Maffione. All rights reserved.
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

#ifndef NETMAP_PYTHON_CLASSES_H
#define NETMAP_PYTHON_CLASSES_H

#include <Python.h>
#include <net/if.h>
#include <net/netmap.h>


extern PyObject *NetmapError;

/* Utilities implemented in netmap.c. */
PyObject *string_get(PyObject *str);
int string_set(PyObject **str, PyObject *value);
void netmap_flags_pretty(unsigned int flags, char *str, int avail,
                    unsigned int *values, const char **strings, int items);
void ringid_pretty_print(uint32_t nr_ringid, uint32_t nr_flags,
                            char *ringid, int rsz, char *flags, int fsz);


/* Netmap memory representation. */
typedef struct {
    PyObject *interface;
    PyObject *transmit_rings;
    PyObject *receive_rings;

} NetmapMemory;

void NetmapMemory_dealloc(NetmapMemory *memory);
void NetmapMemory_new(NetmapMemory *memory);
int NetmapMemory_setup(NetmapMemory *memory, struct netmap_if *nifp,
                        int num_tx_rings, int num_rx_rings);
void NetmapMemory_destroy(NetmapMemory *memory);

/*
 * Main class of the netmap module, managing
 * a netmap port.
 */
typedef struct {
    PyObject_HEAD
    PyObject *dev_name;          /* Netmap device name. */

    PyObject *if_name;
    struct nmreq nmreq;         /* The netmap request we are wrapping. */

    /* Netmap memory representation. */
    NetmapMemory memory;

    /* Internal variables. */
    int _state;
#define INVALID_FD  (-1)
    int _fd;                /* Netmap device file descriptor. */
    void *_memaddr;             /* Netmap memory-mapped area. */
} NetmapManager;

extern PyTypeObject NetmapManagerType;


/*
 * A simpler alternative to the NetmapManager class, which makes use of the
 * nm_open()/nm_close() API.
 */
typedef struct {
    PyObject_HEAD

    struct nm_desc *nmd;    /* The netmap descriptor object we are wrapping. */

    /* Netmap memory representation. */
    NetmapMemory memory;
} NetmapDesc;

extern PyTypeObject NetmapDescType;


/* Class wrapper for the netmap_if struct. */
typedef struct {
    PyObject_HEAD

    struct netmap_if *_nifp;            /* Address of struct netmap_if. */
} NetmapInterface;

extern PyTypeObject NetmapInterfaceType;

int NetmapInterface_build(NetmapInterface *self, void *addr);
void NetmapInterface_destroy(NetmapInterface *self);


/* Class wrapper for the netmap_ring struct. */
typedef struct {
    PyObject_HEAD
    PyObject *slots;

    struct netmap_ring *_ring;            /* Address of struct netmap_ring. */
} NetmapRing;

extern PyTypeObject NetmapRingType;

int NetmapRing_build(NetmapRing *self, void *addr);
void NetmapRing_destroy(NetmapRing *self);


/* Class wrapper for the netmap_slot struct. */
typedef struct {
    PyObject_HEAD
    PyObject *memoryview;

    Py_buffer _view;
    struct netmap_slot *_slot;            /* Address of struct netmap_slot. */
} NetmapSlot;

extern PyTypeObject NetmapSlotType;

int NetmapSlot_build(NetmapSlot *slot, void *addr, void *buf);
void NetmapSlot_destroy(NetmapSlot *slot);

#endif  /* NETMAP_PYTHON_CLASSES_H */
