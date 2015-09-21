#include "netmap_classes.h"

#include <structmember.h>
#include <net/if.h>         /* IFNAMSIZ */
#include <net/netmap.h>
#include <net/netmap_user.h>


void
NetmapMemory_dealloc(NetmapMemory *memory)
{
    Py_XDECREF(memory->interface);
    Py_XDECREF(memory->transmit_rings);
    Py_XDECREF(memory->receive_rings);
}

void
NetmapMemory_new(NetmapMemory *memory)
{
    memory->interface = NULL;
    memory->transmit_rings = memory->receive_rings = NULL;
}

int
NetmapMemory_setup(NetmapMemory *memory, struct netmap_if *nifp,
                        int num_tx_rings, int num_rx_rings)
{
    NetmapInterface *interface;
    NetmapRing *ring;
    PyObject *list;
    int ret;
    int i;

    /* Initialize the 'interface' child object. */
    memory->interface = PyObject_CallObject((PyObject *)&NetmapInterfaceType,
                                            NULL);
    if (!memory->interface) {
        return -1;
    }
    interface = (NetmapInterface *)memory->interface;
    NetmapInterface_build(interface, nifp);

    /* Initialize the 'transmit_rings' child object. */
    list = PyList_New(num_tx_rings);
    if (!list) {
        return -1;
    }
    memory->transmit_rings = list;
    for (i = 0; i < num_tx_rings; i++) {
        ring = (NetmapRing *)PyObject_CallObject((PyObject *)&NetmapRingType,
                                                    NULL);
        if (!ring) {
            return -1;
        }
        ret = NetmapRing_build(ring, NETMAP_TXRING(nifp, i));
        if (ret) {
            return -1;
        }
        ret = PyList_SetItem(list, i, (PyObject *)ring);
        if (ret) {
            return -1;
        }
    }

    /* Initialize the 'receive_rings' child object. */
    list = PyList_New(num_rx_rings);
    if (!list) {
        return -1;
    }
    memory->receive_rings = list;
    for (i = 0; i < num_rx_rings; i++) {
        ring = (NetmapRing *)PyObject_CallObject((PyObject *)&NetmapRingType,
                                                    NULL);
        if (!ring) {
            return -1;
        }
        ret = NetmapRing_build(ring, NETMAP_RXRING(nifp, i));
        if (ret) {
            return -1;
        }
        ret = PyList_SetItem(list, i, (PyObject *)ring);
        if (ret) {
            return -1;
        }
    }

    return 0;
}

void
NetmapMemory_destroy(NetmapMemory *memory)
{
    NetmapRing *ring;
    int n;
    int i;

    if (memory->interface) {
        NetmapInterface_destroy((NetmapInterface *)memory->interface);
        Py_DECREF(memory->interface);
        memory->interface = NULL;
    }

    if (memory->transmit_rings) {
        n = PyList_Size(memory->transmit_rings);
        for (i = 0; i < n; i++) {
            ring = (NetmapRing *)PyList_GetItem(memory->transmit_rings, i);
            if (ring) {
                NetmapRing_destroy(ring);
            }
        }
        Py_DECREF(memory->transmit_rings);
        memory->transmit_rings = NULL;
    }

    if (memory->receive_rings) {
        n = PyList_Size(memory->receive_rings);
        for (i = 0; i < n; i++) {
            ring = (NetmapRing *)PyList_GetItem(memory->receive_rings, i);
            if (ring) {
                NetmapRing_destroy(ring);
            }
        }
        Py_DECREF(memory->receive_rings);
        memory->receive_rings = NULL;
    }
}
