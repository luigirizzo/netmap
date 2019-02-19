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

#include "netmap_classes.h"

#include <structmember.h>

#include <net/if.h>
#include <net/netmap.h>
#include <net/netmap_user.h>


static void
NetmapRing_dealloc(NetmapRing* self)
{
    Py_XDECREF(self->slots);
    self->ob_type->tp_free((PyObject*)self);
}

static PyObject *
NetmapRing_new(PyTypeObject *type, PyObject *args, PyObject *kwds)
{
    NetmapRing *self;

    self = (NetmapRing *)type->tp_alloc(type, 0);
    if (self != NULL) {
        self->_ring = NULL;
        self->slots = NULL;
    }

    return (PyObject *)self;
}

/* Static data for flags pretty printing. */
static unsigned int nr_flag_values[] = {NR_TIMESTAMP, NR_FORWARD};
static const char *nr_flag_strings[] = {"NrTimestamp", "NrForward"};

static PyObject *
NetmapRing_repr(NetmapRing *self)
{
    PyObject *result;
    struct netmap_ring *ring= self->_ring;
    char flags[256];

    if (ring == NULL) {
        return Py_BuildValue("s", "Invalid NetmapRing");
    }

    netmap_flags_pretty(ring->flags, flags, sizeof(flags), nr_flag_values,
                        nr_flag_strings,
                        sizeof(nr_flag_values)/sizeof(*nr_flag_values));

    result = PyString_FromFormat(
            "buf_ofs:       0x%016lx\n"
            "num_slots:     %u\n"
            "nr_buf_size:   %u\n"
            "ringid:        %u\n"
            "dir:           %u\n"
            "head:          %u\n"
            "cur:           %u\n"
            "tail:          %u\n"
            "flags:         [0x%08x] %s\n"
            "tv_sec:        %ld\n"
            "tv_usec:       %ld\n"
            /* TODO sem */,
            (long unsigned)ring->buf_ofs,
            ring->num_slots,
            ring->nr_buf_size,
            ring->ringid,
            ring->dir,
            ring->head,
            ring->cur,
            ring->tail,
            ring->flags,
            flags,
            ring->ts.tv_sec,
            ring->ts.tv_usec
                );

    return result;
}

int
NetmapRing_build(NetmapRing *self, void *addr)
{
    NetmapSlot *slot;
    PyObject *list;
    int ret;
    int i;
    int n;

    if (self->_ring) {
        PyErr_SetString(NetmapError, "Internal error: cannot connect"
                                        " a ring twice");
        return -1;
    }

    /* Init the pointer to the netmap_ring struct. */
    self->_ring = addr;
    n = self->_ring->num_slots;

    /* Create and populate the list of netmap slots. */
    list = PyList_New(n);
    if (!list) {
        return -1;
    }
    self->slots = list;

    for (i = 0; i < n; i++) {
        slot = (NetmapSlot *)PyObject_CallObject((PyObject *)&NetmapSlotType,
                                                    NULL);
        if (!slot) {
            return -1;
        }
        ret = NetmapSlot_build(slot, &self->_ring->slot[i],
                                NETMAP_BUF(self->_ring,
                                self->_ring->slot[i].buf_idx));
        if (ret == -1) {
            return -1;
        }

        ret = PyList_SetItem(list, i, (PyObject *)slot);
        if (ret == -1) {
            return -1;
        }
    }

    return 0;
}

void
NetmapRing_destroy(NetmapRing *self)
{
    self->_ring = NULL;

    if (self->slots) {
        NetmapSlot *slot;
        int n;
        int i;

        n = PyList_Size(self->slots);
        for (i = 0; i < n; i++) {
            slot = (NetmapSlot *)PyList_GetItem(self->slots, i);
            if (slot) {
                NetmapSlot_destroy(slot);
            }
        }
        Py_DECREF(self->slots);
        self->slots = NULL;
    }
}

static PyMemberDef NetmapRing_members[] = {
    {NULL}
};


/*########################## set/get methods #######################*/

static PyObject *
NetmapRing_slots_get(NetmapRing *self, void *closure)
{
    if (self->slots == NULL) {
        Py_RETURN_NONE;
    }
    Py_INCREF(self->slots);

    return self->slots;
}

static int
NetmapRing_slots_set(NetmapRing *self, PyObject *value, void *closure)
{
    if (value == NULL) {
        PyErr_SetString(PyExc_TypeError, "Cannot delete the attribute");
    } else {
        PyErr_SetString(PyExc_TypeError, "Cannot modify the attribute");
    }

    return -1;
}

#define DEFINE_NETMAP_RING_GETSET(field, type, format)                      \
static PyObject *                                                           \
NetmapRing_##field##_get(NetmapRing *self, void *closure)                   \
{                                                                           \
    if (!self->_ring) {                                                     \
        Py_RETURN_NONE;                                                     \
    }                                                                       \
    return Py_BuildValue(format, self->_ring->field);                       \
}                                                                           \
                                                                            \
static int                                                                  \
NetmapRing_##field##_set(NetmapRing *self, PyObject *value, void *closure)  \
{                                                                           \
    long x;                                                                 \
    if (!self->_ring) {                                                     \
        PyErr_SetString(PyExc_TypeError, "Attribute not available");        \
        return -1;                                                          \
    }                                                                       \
    x = PyInt_AsLong(value);                                                \
    if (x == -1 && PyErr_Occurred()) {                                      \
        return -1;                                                          \
    }                                                                       \
    /* Override the 'const' specifier. */                                   \
    *((type *)&self->_ring->field) = (type)x;                               \
    return 0;                                                               \
}

#define DEFINE_NETMAP_RING_GETSET_TV(field)                                 \
static PyObject *                                                           \
NetmapRing_##field##_get(NetmapRing *self, void *closure)                   \
{                                                                           \
    if (!self->_ring) {                                                     \
        Py_RETURN_NONE;                                                     \
    }                                                                       \
    return Py_BuildValue("I", self->_ring->ts.field);                       \
}                                                                           \
                                                                            \
static int                                                                  \
NetmapRing_##field##_set(NetmapRing *self, PyObject *value, void *closure)  \
{                                                                           \
    long x;                                                                 \
    if (!self->_ring) {                                                     \
        PyErr_SetString(PyExc_TypeError, "Attribute not available");        \
        return -1;                                                          \
    }                                                                       \
    x = PyInt_AsLong(value);                                                \
    if (x == -1 && PyErr_Occurred()) {                                      \
        return -1;                                                          \
    }                                                                       \
    /* Override the 'const' specifier. */                                   \
    *((uint32_t *)&self->_ring->ts.field) = (uint32_t)x;                    \
    return 0;                                                               \
}

DEFINE_NETMAP_RING_GETSET(num_slots, uint32_t, "I");
DEFINE_NETMAP_RING_GETSET(nr_buf_size, uint32_t, "I");
DEFINE_NETMAP_RING_GETSET(ringid, uint16_t, "I");
DEFINE_NETMAP_RING_GETSET(dir, uint16_t, "I");
DEFINE_NETMAP_RING_GETSET(head, uint32_t, "I");
DEFINE_NETMAP_RING_GETSET(cur, uint32_t, "I");
DEFINE_NETMAP_RING_GETSET(tail, uint32_t, "I");
DEFINE_NETMAP_RING_GETSET(flags, uint32_t, "I");
DEFINE_NETMAP_RING_GETSET_TV(tv_sec);
DEFINE_NETMAP_RING_GETSET_TV(tv_usec);

#define DECLARE_NETMAP_RING_GETSETERS(field)                                \
    {#field,                                                                \
        (getter)NetmapRing_##field##_get, (setter)NetmapRing_##field##_set, \
        "netmap ring " #field " field",                                     \
        NULL}

static PyGetSetDef NetmapRing_getseters[] = {
    DECLARE_NETMAP_RING_GETSETERS(num_slots),
    DECLARE_NETMAP_RING_GETSETERS(nr_buf_size),
    DECLARE_NETMAP_RING_GETSETERS(ringid),
    DECLARE_NETMAP_RING_GETSETERS(dir),
    DECLARE_NETMAP_RING_GETSETERS(head),
    DECLARE_NETMAP_RING_GETSETERS(cur),
    DECLARE_NETMAP_RING_GETSETERS(tail),
    DECLARE_NETMAP_RING_GETSETERS(flags),
    DECLARE_NETMAP_RING_GETSETERS(tv_sec),
    DECLARE_NETMAP_RING_GETSETERS(tv_usec),
    {"slots",
        (getter)NetmapRing_slots_get, (setter)NetmapRing_slots_set,
        "netmap ring slots",
        NULL},
    {NULL}  /* Sentinel */
};


static PyObject*
NetmapRing_space(NetmapRing *self)
{
    return Py_BuildValue("i", nm_ring_space(self->_ring));
}

static PyObject*
NetmapRing_empty(NetmapRing *self)
{
    if (nm_ring_empty(self->_ring)) {
        Py_RETURN_TRUE;
    }

    Py_RETURN_FALSE;
}

static PyMethodDef NetmapRing_methods[] = {
    {"space", (PyCFunction)NetmapRing_space, METH_NOARGS,
        "Return the number of available ring slots"
    },
    {"empty", (PyCFunction)NetmapRing_empty, METH_NOARGS,
        "Returns True if the ring is empty (no available slots)"
    },
    {NULL}
};

/* Definition exported to netmap.c. */
PyTypeObject NetmapRingType = {
    PyObject_HEAD_INIT(NULL)
        0,                         /*ob_size*/
    "netmap.NetmapRing",             /*tp_name*/
    sizeof(NetmapRing),             /*tp_basicsize*/
    0,                         /*tp_itemsize*/
    (destructor)NetmapRing_dealloc, /*tp_dealloc*/
    0,                         /*tp_print*/
    0,                         /*tp_getattr*/
    0,                         /*tp_setattr*/
    0,                         /*tp_compare*/
    (reprfunc)NetmapRing_repr,                 /*tp_repr*/
    0,                         /*tp_as_number*/
    0,                         /*tp_as_sequence*/
    0,                         /*tp_as_mapping*/
    0,                         /*tp_hash */
    0,                         /*tp_call*/
    0,                         /*tp_str*/
    0,                         /*tp_getattro*/
    0,                         /*tp_setattro*/
    0,                         /*tp_as_buffer*/
    Py_TPFLAGS_DEFAULT, /*tp_flags*/
    "Netmap interface object",           /* tp_doc */
    0,                     /* tp_traverse */
    0,                     /* tp_clear */
    0,                     /* tp_richcompare */
    0,                     /* tp_weaklistoffset */
    0,                     /* tp_iter */
    0,                     /* tp_iternext */
    NetmapRing_methods,             /* tp_methods */
    NetmapRing_members,             /* tp_members */
    NetmapRing_getseters,                         /* tp_getset */
    0,                         /* tp_base */
    0,                         /* tp_dict */
    0,                         /* tp_descr_get */
    0,                         /* tp_descr_set */
    0,                         /* tp_dictoffset */
    0,      /* tp_init */
    0,                         /* tp_alloc */
    NetmapRing_new,                 /* tp_new */
};

