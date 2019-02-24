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


static void
NetmapInterface_dealloc(NetmapInterface* self)
{
    self->ob_type->tp_free((PyObject*)self);
}

static PyObject *
NetmapInterface_new(PyTypeObject *type, PyObject *args, PyObject *kwds)
{
    NetmapInterface *self;

    self = (NetmapInterface *)type->tp_alloc(type, 0);
    if (self != NULL) {
        self->_nifp = NULL;
    }

    return (PyObject *)self;
}

static PyObject *
NetmapInterface_repr(NetmapInterface *self)
{
    PyObject *result;
    struct netmap_if *nifp = self->_nifp;

    if (nifp == NULL) {
        return Py_BuildValue("s", "Invalid NetmapInterface");
    }

    result = PyString_FromFormat(
            "name:           '%s'\n"
            "version:        %u\n"
            "flags:          0x%08x\n"
            "tx_rings:       %u\n"
            "rx_rings:       %u\n"
            "bufs_head:      %u\n"
            "host_tx_rings:  %u\n"
            "host_rx_rings:  %u\n",
            nifp->ni_name,
            nifp->ni_version,
            nifp->ni_flags,
            nifp->ni_tx_rings,
            nifp->ni_rx_rings,
            nifp->ni_bufs_head,
            nifp->ni_host_tx_rings,
            nifp->ni_host_rx_rings
            );

    return result;
}


static PyMemberDef NetmapInterface_members[] = {
    {NULL}
};

int
NetmapInterface_build(NetmapInterface *self, void *addr)
{
    self->_nifp = addr;

    return 0;
}

void
NetmapInterface_destroy(NetmapInterface *self)
{
    self->_nifp = NULL;
}

/*########################## set/get methods #######################*/

static PyObject *
NetmapInterface_name_get(NetmapInterface *self, void *closure)
{
    if (!self->_nifp) {
        /* This cannot happen for NetmapInterface object created by
           a NetmapManager object, but may happen for standalone
           NetmapInterface objects. */
        Py_RETURN_NONE;
    }

    return Py_BuildValue("s", self->_nifp->ni_name);
}

static int
NetmapInterface_name_set(NetmapInterface *self, PyObject *value, void *closure)
{
    const char *str;
    size_t len;

    if (!self->_nifp) {
        /* See comment in NetmapInterface_name_get(). */
        PyErr_SetString(PyExc_TypeError, "Attribute not available");
        return -1;
    }

    str = PyString_AsString(value);
    if (str == NULL) {
        return -1;
    }

    len = PyString_Size(value);
    if (len > IFNAMSIZ-1) {
        len = IFNAMSIZ-1;
    }
    memcpy(self->_nifp->ni_name, str, len);
    self->_nifp->ni_name[len] = '\0';

    return 0;
}

#define DEFINE_NETMAP_INTERFACE_U32_GETSET(x)                               \
static PyObject *                                                           \
NetmapInterface_##x##_get(NetmapInterface *self, void *closure)             \
{                                                                           \
    if (!self->_nifp) {                                                     \
        Py_RETURN_NONE;                                                     \
    }                                                                       \
    return Py_BuildValue("I", self->_nifp->ni_##x);                         \
}                                                                           \
                                                                            \
static int                                                                  \
NetmapInterface_##x##_set(NetmapInterface *self, PyObject *value,           \
                            void *closure)                                  \
{                                                                           \
    long x;                                                                 \
    if (!self->_nifp) {                                                     \
        PyErr_SetString(PyExc_TypeError, "Attribute not available");        \
        return -1;                                                          \
    }                                                                       \
    x = PyInt_AsLong(value);                                                \
    if (x == -1 && PyErr_Occurred()) {                                      \
        return -1;                                                          \
    }                                                                       \
    /* Override the 'const' specifier. */                                   \
    *((uint32_t *)&self->_nifp->ni_##x) = (uint32_t)x;                      \
    return 0;                                                               \
}

DEFINE_NETMAP_INTERFACE_U32_GETSET(version);
DEFINE_NETMAP_INTERFACE_U32_GETSET(flags);
DEFINE_NETMAP_INTERFACE_U32_GETSET(tx_rings);
DEFINE_NETMAP_INTERFACE_U32_GETSET(rx_rings);
DEFINE_NETMAP_INTERFACE_U32_GETSET(bufs_head);

#define DECLARE_NETMAP_INTERFACE_U32_GETSETERS(x)                           \
    {#x,                                                                    \
        (getter)NetmapInterface_##x##_get,                                  \
        (setter)NetmapInterface_##x##_set,                                  \
        "netmap interface " #x " field",                                    \
        NULL}

static PyGetSetDef NetmapInterface_getseters[] = {
    {"name",
        (getter)NetmapInterface_name_get, (setter)NetmapInterface_name_set,
        "netmap interface name field",
        NULL},
    DECLARE_NETMAP_INTERFACE_U32_GETSETERS(version),
    DECLARE_NETMAP_INTERFACE_U32_GETSETERS(flags),
    DECLARE_NETMAP_INTERFACE_U32_GETSETERS(tx_rings),
    DECLARE_NETMAP_INTERFACE_U32_GETSETERS(rx_rings),
    DECLARE_NETMAP_INTERFACE_U32_GETSETERS(bufs_head),
    {NULL}  /* Sentinel */
};


static PyMethodDef NetmapInterface_methods[] = {
    {NULL}
};

/* Definition exported to netmap.c. */
PyTypeObject NetmapInterfaceType = {
    PyObject_HEAD_INIT(NULL)
        0,                         /*ob_size*/
    "netmap.NetmapInterface",             /*tp_name*/
    sizeof(NetmapInterface),             /*tp_basicsize*/
    0,                         /*tp_itemsize*/
    (destructor)NetmapInterface_dealloc, /*tp_dealloc*/
    0,                         /*tp_print*/
    0,                         /*tp_getattr*/
    0,                         /*tp_setattr*/
    0,                         /*tp_compare*/
    (reprfunc)NetmapInterface_repr,                 /*tp_repr*/
    0,                         /*tp_as_number*/
    0,                         /*tp_as_sequence*/
    0,                         /*tp_as_mapping*/
    0,                         /*tp_hash */
    0,                         /*tp_call*/
    0,                         /*tp_str*/
    0,                         /*tp_getattro*/
    0,                         /*tp_setattro*/
    0,                         /*tp_as_buffer*/
    Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE, /*tp_flags*/
    "Netmap interface object",           /* tp_doc */
    0,                     /* tp_traverse */
    0,                     /* tp_clear */
    0,                     /* tp_richcompare */
    0,                     /* tp_weaklistoffset */
    0,                     /* tp_iter */
    0,                     /* tp_iternext */
    NetmapInterface_methods,             /* tp_methods */
    NetmapInterface_members,             /* tp_members */
    NetmapInterface_getseters,                         /* tp_getset */
    0,                         /* tp_base */
    0,                         /* tp_dict */
    0,                         /* tp_descr_get */
    0,                         /* tp_descr_set */
    0,                         /* tp_dictoffset */
    0,      /* tp_init */
    0,                         /* tp_alloc */
    NetmapInterface_new,                 /* tp_new */
};

