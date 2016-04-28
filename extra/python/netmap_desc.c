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
#include <fcntl.h>          /* open() */
#include <sys/ioctl.h>      /* ioctl() */
#include <sys/mman.h>       /* mmap() */
#include <net/if.h>         /* IFNAMSIZ */
#include <net/netmap.h>
#include <stdio.h>
#define NETMAP_WITH_LIBS
#include <net/netmap_user.h>


/* Destructor method for NetmapDescType. */
static void
NetmapDesc_dealloc(NetmapDesc* self)
{
    NetmapMemory_dealloc(&self->memory);

    if (self->nmd) {
        nm_close(self->nmd);
        self->nmd = NULL;
    }
    self->ob_type->tp_free((PyObject*)self);
}

/* Netmap.__new__() is the constructor. */
static PyObject *
NetmapDesc_new(PyTypeObject *type, PyObject *args, PyObject *kwds)
{
    NetmapDesc *self;

    self = (NetmapDesc *)type->tp_alloc(type, 0);
    if (self == NULL) {
        return NULL;
    }

    self->nmd = NULL;
    NetmapMemory_new(&self->memory);

    return (PyObject *)self;
}

/* Netmap.__init__(), may be called many times, or not called at all. */
static int
NetmapDesc_init(NetmapDesc *self, PyObject *args, PyObject *kwds)
{
    PyObject *dev_name = NULL;
    static char *kwlist[] = {"ifname", "flags", NULL};
    const char *ifname;
    unsigned long flags = 0;
    int ret;

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "s|k", kwlist,
                &ifname, &flags)) {
        return -1;
    }

    /* Open the netmap device and register an interface. */
    self->nmd = nm_open(ifname, NULL, flags, NULL);
    if (self->nmd == NULL) {
        PyErr_SetString(NetmapError, "nm_open() failed");
        return -1;
    }

    /* Setup the netmap memory layout. The +1 are here to take into account
       the host rings. */
    ret = NetmapMemory_setup(&self->memory, self->nmd->nifp,
                                self->nmd->req.nr_tx_rings + 1,
                                    self->nmd->req.nr_rx_rings + 1);

    return ret;
}

static PyObject *
NetmapDesc_repr(NetmapDesc *self)
{
    PyObject *result;
    char ringid[128];
    char flags[128];

    ringid_pretty_print(self->nmd->req.nr_ringid, self->nmd->req.nr_flags,
                        ringid, sizeof(ringid), flags, sizeof(flags));

    result = PyString_FromFormat(
            "if_name:    '%s'\n"
            "ringid:     '%s'\n"
            "flags:      '%s'\n",
            self->nmd->req.nr_name, ringid, flags);

    return result;
}


static PyMemberDef NetmapDesc_members[] = {
    {NULL}  /* Sentinel */
};


/*########################## set/get methods #######################*/

#define NETMAP_MANAGER_DEFINE_GETSET(obj)                                   \
static PyObject *                                                           \
NetmapDesc_##obj##_get(NetmapDesc *self, void *closure)                     \
{                                                                           \
    if (self->memory.obj == NULL) {                                         \
        Py_RETURN_NONE;                                                     \
    }                                                                       \
    Py_INCREF(self->memory.obj);                                            \
    return self->memory.obj;                                                \
}                                                                           \
                                                                            \
static int                                                                  \
NetmapDesc_##obj##_set(NetmapDesc *self, PyObject *value,                   \
                            void *closure)                                  \
{                                                                           \
    if (value == NULL) {                                                    \
        PyErr_SetString(PyExc_TypeError, "Cannot delete the attribute");    \
    } else {                                                                \
        PyErr_SetString(PyExc_TypeError, "Cannot modify the attribute");    \
    }                                                                       \
    return -1;                                                              \
}

NETMAP_MANAGER_DEFINE_GETSET(interface);
NETMAP_MANAGER_DEFINE_GETSET(transmit_rings);
NETMAP_MANAGER_DEFINE_GETSET(receive_rings);

#define NETMAP_MANAGER_DECLARE_GETSET(obj, desc)                            \
    {#obj,                                                                  \
        (getter)NetmapDesc_##obj##_get,                                     \
        (setter)NetmapDesc_##obj##_set,                                     \
         desc,                                                              \
        NULL}


static PyGetSetDef NetmapDesc_getseters[] = {
    NETMAP_MANAGER_DECLARE_GETSET(interface, "NetmapInterface object"),
    NETMAP_MANAGER_DECLARE_GETSET(transmit_rings,
                                    "List of NetmapRing objects (Tx)"),
    NETMAP_MANAGER_DECLARE_GETSET(receive_rings,
                                    "List of NetmapRing objects (Rx)"),
    {NULL}  /* Sentinel */
};


/*########################## NetmapDesc methods ########################*/

static PyObject *
NetmapDesc_enter(NetmapDesc *self)
{
    Py_INCREF(self);
    return (PyObject *)self;
}

static PyObject *
NetmapDesc_exit(NetmapDesc *self, PyObject *args)
{
    if (self->nmd) {
        nm_close(self->nmd);
        self->nmd = NULL;
    }

    Py_RETURN_NONE;
}

static PyObject *
NetmapDesc_xxsync(NetmapDesc *self, int iocmd)
{
    int ret;

    /* Issue the request to the netmap device. */
    ret = ioctl(self->nmd->fd, iocmd, NULL);
    if (ret) {
        PyErr_SetFromErrno(NetmapError);
        return NULL;
    }

    Py_RETURN_NONE;
}

static PyObject *
NetmapDesc_txsync(NetmapDesc *self)
{
    return NetmapDesc_xxsync(self, NIOCTXSYNC);
}

static PyObject *
NetmapDesc_rxsync(NetmapDesc *self)
{
    return NetmapDesc_xxsync(self, NIOCRXSYNC);
}

static PyObject *
NetmapDesc_getfd(NetmapDesc *self)
{
    return Py_BuildValue("i", self->nmd->fd);
}

static PyObject *
NetmapDesc_getringid(NetmapDesc *self)
{
    return Py_BuildValue("k", self->nmd->req.nr_ringid);
}

static PyObject *
NetmapDesc_getflags(NetmapDesc *self)
{
    return Py_BuildValue("k", self->nmd->req.nr_flags);
}

/* A container for the netmap methods. */
static PyMethodDef NetmapDesc_methods[] = {
    {"__enter__", (PyCFunction)NetmapDesc_enter, METH_NOARGS,
        "__enter__ implementation to support with statement"
    },
    {"__exit__", (PyCFunction)NetmapDesc_exit, METH_VARARGS,
        "__exit__ implementation to support with statement"
    },
    {"txsync", (PyCFunction)NetmapDesc_txsync, METH_NOARGS,
        "Do a txsync on the registered rings"
    },
    {"rxsync", (PyCFunction)NetmapDesc_rxsync, METH_NOARGS,
        "Do a rxsync on the registered rings"
    },
    {"getfd", (PyCFunction)NetmapDesc_getfd, METH_NOARGS,
        "Get the file descriptor of the open netmap device"
    },
    {"getringid", (PyCFunction)NetmapDesc_getringid, METH_NOARGS,
        "Get the nr_ringid of the registered interface"
    },
    {"getflags", (PyCFunction)NetmapDesc_getflags, METH_NOARGS,
        "Get the nr_flags of the registered interface"
    },
    {NULL}  /* Sentinel */
};

/* Definition exported to netmap.c. */
PyTypeObject NetmapDescType = {
    PyObject_HEAD_INIT(NULL)
        0,                         /*ob_size*/
    "netmap.NetmapDesc",             /*tp_name*/
    sizeof(NetmapDesc),             /*tp_basicsize*/
    0,                         /*tp_itemsize*/
    (destructor)NetmapDesc_dealloc, /*tp_dealloc*/
    0,                         /*tp_print*/
    0,                         /*tp_getattr*/
    0,                         /*tp_setattr*/
    0,                         /*tp_compare*/
    (reprfunc)NetmapDesc_repr,                 /*tp_repr*/
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
    "Netmap descriptor object",           /* tp_doc */
    0,                     /* tp_traverse */
    0,                     /* tp_clear */
    0,                     /* tp_richcompare */
    0,                     /* tp_weaklistoffset */
    0,                     /* tp_iter */
    0,                     /* tp_iternext */
    NetmapDesc_methods,             /* tp_methods */
    NetmapDesc_members,             /* tp_members */
    NetmapDesc_getseters,                         /* tp_getset */
    0,                         /* tp_base */
    0,                         /* tp_dict */
    0,                         /* tp_descr_get */
    0,                         /* tp_descr_set */
    0,                         /* tp_dictoffset */
    (initproc)NetmapDesc_init,      /* tp_init */
    0,                         /* tp_alloc */
    NetmapDesc_new,                 /* tp_new */
};

