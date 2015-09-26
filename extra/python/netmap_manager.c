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
#include <net/netmap_user.h>


enum {
    MANAGER_CLOSED = 0,
    MANAGER_OPENED = 1,
    MANAGER_REGISTERED = 2
};

/* Destructor method for NetmapManagerType. */
static void
NetmapManager_dealloc(NetmapManager* self)
{
    /* The 'X' is necessary only here: In all the other places, because of
       our getters/setters we are sure that PyObject* members cannot be NULL.
       */
    Py_XDECREF(self->dev_name);
    Py_XDECREF(self->if_name);
    NetmapMemory_dealloc(&self->memory);
    self->ob_type->tp_free((PyObject*)self);
}

/* Netmap.__new__() is the constructor. */
static PyObject *
NetmapManager_new(PyTypeObject *type, PyObject *args, PyObject *kwds)
{
    NetmapManager *self;

    self = (NetmapManager *)type->tp_alloc(type, 0);
    if (self == NULL) {
        return NULL;
    }

    /* Init with defaults. */
    self->dev_name = PyString_FromString("/dev/netmap");
    if (self->dev_name == NULL) {
        Py_DECREF(self);
        return NULL;
    }

    self->if_name = PyString_FromString("");
    if (self->if_name == NULL) {
        Py_DECREF(self);
        return NULL;
    }

    memset(&self->nmreq, 0, sizeof(self->nmreq));
    self->nmreq.nr_version = NETMAP_API;
    self->nmreq.nr_flags = NR_REG_DEFAULT;  /* Legacy 'ringid'. */
    self->nmreq.nr_ringid = 0;   /* Bind all physical rings. */

    NetmapMemory_new(&self->memory);

    self->_state = MANAGER_CLOSED;
    self->_fd = INVALID_FD;
    self->_memaddr = NULL;

    return (PyObject *)self;
}

/* Netmap.__init__(), may be called many times, or not called at all. */
static int
NetmapManager_init(NetmapManager *self, PyObject *args, PyObject *kwds)
{
    PyObject *dev_name = NULL;
    static char *kwlist[] = {"dev_name", "version", NULL};

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "|SI", kwlist,
                &dev_name, &self->nmreq.nr_version)) {
        return -1;
    }

    if (dev_name) {
        PyObject *tmp;

        /* Safe reference. */
        tmp = self->dev_name;
        Py_INCREF(dev_name);
        self->dev_name = dev_name;
        Py_XDECREF(tmp);
    }

    return 0;
}

static PyObject *
NetmapManager_repr(NetmapManager *self)
{
    PyObject *result;
    char ringid[128];
    char flags[128];
    char cmd[64];
    struct nmreq *req = &self->nmreq;

    /* Fills in the 'ringid' and 'flags' string buffers. */
    ringid_pretty_print(req->nr_ringid, req->nr_flags, ringid,
                        sizeof(ringid), flags, sizeof(flags));

    switch (req->nr_cmd) {
        case 0:
            sprintf(cmd, "None");
            break;
        case NETMAP_BDG_ATTACH:
            sprintf(cmd, "Bridge attach");
            break;
        case NETMAP_BDG_DETACH:
            sprintf(cmd, "Bridge detach");
            break;
        case NETMAP_BDG_REGOPS:
            sprintf(cmd, "Bridge lookup register");
            break;
        case NETMAP_BDG_LIST:
            sprintf(cmd, "Bridge list");
            break;
        case NETMAP_BDG_VNET_HDR:
            sprintf(cmd, "Bridge set virtio-net header length");
            break;
    }

    result = PyString_FromFormat(
            "dev_name:  '%s'\n"
            "if_name:   '%s'\n"
            "version:   %d\n"
            "memsize:   %u KiB\n"
            "offset:    %u\n"
            "tx_slots:  %d\n"
            "rx_slots:  %d\n"
            "tx_rings:  %d\n"
            "rx_rings:  %d\n"
            "ringid:    %s\n"
            "cmd:       [%d] %s\n"
            "arg1:      %d\n"
            "arg2:      %d\n"
            "arg3:      %d\n"
            "flags:     %s\n"
            "spare2:    %d\n",
            PyString_AsString(self->dev_name),
            PyString_AsString(self->if_name), req->nr_version,
            req->nr_memsize / 1024, req->nr_offset,
            req->nr_tx_slots, req->nr_rx_slots,
            req->nr_tx_rings, req->nr_rx_rings,
            ringid, req->nr_cmd, cmd, req->nr_arg1,
            req->nr_arg2, req->nr_arg3, flags, req->spare2[0]
                );

    return result;
}


/* A container for Netmap attributes where set/get methods are
   managed automatically. */
static PyMemberDef NetmapManager_members[] = {
    {"version", T_UINT, offsetof(NetmapManager, nmreq.nr_version), 0,
        "netmap API version"},
    {"tx_slots", T_UINT, offsetof(NetmapManager, nmreq.nr_tx_slots), 0,
        "number of TX slots in each ring"},
    {"rx_slots", T_UINT, offsetof(NetmapManager, nmreq.nr_rx_slots), 0,
        "number of RX slots in each ring"},
    {"tx_rings", T_USHORT, offsetof(NetmapManager, nmreq.nr_tx_rings), 0,
        "number of TX rings"},
    {"rx_rings", T_USHORT, offsetof(NetmapManager, nmreq.nr_rx_rings), 0,
        "number of RX rings"},
    {"ringid", T_USHORT, offsetof(NetmapManager, nmreq.nr_ringid), 0,
        "identifies which rings to tie to"},
    {"cmd", T_USHORT, offsetof(NetmapManager, nmreq.nr_cmd), 0,
        "cmd"},
    {"arg1", T_USHORT, offsetof(NetmapManager, nmreq.nr_arg1), 0,
        "arg1 field"},
    {"arg2", T_USHORT, offsetof(NetmapManager, nmreq.nr_arg2), 0,
        "arg2 field"},
    {"arg3", T_UINT, offsetof(NetmapManager, nmreq.nr_arg3), 0,
        "arg3 field"},
    {"flags", T_UINT, offsetof(NetmapManager, nmreq.nr_flags), 0,
        "flags"},
    {"spare2", T_UINT, offsetof(NetmapManager, nmreq.spare2[0]), 0,
        "spare2 field"},
    {NULL}  /* Sentinel */
};


/*########################## set/get methods #######################*/

static PyObject *
NetmapManager_dev_name_get(NetmapManager *self, void *closure)
{
    return string_get(self->dev_name);
}

static int
NetmapManager_dev_name_set(NetmapManager *self, PyObject *value, void *closure)
{
    return string_set(&self->dev_name, value);
}

static PyObject *
NetmapManager_if_name_get(NetmapManager *self, void *closure)
{
    return string_get(self->if_name);
}

static int
NetmapManager_if_name_set(NetmapManager *self, PyObject *value, void *closure)
{
    return string_set(&self->if_name, value);
}

#define NETMAP_MANAGER_DEFINE_GETSET(obj)                                   \
static PyObject *                                                           \
NetmapManager_##obj##_get(NetmapManager *self, void *closure)               \
{                                                                           \
    if (self->memory.obj == NULL) {                                         \
        Py_RETURN_NONE;                                                     \
    }                                                                       \
    Py_INCREF(self->memory.obj);                                            \
    return self->memory.obj;                                                \
}                                                                           \
                                                                            \
static int                                                                  \
NetmapManager_##obj##_set(NetmapManager *self, PyObject *value,             \
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
        (getter)NetmapManager_##obj##_get,                                  \
        (setter)NetmapManager_##obj##_set,                                  \
         desc,                                                              \
        NULL}


static PyGetSetDef NetmapManager_getseters[] = {
    {"dev_name",
        (getter)NetmapManager_dev_name_get, (setter)NetmapManager_dev_name_set,
        "netmap device name",
        NULL},
    {"if_name",
        (getter)NetmapManager_if_name_get, (setter)NetmapManager_if_name_set,
        "interface name",
        NULL},
    NETMAP_MANAGER_DECLARE_GETSET(interface, "NetmapInterface object"),
    NETMAP_MANAGER_DECLARE_GETSET(transmit_rings,
                                    "List of NetmapRing objects (Tx)"),
    NETMAP_MANAGER_DECLARE_GETSET(receive_rings,
                                    "List of NetmapRing objects (Rx)"),
    {NULL}  /* Sentinel */
};

static void
NetmapManager_destroy(NetmapManager *self)
{
    NetmapMemory_destroy(&self->memory);
}


/*########################## NetmapManager methods ########################*/

static PyObject *
NetmapManager_open(NetmapManager* self)
{
    const char *dev_name;
    int fd;

    dev_name = PyString_AsString(self->dev_name);
    if (dev_name == NULL) {
        return NULL;
    }

    if (self->_state != MANAGER_CLOSED) {
        PyErr_SetString(NetmapError, "Cannot open netmap device twice");
        return NULL;
    }

    fd = open(dev_name, O_RDWR);
    if (fd < 0) {
        PyErr_SetFromErrno(NetmapError);
        return NULL;
    }
    self->_fd = fd;
    self->_state = MANAGER_OPENED;

    Py_RETURN_NONE;
}

static PyObject *
NetmapManager_close(NetmapManager* self)
{
    int ret;

    if (self->_state == MANAGER_CLOSED) {
        PyErr_SetString(NetmapError, "Netmap device is not opened");
        return NULL;
    }

    if (self->_memaddr) {
        munmap(self->_memaddr, self->nmreq.nr_memsize);
        self->_memaddr = NULL;
        self->nmreq.nr_memsize = 0;
    }

    ret = close(self->_fd);
    if (ret) {
        PyErr_SetFromErrno(NetmapError);
        return NULL;
    }
    self->_fd = INVALID_FD;
    self->_state = MANAGER_CLOSED;

    NetmapManager_destroy(self);

    Py_RETURN_NONE;
}

static int
NetmapManager_ioctl(NetmapManager *self, int iocmd)
{
    struct nmreq req;
    const char *if_name;
    int ret;

    if_name = PyString_AsString(self->if_name);
    if (if_name == NULL) {
        return -1;
    }

    /* Prepare the netmap request ioctl argument. */
    memcpy(&req, &self->nmreq, sizeof(req));
    strncpy(req.nr_name, if_name, IFNAMSIZ);

    /* Issue the request to the netmap device. */
    ret = ioctl(self->_fd, iocmd, &req);
    if (ret) {
        PyErr_SetFromErrno(NetmapError);
        return -1;
    }

    /* Request writeback. */
    memcpy(&self->nmreq, &req, sizeof(req));

    return 0;
}

static PyObject *
NetmapManager_register(NetmapManager *self)
{
    NetmapInterface *interface;
    NetmapRing *ring;
    PyObject *list;
    int ret;
    int i;

    if (self->_state != MANAGER_OPENED) {
        if (self->_state == MANAGER_CLOSED) {
            PyErr_SetString(NetmapError, "Netmap device is not opened");
        } else if (self->_state == MANAGER_REGISTERED) {
            PyErr_SetString(NetmapError,
                            "Netmap interface already registered");
        }
        return NULL;
    }

    /* Issue a NIOCREGIF command. */
    ret = NetmapManager_ioctl(self, NIOCREGIF);
    if (ret == -1) {
        return NULL;
    }

    /* Map netmap memory area. */
    self->_memaddr = mmap(0, self->nmreq.nr_memsize,
                            PROT_WRITE | PROT_READ,
                                MAP_SHARED, self->_fd, 0);
    if (self->_memaddr == MAP_FAILED) {
        self->_memaddr = NULL;
        PyErr_SetFromErrno(NetmapError);
        return NULL;
    }

    /* Setup the Python data structures corresponding to the netmap memory layout.
       The +1 are here to take into account the host rings. */
    ret = NetmapMemory_setup(&self->memory, NETMAP_IF(self->_memaddr,
                        self->nmreq.nr_offset), self->nmreq.nr_tx_rings + 1,
                        self->nmreq.nr_rx_rings + 1);
    if (ret) {
        return NULL;
    }

    self->_state = MANAGER_REGISTERED;

    Py_RETURN_NONE;
}

static PyObject *
NetmapManager_xxsync(NetmapManager *self, int iocmd)
{
    int ret;

    if (self->_state == MANAGER_CLOSED) {
        PyErr_SetString(NetmapError, "Netmap device is not opened");
        return NULL;
    }

    if (self->_state == MANAGER_OPENED) {
        PyErr_SetString(NetmapError, "Netmap interface is not registered");
        return NULL;
    }

    /* Issue the request to the netmap device. */
    ret = ioctl(self->_fd, iocmd, NULL);
    if (ret) {
        PyErr_SetFromErrno(NetmapError);
        return NULL;
    }

    Py_RETURN_NONE;
}

static PyObject *
NetmapManager_txsync(NetmapManager *self)
{
    return NetmapManager_xxsync(self, NIOCTXSYNC);
}

static PyObject *
NetmapManager_rxsync(NetmapManager *self)
{
    return NetmapManager_xxsync(self, NIOCRXSYNC);
}

static PyObject *
NetmapManager_getfd(NetmapManager *self)
{
    if (self->_state == MANAGER_CLOSED) {
        PyErr_SetString(NetmapError, "Netmap device is not opened");
        return NULL;
    }

    return Py_BuildValue("i", self->_fd);
}

static PyObject *
NetmapManager_getinfo(NetmapManager *self)
{
    int ret;

    if (self->_state == MANAGER_CLOSED) {
        PyErr_SetString(NetmapError, "Netmap device is not opened");
        return NULL;
    }

    /* Issue a NIOCGINFO command. */
    ret = NetmapManager_ioctl(self, NIOCGINFO);
    if (ret == -1) {
        return NULL;
    }

    Py_RETURN_NONE;
}

static PyObject *
NetmapManager_clear(NetmapManager *self)
{
    memset(&self->nmreq, 0, sizeof(self->nmreq));
    self->nmreq.nr_version = NETMAP_API;
    self->nmreq.nr_flags = NR_REG_DEFAULT;  /* Legacy 'ringid'. */
    self->nmreq.nr_ringid = 0;   /* Bind all physical rings. */

    Py_RETURN_NONE;
}

static PyObject *
NetmapManager_regif(NetmapManager *self)
{
    int ret;

    if (self->_state == MANAGER_CLOSED) {
        PyErr_SetString(NetmapError, "Netmap device is not opened");
        return NULL;
    }

    /* Issue a NIOCGREGIF command. */
    ret = NetmapManager_ioctl(self, NIOCREGIF);
    if (ret == -1) {
        return NULL;
    }

    Py_RETURN_NONE;
}

/* A container for the netmap methods. */
static PyMethodDef NetmapManager_methods[] = {
    {"open", (PyCFunction)NetmapManager_open, METH_NOARGS,
        "Open the netmap device"
    },
    {"close", (PyCFunction)NetmapManager_close, METH_NOARGS,
        "Close the netmap device"
    },
    {"register", (PyCFunction)NetmapManager_register, METH_NOARGS,
        "Register an interface with netmap"
    },
    {"txsync", (PyCFunction)NetmapManager_txsync, METH_NOARGS,
        "Do a txsync on the registered rings"
    },
    {"rxsync", (PyCFunction)NetmapManager_rxsync, METH_NOARGS,
        "Do a rxsync on the registered rings"
    },
    {"getfd", (PyCFunction)NetmapManager_getfd, METH_NOARGS,
        "Get the file descriptor of the open netmap device"
    },
    {"getinfo", (PyCFunction)NetmapManager_getinfo, METH_NOARGS,
        "Ask netmap for interface info"
    },
    {"clear", (PyCFunction)NetmapManager_clear, METH_NOARGS,
        "Reset some netmap request fields to their default values"
    },
    {"regif", (PyCFunction)NetmapManager_regif, METH_NOARGS,
        "Issue a NIOCREGIF command to the netmap device (can be used to issue "
        "NETMAP_BDG_ATTACH and similar commands)"
    },
    {NULL}  /* Sentinel */
};

/* Definition exported to netmap.c. */
PyTypeObject NetmapManagerType = {
    PyObject_HEAD_INIT(NULL)
        0,                         /*ob_size*/
    "netmap.Netmap",             /*tp_name*/
    sizeof(NetmapManager),             /*tp_basicsize*/
    0,                         /*tp_itemsize*/
    (destructor)NetmapManager_dealloc, /*tp_dealloc*/
    0,                         /*tp_print*/
    0,                         /*tp_getattr*/
    0,                         /*tp_setattr*/
    0,                         /*tp_compare*/
    (reprfunc)NetmapManager_repr,                 /*tp_repr*/
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
    "Netmap manager object",           /* tp_doc */
    0,                     /* tp_traverse */
    0,                     /* tp_clear */
    0,                     /* tp_richcompare */
    0,                     /* tp_weaklistoffset */
    0,                     /* tp_iter */
    0,                     /* tp_iternext */
    NetmapManager_methods,             /* tp_methods */
    NetmapManager_members,             /* tp_members */
    NetmapManager_getseters,                         /* tp_getset */
    0,                         /* tp_base */
    0,                         /* tp_dict */
    0,                         /* tp_descr_get */
    0,                         /* tp_descr_set */
    0,                         /* tp_dictoffset */
    (initproc)NetmapManager_init,      /* tp_init */
    0,                         /* tp_alloc */
    NetmapManager_new,                 /* tp_new */
};

