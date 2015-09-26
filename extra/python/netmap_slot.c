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
NetmapSlot_dealloc(NetmapSlot* self)
{
    if (self->_view.buf) {
        /* XXX Should I free this? I hope self->memoryview
           doesn't do it again in its destructor. */
        free(self->_view.shape);
    }
    Py_XDECREF(self->memoryview);
    self->ob_type->tp_free((PyObject*)self);
}

static PyObject *
NetmapSlot_new(PyTypeObject *type, PyObject *args, PyObject *kwds)
{
    NetmapSlot *self;

    self = (NetmapSlot *)type->tp_alloc(type, 0);
    if (self != NULL) {
        self->_slot = NULL;
        self->memoryview = NULL;
        memset(&self->_view, 0, sizeof(Py_buffer));
    }

    return (PyObject *)self;
}

/* Static data for flags pretty printing. */
static unsigned int ns_flag_values[] = {NS_BUF_CHANGED, NS_REPORT,
                                        NS_FORWARD, NS_NO_LEARN,
                                        NS_INDIRECT, NS_MOREFRAG};

static const char *ns_flag_strings[] = {"NsBufChanged", "NsReport",
                                        "NsForward", "NsNoLearn",
                                        "NsIndirect", "NsMorefrag"};

static PyObject *
NetmapSlot_repr(NetmapSlot *self)
{
    PyObject *result;
    struct netmap_slot *slot = self->_slot;
    char flags[256];

    if (slot == NULL) {
        return Py_BuildValue("s", "Invalid NetmapSlot");
    }

    netmap_flags_pretty(slot->flags, flags, sizeof(flags), ns_flag_values,
                            ns_flag_strings,
                            sizeof(ns_flag_values)/sizeof(*ns_flag_values));

    result = PyString_FromFormat(
            "buf_idx:       %u\n"
            "len:           %u\n"
            "flags:         [0x%04x] %s\n"
            "ptr:           0x%016x\n",
            slot->buf_idx,
            slot->len,
            slot->flags,
            flags,
            slot->ptr
            );

    return result;
}


static PyMemberDef NetmapSlot_members[] = {
    {NULL}
};

int
NetmapSlot_build(NetmapSlot *self, void *addr, void *buf)
{
    /* Init the pointer. */
    self->_slot = (struct netmap_slot *)addr;

    /* Populate a Py_buffer struct, which represents a C memory
       buffer. */
    memset(&self->_view, 0, sizeof(Py_buffer));
    self->_view.buf = buf;
    self->_view.len = self->_slot->len;
    self->_view.format = "B";
    self->_view.ndim = 1;
    self->_view.shape = malloc(1 * sizeof (Py_ssize_t));
    self->_view.shape[0] = self->_slot->len;
    self->_view.itemsize = 1;

    /* Expose the C buffer through a 'memoryview' Python object,
       so that Python code can directly access the C buffer. */
    self->memoryview = PyMemoryView_FromBuffer(&self->_view);
    if (!self->memoryview) {
        return -1;
    }

    return 0;
}

void
NetmapSlot_destroy(NetmapSlot *self)
{
    self->_slot = NULL;

    if (self->_view.buf) {
        free(self->_view.shape);
        memset(&self->_view, 0, sizeof(Py_buffer));
    }

/* TODO should destroy self->memoryview */
}

/*########################## set/get methods #######################*/

static PyObject *
NetmapSlot_memoryview_get(NetmapSlot *self, void *closure)
{
    if (self->memoryview == NULL) {
        Py_RETURN_NONE;
    }
    Py_INCREF(self->memoryview);

    return self->memoryview;
}

static int
NetmapSlot_memoryview_set(NetmapSlot *self, PyObject *value, void *closure)
{
    if (value == NULL) {
        PyErr_SetString(PyExc_TypeError, "Cannot delete the attribute");
    } else {
        PyErr_SetString(PyExc_TypeError, "Cannot modify the attribute");
    }

    return -1;
}

#define DEFINE_NETMAP_SLOT_GETSET(field, type, format)                      \
static PyObject *                                                           \
NetmapSlot_##field##_get(NetmapSlot *self, void *closure)                   \
{                                                                           \
    if (!self->_slot) {                                                     \
        Py_RETURN_NONE;                                                     \
    }                                                                       \
    return Py_BuildValue(format, self->_slot->field);                       \
}                                                                           \
                                                                            \
static int                                                                  \
NetmapSlot_##field##_set(NetmapSlot *self, PyObject *value, void *closure)  \
{                                                                           \
    long x;                                                                 \
    if (!self->_slot) {                                                     \
        PyErr_SetString(PyExc_TypeError, "Attribute not available");        \
        return -1;                                                          \
    }                                                                       \
    x = PyInt_AsLong(value);                                                \
    if (x == -1 && PyErr_Occurred()) {                                      \
        return -1;                                                          \
    }                                                                       \
    /* Override the 'const' specifier. */                                   \
    *((type *)&self->_slot->field) = (type)x;                               \
    return 0;                                                               \
}

DEFINE_NETMAP_SLOT_GETSET(buf_idx, uint32_t, "I");
DEFINE_NETMAP_SLOT_GETSET(len, uint16_t, "I");
DEFINE_NETMAP_SLOT_GETSET(flags, uint16_t, "I");
DEFINE_NETMAP_SLOT_GETSET(ptr, uint64_t, "k");


#define DECLARE_NETMAP_SLOT_GETSETERS(field)                                \
    {#field,                                                                \
        (getter)NetmapSlot_##field##_get, (setter)NetmapSlot_##field##_set, \
        "netmap ring " #field " field",                                     \
        NULL}

static PyGetSetDef NetmapSlot_getseters[] = {
    DECLARE_NETMAP_SLOT_GETSETERS(buf_idx),
    DECLARE_NETMAP_SLOT_GETSETERS(len),
    DECLARE_NETMAP_SLOT_GETSETERS(flags),
    DECLARE_NETMAP_SLOT_GETSETERS(ptr),
    {"buf",
        (getter)NetmapSlot_memoryview_get, (setter)NetmapSlot_memoryview_set,
        "netmap buffer memoryview",
        NULL},
    {NULL}  /* Sentinel */
};


static PyMethodDef NetmapSlot_methods[] = {
    {NULL}
};

/* Definition exported to netmap.c. */
PyTypeObject NetmapSlotType = {
    PyObject_HEAD_INIT(NULL)
        0,                         /*ob_size*/
    "netmap.NetmapSlot",             /*tp_name*/
    sizeof(NetmapSlot),             /*tp_basicsize*/
    0,                         /*tp_itemsize*/
    (destructor)NetmapSlot_dealloc, /*tp_dealloc*/
    0,                         /*tp_print*/
    0,                         /*tp_getattr*/
    0,                         /*tp_setattr*/
    0,                         /*tp_compare*/
    (reprfunc)NetmapSlot_repr,                 /*tp_repr*/
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
    NetmapSlot_methods,             /* tp_methods */
    NetmapSlot_members,             /* tp_members */
    NetmapSlot_getseters,                         /* tp_getset */
    0,                         /* tp_base */
    0,                         /* tp_dict */
    0,                         /* tp_descr_get */
    0,                         /* tp_descr_set */
    0,                         /* tp_dictoffset */
    0,      /* tp_init */
    0,                         /* tp_alloc */
    NetmapSlot_new,                 /* tp_new */
};

