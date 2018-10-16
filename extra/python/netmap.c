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

#include <Python.h>

#include <net/if.h>         /* IFNAMSIZ */
#include <net/netmap.h>
#include <net/netmap_user.h>

#include "netmap_classes.h"


/* ############## Data and functions useful to all the classes ############# */
PyObject *NetmapError;

PyObject *
string_get(PyObject *str)
{
    Py_INCREF(str);

    return str;
}

int
string_set(PyObject **str, PyObject *value)
{
    if (value == NULL) {
        PyErr_SetString(PyExc_TypeError, "Cannot delete the attribute");
        return -1;
    }

    if (!PyString_Check(value)) {
        PyErr_SetString(PyExc_TypeError,
                "The attribute value must be a string");
        return -1;
    }

    Py_DECREF(*str);
    Py_INCREF(value);
    *str = value;

    return 0;
}

/* @flags: contains the bits we want to pretty-print
   @str: where to print
   @avail: length of @str
   @values: array of all the possible flags
   @strings: array of names associated to each flag
   @items: length of @values and @strings
*/
void
netmap_flags_pretty(unsigned int flags, char *str, int avail,
                    unsigned int *values, const char **strings, int items)
{
    int ret;
    int i;

    for (i = 0; avail && i < items; i++) {
        if (flags & values[i]) {
            ret = snprintf(str, avail, "[%s],", strings[i]);
            if (ret < 0) {
                *str = '\0';
                return;
            }
            str += ret;
            avail -= ret;
        }
    }

    *str = '\0';
}

static unsigned int nr_flags_values[] = { NR_MONITOR_TX, NR_MONITOR_RX };
static const char *nr_flags_strings[] = { "MonitorTx", "MonitorRx" };
static unsigned int nr_poll_values[] = { NETMAP_NO_TX_POLL,
                                          NETMAP_DO_RX_POLL };
static const char *nr_poll_strings[] = { "NoTxPoll", "DoRxPoll" };

/* Pretty print nr_ringid and nr_flags. */
void
ringid_pretty_print(uint32_t nr_ringid, uint32_t nr_flags,
                    char *ringid, int rsz, char *flags, int fsz)
{
    unsigned int idx;
    int nr, nf;

    idx = nr_ringid & NETMAP_RING_MASK;

    if ((nr_flags & NR_REG_MASK) == (uint32_t)NR_REG_DEFAULT) {
        /* Legacy 'ringid' API. */
        unsigned int ringflags = nr_ringid & ~NETMAP_RING_MASK
                        & ~NETMAP_NO_TX_POLL & ~NETMAP_DO_RX_POLL;

        switch (ringflags) {
            case 0:
                nr = sprintf(ringid, "[0x%04X] all hardware rings ",
                                nr_ringid);
                break;
            case NETMAP_HW_RING:
                nr = sprintf(ringid, "[0x%04X] hardware rings pair %u ",
                                nr_ringid, idx);
                break;
            case NETMAP_SW_RING:
                nr = sprintf(ringid, "[0x%04X] host rings pair ", nr_ringid);
                break;
            default:
                nr = sprintf(ringid, "[0x%04X] ***UNKNOWN*** ", nr_ringid);
        }

        sprintf(flags, "[0x%08X] Legacy ringid", nr_flags);
    } else {
        /* New 'ringid' API. */
        nr = sprintf(ringid, "[0x%04X] %u ", nr_ringid, idx);

        switch (nr_flags & NR_REG_MASK) {
            case NR_REG_ALL_NIC:
                nf = sprintf(flags, "[0x%08X] all hardware rings ", nr_flags);
                break;
            case NR_REG_SW:
                nf = sprintf(flags, "[0x%08X] host ring pair ", nr_flags);
                break;
            case NR_REG_NIC_SW:
                nf = sprintf(flags, "[0x%08X] all hardware and host rings ",
                                nr_flags);
                break;
            case NR_REG_ONE_NIC:
                nf = sprintf(flags, "[0x%08X] an hardware rings pair ",
                                nr_flags);
                break;
            case NR_REG_PIPE_MASTER:
                nf = sprintf(flags, "[0x%08X] a master pipe rings pair ",
                                nr_flags);
                break;
            case NR_REG_PIPE_SLAVE:
                nf = sprintf(flags, "[0x%08X] a slave pipe rings pair ",
                                nr_flags);
                break;
            default:
                nf = sprintf(flags, "[0x%08X] ***UNKNOWN*** ", nr_flags);
        }
        if (nf > 0) {
            netmap_flags_pretty(nr_flags, flags + nf, fsz - nf,
                                nr_flags_values, nr_flags_strings,
                        sizeof(nr_flags_values) / sizeof(nr_flags_values[0]));
        }
    }

    if (nr > 0) {
        netmap_flags_pretty(nr_ringid, ringid + nr, rsz - nr,
                nr_poll_values, nr_poll_strings,
                sizeof(nr_poll_values) / sizeof(nr_poll_values[0]));
    }
}


/*########################### Module functions ############################*/
static PyObject *
netmap_hello(PyObject *self, PyObject *args)
{
    const char *msg;

    if (!PyArg_ParseTuple(args, "s", &msg)) {
        return NULL;
    }

    return Py_BuildValue("s", msg);
}

static PyMethodDef netmap_functions[] = {
    { "hello", (PyCFunction)netmap_hello, METH_VARARGS, NULL },
    { NULL, NULL, 0, NULL }
};

#ifndef PyMODINIT_FUNC  /* declarations for DLL import/export */
#define PyMODINIT_FUNC void
#endif

/* An integer constant visible from Python. */
struct NetmapConst {
    const char *name;
    long value;
};

static struct NetmapConst netmap_constants[] = {
    {
        .name = "AllHwRings",
        .value = 0,
    },
    {
        .name = "HwRing",
        .value = NETMAP_HW_RING,
    },
    {
        .name = "SwRing",
        .value = NETMAP_SW_RING,
    },
    {
        .name = "NoTxPoll",
        .value = NETMAP_NO_TX_POLL,
    },
    {
        .name = "DoRxPoll",
        .value = NETMAP_DO_RX_POLL,
    },
    /* Add 'nmreq.flags' constants to the module. */
    {
        .name = "RegDefault",
        .value = NR_REG_DEFAULT,
    },
    {
        .name = "RegAllNic",
        .value = NR_REG_ALL_NIC,
    },
    {
        .name = "RegSw",
        .value = NR_REG_SW,
    },
    {
        .name = "RegNicSw",
        .value = NR_REG_NIC_SW,
    },
    {
        .name = "RegOneNic",
        .value = NR_REG_ONE_NIC,
    },
    {
        .name = "RegPipeMaster",
        .value = NR_REG_PIPE_MASTER,
    },
    {
        .name = "RegPipeSlave",
        .value = NR_REG_PIPE_SLAVE,
    },
    {
        .name = "RegMonitorTx",
        .value = NR_MONITOR_TX,
    },
    {
        .name = "RegMonitorRx",
        .value = NR_MONITOR_RX,
    },
    {
        .name = "RegZcopyMon",
        .value = NR_ZCOPY_MON,
    },
    {
        .name = "RegExclusive",
        .value = NR_EXCLUSIVE,
    },
    /* Add 'netmap_rings.flags' constants to the module. */
    {
        .name = "NrTimestamp",
        .value = NR_TIMESTAMP,
    },
    {
        .name = "NrForward",
        .value = NR_FORWARD,
    },
    /* Add 'netmap_slot.flags' constants to the module. */
    {
        .name = "NsBufChanged",
        .value = NS_BUF_CHANGED,
    },
    {
        .name = "NsReport",
        .value = NS_REPORT,
    },
    {
        .name = "NsForward",
        .value = NS_FORWARD,
    },
    {
        .name = "NsNoLearn",
        .value = NS_NO_LEARN,
    },
    {
        .name = "NsIndirect",
        .value = NS_INDIRECT,
    },
    {
        .name = "NsMorefrag",
        .value = NS_MOREFRAG,
    },
    /* Add bridge and passthrough management commands. */
    {
        .name = "BdgAttach",
        .value = NETMAP_BDG_ATTACH,
    },
    {
        .name = "BdgDetach",
        .value = NETMAP_BDG_DETACH,
    },
    {
        .name = "BdgRegOps",
        .value = NETMAP_BDG_REGOPS,
    },
    {
        .name = "BdgList",
        .value = NETMAP_BDG_LIST,
    },
    {
        .name = "BdgVnetHdr",
        .value = NETMAP_BDG_VNET_HDR,
    },
    {
        .name = "BdgNewIf",
        .value = NETMAP_BDG_NEWIF,
    },
    {
        .name = "BdgDelIf",
        .value = NETMAP_BDG_DELIF,
    },
    {
        .name = "PtHostCreate",
        .value = NETMAP_PT_HOST_CREATE,
    },
    {
        .name = "PtHostDelete",
        .value = NETMAP_PT_HOST_DELETE,
    },
    {
        .name = "BdgHost",
        .value = NETMAP_BDG_HOST,
    }
};


/*############################### Module init #############################*/
PyMODINIT_FUNC
initnetmap()
{
    PyObject *module;
    int i;

    /* Initialize Netmap***Type. */
    if (PyType_Ready(&NetmapManagerType) < 0)
        return;
    if (PyType_Ready(&NetmapInterfaceType) < 0)
        return;
    if (PyType_Ready(&NetmapRingType) < 0)
        return;
    if (PyType_Ready(&NetmapSlotType) < 0)
        return;
    if (PyType_Ready(&NetmapDescType) < 0)
        return;

    /* Create the python module. */
    module = Py_InitModule3("netmap", netmap_functions,
                            "Netmap bindings for Python.");

    /* Add the Netmap***Type to the module. */
    Py_INCREF(&NetmapManagerType);
    PyModule_AddObject(module, "Netmap", (PyObject *)&NetmapManagerType);
    Py_INCREF(&NetmapInterfaceType);
    PyModule_AddObject(module, "NetmapInterface",
                        (PyObject *)&NetmapInterfaceType);
    Py_INCREF(&NetmapRingType);
    PyModule_AddObject(module, "NetmapRing", (PyObject *)&NetmapRingType);
    Py_INCREF(&NetmapSlotType);
    PyModule_AddObject(module, "NetmapSlot", (PyObject *)&NetmapSlotType);
    Py_INCREF(&NetmapDescType);
    PyModule_AddObject(module, "NetmapDesc", (PyObject *)&NetmapDescType);

    /* Add the NetmapError to the module. */
    NetmapError = PyErr_NewException("netmap.error", NULL, NULL);
    Py_INCREF(NetmapError);
    PyModule_AddObject(module, "error", NetmapError);

    /* Add some integer constants to the module. */
    for (i = 0; i < sizeof(netmap_constants)/sizeof(struct NetmapConst); i++) {
        PyModule_AddIntConstant(module, netmap_constants[i].name,
                                    netmap_constants[i].value);
    }
}

