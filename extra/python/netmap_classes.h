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
