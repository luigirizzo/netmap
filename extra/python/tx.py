#!/usr/bin/env python

import netmap
import time
import struct
import select


def build_packet():
    fmt = '!6s6sH' + '46s'
    return struct.pack(fmt, '\xff'*6, '\x00'*6, 0x0800, '\x00'*50)


############################## MAIN ###########################
pkt = build_packet()

# open the netmap device and register an interface
nm = netmap.Netmap()
nm.open()
nfd = nm.getfd()
nm.if_name = 'vale:1'
nm.register()
time.sleep(1)

# fill in the netmap slots and netmap buffers for tx ring 0
txr = nm.transmit_rings[0]
num_slots = txr.num_slots
for i in range(num_slots):
    txr.slots[i].buf[0:len(pkt)] = pkt
    txr.slots[i].len = len(pkt)


# transmit at maximum speed until Ctr-C is pressed
cnt = 0         # packet counter
batch = 256
poller = select.poll()
poller.register(nfd, select.POLLOUT)
t_start = time.time()
try:
    cur = txr.cur
    while 1:
        ready_list = poller.poll(2)
        if len(ready_list) == 0:
            print("Timeout occurred")
            break;
        n = txr.tail - cur  # avail
        if n < 0:
            n += num_slots
        if n > batch:
            n = batch
        cur += n
        if cur >= num_slots:
            cur -= num_slots
        txr.cur = txr.head = cur # lazy update txr.cur and txr.head
        nm.txsync()
        cnt += n
except KeyboardInterrupt:
    pass
t_end = time.time()

print("\nPackets sent: %s, Avg rate %s Kpps" % (cnt, 0.001 * cnt / (t_end - t_start)))

nm.close()
