#!/usr/bin/env python
# Copyright (C) 2013-2015, Vincenzo Maffione

import netmap
import time
import struct
import select
import argparse     # program argument parsing


def build_packet():
    fmt = '!6s6sH' + '46s'
    return struct.pack(fmt, '\xff'*6, '\x00'*6, 0x0800, '\x00'*50)


############################## MAIN ###########################

parser = argparse.ArgumentParser(description = 'Minimal, high-performance packet '\
                                               'generator written in Python using '\
                                               'the netmap API',
                                 epilog = 'Press Ctrl-C to stop')
parser.add_argument('-i', '--interface', help = 'the interface to register with netmap; '
                    'can be in the form <OSNAME> or <VALENAME>, where '
                    'OSNAME is the O.S. name for a network interface (e.g. "eth0"), '
                    '<VALENAME> is a valid VALE port name (e.g. "vale18:2")',
                    default = 'vale0:0')

args = parser.parse_args()

pkt = build_packet()

print("Opening interface %s" % (args.interface))

# open the netmap device and register an interface
nm = netmap.Netmap()
nm.open()
nfd = nm.getfd()
nm.if_name = args.interface
nm.register()
time.sleep(1)

# fill in the netmap slots and netmap buffers for tx ring 0
txr = nm.transmit_rings[0]
num_slots = txr.num_slots
for i in range(num_slots):
    txr.slots[i].buf[0:len(pkt)] = pkt
    txr.slots[i].len = len(pkt)

print("Starting transmission, press Ctrl-C to stop")

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

rate = 0.001 * cnt / (t_end - t_start)
unit = 'K'
if rate > 1000:
    rate /= 1000.0
    unit = 'M'

print("\nPackets sent: %s, Avg rate %6.3f %spps" % (cnt, rate, unit))

nm.close()
