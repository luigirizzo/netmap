#!/usr/bin/env python

# Written by Vincenzo Maffione <v.maffione AT gmail DOT com>

import netmap
import time

# open a netmap interface and register
desc = netmap.NetmapDesc('netmap:enp2s0f1')

while 1:
    print('Waiting for a packet to come')

    # sync RX rings with kernel
    desc.rxsync()

    # scan all the receive rings
    rxr = None
    for r in desc.receive_rings:
        if r.head != r.tail:
            # At least one packet has been received on
            # this ring
            rxr = r
            break

    if rxr == None:
        # no packets received on the rings, let's sleep a bit
        time.sleep(1)
        continue

    # slot pointed by rxr.head has been received
    # and can be extracted
    slot = rxr.slots[rxr.head]
    print('Received a packet with len %d' % (slot.len))

    # convert the buffer associated to the slot to
    # a string of hexadecimal digits, up to the received length
    pktstr = ''
    for b in slot.buf[:slot.len].tolist():
        pktstr += '%02x' % (b)

    # print the received packet
    print(pktstr)

    # update head and cur, managing index wraparound
    rxr.head = rxr.head + 1
    if rxr.head >= rxr.num_slots:
        rxr.head -= rxr.num_slots
    rxr.cur = rxr.head
