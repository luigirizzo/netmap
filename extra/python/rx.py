#!/usr/bin/env python
# Description: Simple netmap rx example
# Author: Faisal T. Abu-Nimeh (abunimeh@)

import netmap
import select

IF_NAME = 'em0'

d=netmap.NetmapDesc('netmap:' + IF_NAME)
rxr = d.receive_rings[0] # single ring example
# use poll
poller = select.poll()
poller.register(d.getfd(), select.POLLIN)

while True:
    ready_list = poller.poll() # wait for data
    if len(ready_list) == 0:
        print("Timeout occurred")
        break;

    if not rxr.empty(): # only process nonempty ring
        i = rxr.cur

        flen = rxr.slots[i].len
        if flen > rxr.nr_buf_size: continue # drop large packets
        fbuf = rxr.slots[i].buf[:flen] # this will fail if flen > nr_buf_size, i.e., nr_buf_size must be >= mtu

        # drop everything except the following:
        # if frame is an IP_pkt and UDP_pkt and and UDP_DST_PORT is 9956 
        if fbuf[12:14] == '\x08\x00' and fbuf[23] == '\x11' and fbuf[36:38] == '\x26\xe4':
            print "udp/ip pkt on my port"
            print "netmap len=" + str(flen)
            print "actual len=" + str(len(fbuf))
            print "first=%02x" % ord(fbuf[0])
            print "last=%02x" % ord(fbuf[-1])            

        # increment netmap pointers
        rxr.cur = rxr.head = 0 if (i+1 == rxr.num_slots) else i+1
