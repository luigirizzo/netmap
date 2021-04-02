#!/usr/bin/env python
#
# Packet generator written in Python, providing functionalities
# similar to the netmap pkt-gen written in C
#
#   Author: Vincenzo Maffione
#

import netmap       # our module
import time         # time measurements
import select       # poll()
import argparse     # program argument parsing
import multiprocessing    # thread management
import re

# import scapy suppressing the initial WARNING message
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import Ether, IP, UDP  # packet forgery


def help_quit(parser):
    print("")
    parser.print_help()
    quit()


def build_packet(args, parser):
    src = args.src.split(':')
    dst = args.dst.split(':')

    # create the payload
    base = "Hello from Python"
    header_len = 14 + 20 + 8
    data = base * ((args.length-header_len)/len(base) + 1)
    data = data[0:args.length-header_len]

    scap = Ether(src = args.srcmac, dst = args.dstmac)
    scap = scap / IP(src = src[0], dst = dst[0])
    scap = scap / UDP(sport = int(src[1]), dport = int(dst[1]))
    scap = scap / data

    try:
        # checksum is computed when calling str(scap), e.g. when the packet is
        # assembled
        ret = str(scap)
    except:
        print("Packet parameters are invalid\n")
        help_quit(parser)

    if args.dump:
        scap.show2()

    return ret


def transmit(idx, ifname, args, parser, queue):
    # use nm_open() to open the netmap device and register an interface
    # using an extended interface name
    nmd = netmap.NetmapDesc(ifname)
    time.sleep(args.wait_link)

    # build the packet that will be transmitted
    pkt = build_packet(args, parser)

    # fill in the netmap slots and netmap buffers for tx ring 0
    txr = nmd.transmit_rings[idx]
    num_slots = txr.num_slots
    for i in range(num_slots):
        txr.slots[i].buf[0:len(pkt)] = pkt
        txr.slots[i].len = len(pkt)

    # transmit at maximum speed until Ctr-C is pressed
    cnt = 0         # packet counter
    batch = args.batch
    poller = select.poll()
    poller.register(nmd.getfd(), select.POLLOUT)
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
            nmd.txsync()
            cnt += n
    except KeyboardInterrupt:
        # report the result to the main process
        queue.put([cnt, time.time() - t_start])
        pass


def receive(idx, ifname, args, parser, queue):
    # use nm_open() to open the netmap device and register an interface
    # using an extended interface name
    nmd = netmap.NetmapDesc(ifname)
    time.sleep(args.wait_link)

    # select the right ring
    rxr = nmd.receive_rings[idx]
    num_slots = rxr.num_slots

    cnt = 0         # packet counter
    poller = select.poll()
    poller.register(nmd.getfd(), select.POLLIN)

    # wait for the first packet
    try:
        poller.poll()
    except KeyboardInterrupt:
        # report the result to the main process
        queue.put([cnt, None])
        return

    # receive (throwing away everything) until Ctr-C is pressed
    t_start = time.time()
    try:
        cur = rxr.cur
        while 1:
            ready_list = poller.poll()
            if len(ready_list) == 0:
                print("Timeout occurred")
                break;
            n = rxr.tail - cur  # avail
            if n < 0:
                n += num_slots
            cur += n
            if cur >= num_slots:
                cur -= num_slots
            rxr.cur = rxr.head = cur # lazy update rxr.cur and rxr.head
            cnt += n
    except KeyboardInterrupt:
        # report the result to the main process
        queue.put([cnt, time.time() - t_start])
        pass


############################## MAIN ###########################

if __name__ == '__main__':

    # functions implemented by this program
    handler = dict();
    handler['tx'] = transmit
    handler['rx'] = receive

    # program arguments
    parser = argparse.ArgumentParser(description = 'Send or receive packets using the netmap API')
    parser.add_argument('-i', '--interface', help = 'the interface to register with netmap; '
                        'can be in the form netmap:<OSNAME>[<EXT>] or <VALENAME>[<EXT>], where '
                        'OSNAME is the O.S. name for a network interface (e.g. "eth0"), '
                        '<VALENAME> is a valid VALE port name (e.g. "vale18:2") and <EXT> is an '
                        'optional extension suffix, specified using the nm_open() syntax '
                        '(e.g. "^", "-5", "{44", ...)',
                    required = True)
    parser.add_argument('-f', '--function', help = 'the function to perform',
                    choices = ['tx', 'rx'], default = 'rx')
    parser.add_argument('-b', '--batchsize', help = 'number of packets to send with each TXSYNC '
                    'operation', type=int, default = 512, dest = 'batch')
    parser.add_argument('-l', '--length', help = 'lenght of the ethernet frame sent',
                    type = int, default = 60)
    parser.add_argument('-D', '--dstmac', help = 'destination MAC of tx packets',
                    default = 'ff:ff:ff:ff:ff:ff')
    parser.add_argument('-S', '--srcmac', help = 'source MAC of tx packets',
                    default = '00:00:00:00:00:00')
    parser.add_argument('-d', '--dst', help = 'destination IP address and UDP port of tx packets',
                    default = '10.0.0.2:54322', metavar = 'IP:PORT')
    parser.add_argument('-s', '--src', help = 'source IP address and UDP port of tx packets',
                    default = '10.0.0.1:54321', metavar = 'IP:PORT')
    parser.add_argument('-w', '--wait-link', help = 'time to wait for the link before starting '
                    'transmit/receive operations (in seconds)', type = int, default = 1)
    parser.add_argument('-X', '--dump', help = 'dump the packet', action = 'store_true')
    parser.add_argument('-p', '--threads', help = 'number of threads to used for tx/rx '
                    'operations', type = int, default = 1)
    # parse the input
    args = parser.parse_args()
    # print args

    # bound checking
    if args.length < 60:
        print('Invalid packet length\n')
        help_quit(parser)

    if args.threads < 1:
        print('Invalid number of threads\n')
        help_quit(parser)

    # Temporary open a netmap descriptor to get some info about
    # number of involved rings or the specific ring couple involved
    d = netmap.NetmapDesc(args.interface)
    if d.getflags() in [netmap.RegAllNic, netmap.RegNicSw]:
        max_couples = min(len(d.receive_rings), len(d.transmit_rings))
        if d.getflags() == netmap.RegAllNic:
            max_couples -= 1
        ringid_offset = 0
        suffix_required = True
    else:
        max_couples = 1
        ringid_offset = d.getringid()
        suffix_required = False
    del d

    if args.threads > max_couples:
        print('You cannot use more than %s (tx,rx) rings couples with "%s"' % (max_couples, args.interface))
        quit(1)

    jobs = []    # array of worker processes
    queues = []  # array of queues for IPC
    for i in range(args.threads):
        queue = multiprocessing.Queue()
        queues.append(queue)

        # 'ring_id' contains the ring idx on which the process below will operate
        ring_id = i + ringid_offset
        # it may also be necessary to add an extension suffix to the interface
        # name specified by the user
        ifname = args.interface
        if suffix_required:
            ifname += '-' + str(ring_id)

        print("Run worker #%d on %s, ring_id %d" % (i, ifname, ring_id))

        # create a new process that will execute the user-selected handler function,
        # with the arguments specified by the 'args' tuple
        job = multiprocessing.Process(name = 'worker-' + str(i),
                                        target = handler[args.function],
                                        args = (ring_id, ifname, args, parser, queue))
        job.daemon = True   # ensure work termination
        jobs.append(job)

    # start all the workers
    for i in range(len(jobs)):
        jobs[i].start()

    # Wait for the user pressing Ctrl-C
    try:
        while 1:
            time.sleep(1000)
    except KeyboardInterrupt:
        pass

    # collect and print the result returned by the workers
    tot_rate = 0.0
    for i in range(len(jobs)):
        result = queues[i].get()
        jobs[i].join()
        delta = result[1]
        cnt = result[0]
        if delta == None:
            rate = None
        else:
            rate = 0.001 * cnt / delta
            tot_rate += rate
        print('[%d] Packets processed: %s, Avg rate %s Kpps' % (i, cnt, rate))
    print('Total rate: %s' % (tot_rate, ))
