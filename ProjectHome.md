**NOTE: On aug.28, 2014 there will be a netmap tutorial at Hot Interconnects, Mountain View. See  http://www.hoti.org/hoti22/tutorials/#tut4 for more information.**


---


This repository contains kernel source code (FreeBSD and Linux) and some example applications for the **netmap** framework, the **VALE** software switch and **netmap pipes**.
netmap/VALE permit extremely high speed network I/O from user space: one core is enough for 14.88 Mpps on a 10Gbit/s ethernet; over 20 Mpps or 70 Gbit/s for the VALE software switch; over 100 Mpps for netmap pipes.

See http://info.iet.unipi.it/~luigi/netmap for more details.

Other related repositories of interest (in all cases we track the original repositories and will try to upstream our changes):
  * https://code.google.com/p/netmap-libpcap  a netmap-enabled version of libpcap from https://github.com/the-tcpdump-group/libpcap.git . With this, basically any pcap client can read/write traffic at 10+ Mpps, with zerocopy reads and (soon) support for  zerocopy writes
  * https://code.google.com/p/netmap-click a netmap-enabled version of the Click Modular Router from git://github.com/kohler/click.git . This version matches the current version of netmap, supporting all features (including netmap pipes)
  * https://code.google.com/p/netmap-ipfw a netmap-enabled, userspace version of the ipfw firewall and  [dummynet](http://info.iet.unipi.it/~luigi/dummynet/) network emulator. This version reaches 7-10 Mpps for filtering and over 2.5 Mpps for emulation.
  * https://code.google.com/p/netmap/ this repository (for cut&paste convenience).

[Related publications](http://info.iet.unipi.it/~luigi/research.html)

  * Luigi Rizzo, Giuseppe Lettieri, Vincenzo Maffione, **Speeding up packet I/O in virtual machines,** IEEE/ACM ANCS 2013, San Jose, Oct 2013
  * Luigi Rizzo, Giuseppe Lettieri, **VALE: a switched ethernet for virtual machines,** ACM CoNEXT'2012, Nice, France
  * Luigi Rizzo, **netmap: a novel framework for fast packet I/O,** Usenix ATC'12, Boston, June 2012
  * Luigi Rizzo, **Revisiting network I/O APIs: the netmap framework,** Communications of the ACM 55 (3), 45-51, March 2012 (a version of this paper appears on ACM Queue)



