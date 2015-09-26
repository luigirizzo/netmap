import netmap


# see 'help(netmap)' for documentation
n = netmap.Netmap()
print n
n.open()
n.if_name = 'enp1s0f1'
n.ringid = netmap.HwRing | 3
n.arg3 = 2
n.register()
print n
print n.interface
n.close()
