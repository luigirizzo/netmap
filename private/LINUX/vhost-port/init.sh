#!/bin/sh

set -x

sudo modprobe tun
sudo modprobe macvtap

sudo ip tuntap add mode tap name tap1
sudo ip tuntap add mode tap name tap2
sudo ip link set tap1 up
sudo ip link set tap2 up
sudo brctl addbr br1
sudo brctl addif br1 tap1
sudo brctl addif br1 tap2
sudo ip link set br1 up
sudo ip addr add 10.1.1.200/24 dev br1

sudo arp -s "10.1.1.1" "00:aa:bb:cc:de:1"
sudo arp -s "10.1.1.2" "00:aa:bb:cc:de:2"

cp test.c .test.c
BR0MAC=$(ip link | tail -1 | awk '{print $2}')
sed -i "s|BR0MAC|${BR0MAC}|" test.c
make "test"


sudo insmod v1000_net.ko
sudo chmod a+rw /dev/v1000

