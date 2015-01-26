#!/bin/bash

set -x

sudo rmmod v1000_net.ko
#sudo rm /dev/v1000

mv .test.c test.c

sudo arp -d "10.1.1.1"
sudo arp -d "10.1.1.2"

sudo ip link set br1 down
sudo brctl delbr br1
sudo ip link set tap1 up
sudo ip link set tap2 up
sudo ip tuntap del mode tap name tap1
sudo ip tuntap del mode tap name tap2
