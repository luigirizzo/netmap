#!/bin/sh

#set -x  # for debugging

if [ -z "$NMSRC" ]; then
    NMSRC=~/netmap-release
fi
DRIVER="ixgbe"
#IF="eth0"  # force an interface

if [ ! -f ${NMSRC}/LINUX/netmap_lin.ko ]; then
    echo "LINUX/netmap_lin.ko missing. Please compile netmap."
    exit 1
fi

if [ ! -f ${NMSRC}/LINUX/${DRIVER}/${DRIVER}.ko ]; then
    echo "LINUX/${DRIVER}/${DRIVER}.ko missing."
    echo "Please compile netmap or make sure to have netmap support for ${DRIVER}"
    exit 1
fi

NMLOADED=$(lsmod | grep netmap_lin | wc -l)
DRVLOADED=$(lsmod | grep "${DRIVER}" | wc -l)

# Unload the driver
if [ $DRVLOADED != "0" ]; then
    sudo rmmod "$DRIVER"
fi

# Load netmap
if [ $NMLOADED == "0" ]; then
    sudo insmod ${NMSRC}/LINUX/netmap_lin.ko
fi

if [ "$1" == "g" ]; then
    # In order to use generic netmap adapter, load the original driver module, that doesn't
    # have netmap support
    sudo modprobe ${DRIVER}
    echo "Generic netmap adapter."
else
    # Use the driver modified with netmap support
    sudo insmod ${NMSRC}/LINUX/${DRIVER}/${DRIVER}.ko
    echo "Native netmap adapter."
fi

# Wait a bit for interface name changing
sleep 2

# Find all interfaces
IFLIST=$(ip link | grep -o "^[0-9]\+: [^:]\+" | awk '{print $2}')
IFLIST=$(echo ${IFLIST})

# Find the interface that match the driver $DRIVER
for i in $IFLIST; do
    drv=$(sudo ethtool -i $i 2> /dev/null | grep "driver" | awk '{print $2}')
    if [ "$drv" == "$DRIVER" ]; then
        IF=$i
        echo "    Found interface \"${IF}\""
    fi
done

if [ "$IF" == "" ]; then
    echo "No interface using ${DRIVER} driver was found."
    exit 1
fi

sudo ip link set ${IF} up

