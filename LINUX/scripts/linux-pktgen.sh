#!/bin/bash

#set -x


function pgset()
{
    local result

    echo $1 > ${PGDEV}

    result=$(cat $PGDEV | fgrep "Result: OK:")
    if [ "$result" = "" ]; then
        cat $PGDEV | fgrep "Result:"
    fi
}


##################### Script configuration ######################
N="$1"                          # number of TX kthreads minus one
if [ -z "$1" ]; then
    N=0
fi
NCPUS="1"                       # number of CPUs on your machine minus one
IF="ens4"                   # network interface to test
DST_IP="10.216.8.1"             # destination IP address
SRC_MAC="00:00:00:00:00:00"     # source MAC address
DST_MAC="ff:ff:ff:ff:ff:ff"     # destination MAC address
PKT_SIZE="60"                   # packet size
PKT_COUNT="0"            # number of packets to send (0 means an infinite number)
CLONE_SKB="0"               # how many times a sk_buff is recycled (0 means always use the same skbuff)
BURST_LEN="1"		# burst-size (xmit_more skb flag)
XMIT_MODE="start_xmit"       # Transmit mode. start_xmit to put on wire, netif_receive to put into kernel stack


# Load pktgen kernel module
modprobe pktgen || exit 1


# Clean the configuration for all the CPU-kthread (from 0 to ${NCPUS})
IDX=$(seq 0 1 ${NCPUS})
for cpu in ${IDX}; do
    PGDEV="/proc/net/pktgen/kpktgend_${cpu}"
    echo "Removing all devices (${cpu})"
    pgset "rem_device_all"
done

IDX=$(seq 0 1 ${N})
for cpu in ${IDX}; do
    # kthread-device configuration
    PGDEV="/proc/net/pktgen/kpktgend_${cpu}"
    echo "Configuring $PGDEV"
    echo "Adding ${IF}@${cpu}"
    pgset "add_device ${IF}@${cpu}"

    # Packets/mode configuration
    PGDEV="/proc/net/pktgen/${IF}@${cpu}"
    echo "Configuring $PGDEV"
    pgset "count ${PKT_COUNT}"
    pgset "clone_skb ${CLONE_SKB}"
    pgset "pkt_size ${PKT_SIZE}"
    pgset "burst ${BURST_LEN}"
    pgset "delay 0"
    pgset "src_mac $SRC_MAC"
    pgset "dst $DST_IP"
    pgset "dst_mac $DST_MAC"
    pgset "xmit_mode $XMIT_MODE"
    pgset "flag QUEUE_MAP_CPU"

    echo ""
done


# Run
PGDEV="/proc/net/pktgen/pgctrl"
echo "Running... Ctrl-C to stop"
pgset "start"
echo "Done."

# Show results
NUMS=""
for cpu in ${IDX}; do
    TMP=$(cat /proc/net/pktgen/${IF}@${cpu} | grep -o "[0-9]\+pps" | grep -o "[0-9]\+")
    echo "$cpu $TMP"
    NUMS="${NUMS} ${TMP}"
done

echo "Total TX rate: $(echo $NUMS | tr ' ' '+' | bc)"
