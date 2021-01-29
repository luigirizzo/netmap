#!/bin/sh -x

KSRC=$1

if [ -e mlx5/config.mk ]; then
	exit 0
fi

cd mlx5
scripts/mlnx_en_patch.sh -s $KSRC -j$(grep -c processor /proc/cpuinfo)
