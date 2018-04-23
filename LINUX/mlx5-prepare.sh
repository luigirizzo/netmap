#!/bin/sh -x

KSRC=$1
TMPDIR=$2

if [ -e mlx5/config.mk ]; then
	exit 0
fi

if [ -e $TMPDIR/mlx5/config.mk ]; then
	sed "s|^CWD=.*|CWD=$PWD/mlx5|" $TMPDIR/mlx5/config.mk > mlx5/config.mk
	cp -r $TMPDIR/mlx5/compat/* mlx5/compat/
	exit 0
fi

cd mlx5
scripts/mlnx_en_patch.sh --without-mlx4 -s $KSRC -j$(grep -c processor /proc/cpuinfo)
