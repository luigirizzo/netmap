#!/bin/sh
#
# commands to sync the files in netmap
# sh ... --netmap netmap_tree --src bsd_tree [diff|patch|revert]

# MYFILES is the list of kernel files modified
FREEBSD_TREE=${HOME}/FreeBSD/head
NETMAP_TREE=/usr/ports-luigi/netmap-release
MY_FILES="\
	conf/NOTES conf/files conf/options \
	dev/e1000/if_igb.c dev/e1000/if_lem.c dev/e1000/if_em.c \
	dev/re/if_re.c \
	dev/bge/if_bge.c \
	dev/ixgbe/ixgbe.c \
	"

while [ true ] ; do
    case $1 in
    --netmap)	# netmap tree
	NETMAP_TREE=$2;
	shift
	;;
    --src)	# FreeBSD tree
	FREEBSD_TREE=$2
	shift
	;;
    --dry)	# dry run
	DRY=-C
	;;
    --h*)	# help
	echo "sh ... --netmap netmap_tree --src bsd_tree [diff|patch|revert] "
	exit 0
	;;

    diff)	# compute diffs
	(cd $FREEBSD_TREE/sys; svn diff $MY_FILES)
	;;
    revert)	# remove additional files
	(cd $FREEBSD_TREE/sys; svn revert $MY_FILES; \
		rm dev/netmap; rm net/netmap*)
	;;
    patch)	# compute diffs
	in=$2
	[ x"$in" = x ] && in=$NETMAP_TREE/head-netmap.diff
	(cd $FREEBSD_TREE/sys; patch ${DRY} < $in ; \
	    ln -s $NETMAP_TREE/sys/dev/netmap dev/netmap; \
	    ln -s $NETMAP_TREE/sys/net/netmap.h net/netmap.h; \
	    ln -s $NETMAP_TREE/sys/net/netmap_user.h net/netmap_user.h; \
	)
	;;
    *)
	break;
    esac
    shift;
done
