# $Id$
# targets to build tarballs and diffs

# build a distribution

RELEASE_SRCS := ./sys/net ./sys/dev ./sys/modules ./examples
RELEASE_SRCS += ./README* ./LINUX ./OSX
RELEASE_EXCL := --exclude .svn --exclude examples/testmod
RELEASE_EXCL += --exclude connlib\*
RELEASE_EXCL += --exclude if_epair.diff
#RELEASE_EXCL += --exclude \*-patches
RELEASE_EXCL += --exclude \*bnx2x\* --exclude \*mellanox\* --exclude \*mlx4\*
RELEASE_EXCL += --exclude OSX

all:
	@echo "What do you want to do ?"


diff-head:
	(cd ~/FreeBSD/head ; \
	svn diff sys/conf sys/dev sbin/ifconfig ) > head-netmap.diff

# XXX remember to patch sbin/ifconfig if not done yet
diff-r8:
	(cd ~/FreeBSD/RELENG_8 ; \
	svn diff sys/conf sys/dev sbin/ifconfig ) > r8-netmap.diff

release:
	D=`date +%Y%m%d` && tar cvzf /tmp/$${D}-netmap.tgz \
		-s'/^./netmap-release/' $(RELEASE_EXCL) $(RELEASE_SRCS)
