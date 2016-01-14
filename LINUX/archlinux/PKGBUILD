# See http://wiki.archlinux.org/index.php/VCS_PKGBUILD_Guidelines
# for more information on packaging from GIT sources.

# Maintainer: Vincenzo Maffione <v.maffione@gmail.com>
pkgname=netmap
pkgver=r1324.519c07f
pkgrel=1
pkgdesc="Netmap is a framework for high speed network packet I/O."
arch=('any')
url="http://info.iet.unipi.it/~luigi/netmap"
license=('BSD')
groups=()
depends=('linux' 'glibc')
makedepends=('git' 'sed' 'gzip' 'linux-headers' 'abs' 'pacman' 'xmlto' 'docbook-xsl')
provides=()
conflicts=()
replaces=()
backup=()
options=()
install="netmap.install"
source=("netmap.install" "git+https://github.com/luigirizzo/netmap")
noextract=()
md5sums=("9f936e9fdd86c8a18babdc5848812f92" "SKIP")

pkgver() {
        cd "$srcdir/${pkgname%-git}"
        printf "r%s.%s" "$(git rev-list --count HEAD)" "$(git rev-parse --short HEAD)"
}

build() {
    msg "Downloading kernel sources..."
    # Download kernel sources using ABS, checking that the version is the
    # same as the running kernel
    mkdir -p $srcdir/abs
    cd $srcdir/abs
    ABSROOT=. abs core/linux
    NESTEDDIR="$srcdir/abs/core/linux"
    cd $NESTEDDIR
    grep "pkgver[ ]*=" PKGBUILD > .ksver
    KSVER=$(sed 's|pkgver[ ]*=[ ]*||g' .ksver)
    rm .ksver
    RKVER=$(uname -r | sed 's|-.*||g')
    if [ "$KSVER" != "$RKVER" ]; then
        msg "Kernel sources version ($KSVER) differs from running kernel version ($RKVER): Cannot continue"
        return 1
    fi
    KMAJVER=$(echo "$KSVER" | sed 's|\.[0-9]\+$||g')

    echo "SRCDEST=$SRCDEST"
    echo "SRCPKGDEST=$SRCPKGDEST"
    echo "PKGDEST=$PKGDEST"
    echo "BUILDDIR=$BUILDDIR"
    # We force some makepkg variables, trying to ovverride yaourt default behaviour,
    # which is to download sources in $srcdir/../linux instead of the place where
    # makepkg is invoked
    SRCDEST=$NESTEDDIR SRCPKGDEST=$NESTEDDIR PKGDEST=$NESTEDDIR BUILDDIR=$NESTEDDIR \
                                        makepkg --nobuild --skippgpcheck
    msg "Kernel sources are ready"

    # Build the netmap kernel module and all modified drivers, using the
    # kernel sources downloaded in the previous steps to copy the NIC
    # drivers. Note however that the kernel modules are built against the
    # running kernel, and not against the downloaded sources.
    msg "Starting to build netmap"
    cd "$srcdir/netmap/LINUX"
    ./configure --kernel-sources=$NESTEDDIR/src/linux-$KMAJVER
    make || return 1
    # Build pkt-gen and vale-ctl
    cd "$srcdir/netmap/examples"
    make clean  # amend for existing .o
    make pkt-gen vale-ctl || return 1
    msg "Build complete"
}

package() {
    # Compute the version numbers of the running kernel
    KVER1=$(uname -r)
    KVER2=$(uname -r | sed 's/\.[0-9]\+-[0-9]\+//')

    # Install the netmap module into the extramodules-VERSION directory
    mkdir -p "$pkgdir/usr/lib/modules/extramodules-${KVER2}"
    cp "$srcdir/netmap/LINUX/netmap.ko" "$pkgdir/usr/lib/modules/extramodules-${KVER2}"

    # Install pkt-gen and valectl into /usr/bin
    mkdir -p "$pkgdir/usr/bin"
    cp "$srcdir/netmap/examples/pkt-gen" "$pkgdir/usr/bin"
    cp "$srcdir/netmap/examples/vale-ctl" "$pkgdir/usr/bin"

    # Install the netmap public headers
    mkdir -p "$pkgdir/usr/include/net"
    cp "$srcdir/netmap/sys/net/netmap.h" "$srcdir/netmap/sys/net/netmap_user.h" "$pkgdir/usr/include/net"

    # Install the netmap man page
    mkdir -p "$pkgdir/usr/share/man/man4"
    cp "$srcdir/netmap/share/man/man4/netmap.4" "$pkgdir/usr/share/man/man4"
    gzip "$pkgdir/usr/share/man/man4/netmap.4"

    #Find and install the modified NIC drivers
    cd "$srcdir/netmap/LINUX"
    DRIVERS=$(find . -name "*.ko" -and ! -name "netmap.ko")
    if [ -n "$DRIVERS" ]; then
        mkdir -p "$pkgdir/usr/lib/modules/extramodules-${KVER2}/netmap-drivers"
        cp --parent $DRIVERS "$pkgdir/usr/lib/modules/extramodules-${KVER2}/netmap-drivers"
        cd "$pkgdir/usr/lib/modules/extramodules-${KVER2}/netmap-drivers"
        find . -name "*.ko" -exec sh -c "mv {} \$(echo {} | sed 's|\.ko|_netmap\.ko|g')" \;
    fi
}

# vim:set ts=2 sw=2 et:
