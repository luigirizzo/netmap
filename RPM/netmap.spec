# RPMBUILD file for netmap in NectarCAM
# Dirk Hoffmann -CPPM-, September 2014
# $Id: $
Name:           netmap
Version:        1.0
Release:        1%{?dist}
Summary:        Netmap distribution for NectarCAM
License:        GPL
#URL:            https://portal.cta-observatory.org/WP/MST/...???
#Source0:        http://ftp.gnu.org/gnu/hello/hello-2.8.tar.gz
BuildRoot:      %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)

#BuildRequires:  
Requires:       kernel-x86_64 >= 3.10.0
Requires:       module-init-tools
Requires:       kernel-devel

%description
The netmap driver with adapted network interface drivers e1000e, i40e, igb,
ixgbe, ixgbevf for CentOS/EL/SL 7.1 prepared for Cherenkov Telescope Array
by Julien Houles and Dirk Hoffmann -CPPM-.

%define kmod_dir /lib/modules/%(uname -r)/extra

%prep
#%setup -q
rm -rf $RPM_BUILD_DIR/%{name}
#svn export svn+ssh://svn.in2p3.fr/cta/ACTL/netmap/trunk $RPM_BUILD_DIR/%{name}
git clone https://github.com/luigirizzo/netmap.git


%build
./configure
make %{?_smp_mflags}
#(cd %{name}/netmap/LINUX; make %{?_smp_mflags})
#(cd %{name}/netmap/examples; make %{?_smp_mflags})


%install
rm -rf $RPM_BUILD_ROOT
make install DESTDIR=$RPM_BUILD_ROOT
#mkdir -p $RPM_BUILD_ROOT/%{_bindir}
#install --mode=0755 %{name}/netmap/examples/pkt-gen $RPM_BUILD_ROOT/%{_bindir}
#mkdir -p $RPM_BUILD_ROOT/%{kmod_dir}
#install --mode=0644 `find %{name}/netmap/LINUX -name \*.ko` \
#	$RPM_BUILD_ROOT/%{kmod_dir}
#mkdir -p $RPM_BUILD_ROOT/%{_mandir}/man4
#install --mode=0644 %{name}/netmap/share/man/man4/* \
#	$RPM_BUILD_ROOT/%{_mandir}/man4
#gzip -9 %{name}/netmap/share/man/man4/*


%post
depmod
modprobe -r ixgbe
modprobe ixgbe


%postun
depmod
modprobe -r ixgbe
modprobe ixgbe


%clean
rm -rf $RPM_BUILD_ROOT


%files
%defattr(-,root,root,-)
%doc
%{kmod_dir}/*.ko
%{_mandir}/*/*.gz
%attr(4755,root,root) %{_bindir}/*


%changelog
* Tue Mar 14 2016 Dirk Hoffmann -CPPM-
 - Adapted to the "git-way of netmap distribution"
* Mon Sep 15 2014 Dirk Hoffmann -CPPM-
 - Binary is now suid'd
 - Requiring kernel 3.16.2
* Wed Sep 10 2014 Dirk Hoffmann -CPPM-
 - Initial version of the package
