# RPMBUILD file for netmap in NectarCAM
# Dirk Hoffmann -CPPM-, 2014-2018
Name:           netmap
Version:        11.4
Release:        1%{?dist}
Summary:        Netmap distribution for CTA-North EVB
License:        GPL
#URL:            https://portal.cta-observatory.org/WP/MST/...???
#Source0:        http://ftp.gnu.org/gnu/hello/hello-2.8.tar.gz
BuildRoot:      %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)

BuildRequires:  linuxptp
BuildRequires:  kernel-devel
Requires:       kernel-x86_64 = 3.10.0-693.17.1
Requires:       module-init-tools
Requires:       kernel-devel

%description
The netmap driver with adapted network interface drivers e1000e, i40e, igb,
ixgbe, ixgbevf for CentOS/EL/SL 7 prepared for Cherenkov Telescope Array
by Julien Houles and Dirk Hoffmann -CPPM-.

%define kver     %(uname -r)
%define kmod_dir /lib/modules/%{kver}

%prep
#%setup -q
rm -rf %{name}
#git clone https://github.com/luigirizzo/netmap.git
git clone https://github.com/DirkHoffmann/netmap.git --branch rpm


%build
cd %{name}
./configure --install-mod-path=%{buildroot} --prefix=%{buildroot}/usr
make %{?_smp_mflags}


%install
rm -rf %{buildroot}
cd %{name}
make install 


%post
depmod
modprobe -r ixgbe
modprobe ixgbe


%postun
depmod
modprobe -r ixgbe
modprobe ixgbe


%clean
rm -rf %{buildroot}


%files
%defattr(-,root,root,-)
%doc
%{kmod_dir}/extra
%{kmod_dir}/updates
%{_mandir}/*/*.gz
%attr(4755,root,root) %{_bindir}/*
%{_includedir}/net/*.h
%exclude %{kmod_dir}/modules.*

%changelog
* Fri Jul 27 2018 Dirk Hoffmann <hoffmann@cppm.in2p3.fr> - 11.4
- Bumping to the official netmap version (tag) number
- One (tiny) step back in kernel release number
* Mon Feb 12 2018 Dirk Hoffmann <hoffmann@cppm.in2p3.fr> - 2.0
- Pulled latest version from github
- Adapted to CentOS 7.4
* Mon Mar 14 2016 Dirk Hoffmann <hoffmann@cppm.in2p3.fr> 
- Adapted to the "git-way of netmap distribution"
* Mon Sep 15 2014 Dirk Hoffmann <hoffmann@cppm.in2p3.fr>
- Binary is now suid'd
- Requiring kernel 3.16.2
* Wed Sep 10 2014 Dirk Hoffmann <hoffmann@cppm.in2p3.fr> - 1.0
- Initial version of the package

