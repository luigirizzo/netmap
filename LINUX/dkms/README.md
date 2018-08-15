DKMS GUIDE
==========

**Disclaimer**
The dkms build infrastructure is not the official way to build netmap and its
patched drivers.
This alternative build system is not actively maintained, so you may need some
tweaks to make it work on your platform.

Please prefer the standard ./configure && make && make install process to
build netmap.
**************

Some prerequisites:
    # apt-get install dkms linux-source linux-headers-$(uname -r) devscripts


First way is a plain dkms installation:
```
make install-dkms
dkms install netmap/<VERSION>
```

Or make .deb package with sources:
```
make install-dkms
dkms mkdeb netmap/0.0.1 --source-only
```
