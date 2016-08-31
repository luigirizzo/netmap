DKMS GUIDE
==========

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
