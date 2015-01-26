#ifndef _NETMAP_TEST_DEVICE_H
#define _NETMAP_TEST_DEVICE_H

#include <sys/types.h>


int netmap_open(void);
void netmap_close(int fd);
void netmap_ioctl(int fd, u_long cmd, caddr_t data);
void *netmap_mmap(int fd, int l);

#endif  /* _NETMAP_TEST_DEVICE_H */
