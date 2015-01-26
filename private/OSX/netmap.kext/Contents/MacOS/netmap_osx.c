/*
 * OSX wrapper for netmap module
 */
#include <libkern/libkern.h>
#include <mach/mach_types.h>

kern_return_t netmap_kext_Start(kmod_info_t *ki, void *d) {
  printf("Hello, World!\n");
  return KERN_SUCCESS;
}

kern_return_t netmap_kext_Stop(kmod_info_t *ki, void *d) {
  printf("Goodbye, World!\n");
  return KERN_SUCCESS;
}

extern kern_return_t _start(kmod_info_t *ki, void *data);
extern kern_return_t _stop(kmod_info_t *ki, void *data);

KMOD_EXPLICIT_DECL(it.unipi.iet.netmap_osx, "1.0.0", _start, _stop)
__private_extern__ kmod_start_func_t *_realmain = netmap_kext_Start;
__private_extern__ kmod_stop_func_t *_antimain = netmap_kext_Stop;
__private_extern__ int _kext_apple_cc = __APPLE_CC__;
