SRC= netmap_osx.c netmap.c
NM_BASE = ../../../../sys
VPATH = .:../../../../sys/dev/netmap
CFLAGS = -static -fno-builtin -nostdlib -lkmod -r -mlong-branch
CFLAGS +=  -I/System/Library/Frameworks/Kernel.framework/Headers
CFLAGS += -I$(NM_BASE) -I. -I$(NM_BASE)/dev/netmap
CFLAGS += -include osx_glue.h
CFLAGS += -Wall
netmap_osx: $(SRC)
