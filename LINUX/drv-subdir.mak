ifdef NETMAP_DRIVER_SUFFIX
save-obj-m := $(obj-m)

include $(src)/orig.mak

driver-name := $(patsubst %.o,%,$(filter-out $(save-obj-m),$(obj-m)))

$(info driver-name = $(driver-name))

obj-m = $(save-obj-m) $(driver-name)$(NETMAP_DRIVER_SUFFIX).o

$(driver-name)$(NETMAP_DRIVER_SUFFIX)-objs := $($(driver-name)-objs)
$(info $(driver-name)$(NETMAP_DRIVER_SUFFIX)-objs = $($(driver-name)-objs))
$(driver-name)$(NETMAP_DRIVER_SUFFIX)-y := $($(driver-name)-y)
$(info $(driver-name)$(NETMAP_DRIVER_SUFFIX)-y = $($(driver-name)-y))
else
include $(src)/orig.mak
endif
