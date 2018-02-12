all:

-include netmap.mak

COMPAT_ARGS=$(if $(KSRC),--kernel-dir=$(KSRC),)\
	    $(if $(SRC),--kernel-sources=$(SRC),)\
	    $(if $(NODRIVERS),--no-drivers)


netmap.mak:
	@echo 'The new way to build netmap is to run the provided configure script first,'
	@echo 'followed by make.'
ifneq ($(MAKECMDGOALS),clean)
ifneq ($(MAKECMDGOALS),distclean)
	@echo 'We run configure for you now, with compatible arguments, and restart make.'
	@echo 'Please run configure again if this is not what you want.'
	./configure $(COMPAT_ARGS)
endif
endif
