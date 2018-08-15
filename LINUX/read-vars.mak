-include extdrv-versions.mak
-include default-config.mak
-include config.mak
-include drivers.mak

%@vars: FORCE
	$(foreach v,$(filter $*@%,$(.VARIABLES)),drv_$(patsubst $*@%,%,$(v))='$($(v))';)true

FORCE:
