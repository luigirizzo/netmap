-include config.mak
-include drivers.mak

%@vars: FORCE
	$(foreach v,$(filter $*@%,$(.VARIABLES)),echo drv_$(patsubst $*@%,%,$(v))='"$(subst ",\",$($(v)))"';)true

FORCE:
