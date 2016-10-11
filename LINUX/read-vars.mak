include config.mak

%@vars:
	@$(foreach v,$(filter $*@%,$(.VARIABLES)),echo drv_$(patsubst $*@%,%,$(v))=\"$($(v))\";)
