mod_ezclustered_image.la: mod_ezclustered_image.slo
	$(SH_LINK) -rpath $(libexecdir) -module -avoid-version  mod_ezclustered_image.lo
DISTCLEAN_TARGETS = modules.mk
shared =  mod_ezclustered_image.la
