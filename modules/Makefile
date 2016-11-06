ifneq ($(PATCHLEVEL),) # kbuild part of makefile
obj-y := exanic/ exasock/

else # normal part makefile

KDIR ?= /lib/modules/`uname -r`/build

default:
	$(MAKE) -C $(KDIR) M=$$PWD modules
install:
	$(MAKE) -C $(KDIR) M=$$PWD modules_install
clean:
	$(MAKE) -C $(KDIR) M=$$PWD clean
	rm -f Module.markers Module.symvers

endif
