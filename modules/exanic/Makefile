ifneq ($(PATCHLEVEL),) # kbuild part of makefile
obj-m := exanic.o
exanic-objs := exanic-main.o exanic-filter.o exanic-ctx.o exanic-dev.o exanic-netdev.o exanic-ptp.o exanic-ate.o exanic-i2c.o exanic-z10.o

# detect kernel features that cannot be reliably detected by version
HAS_NETDEVICE_DEV_PORT := ${shell grep -c 'dev_port' $(srctree)/include/linux/netdevice.h}
USE_RH_NETDEV_CHANGE_MTU := ${shell grep -c 'RH_KABI_RENAME.*ndo_change_mtu' $(srctree)/include/linux/netdevice.h}
ccflags-y := -D__HAS_NETDEVICE_DEV_PORT=$(HAS_NETDEVICE_DEV_PORT) -D__USE_RH_NETDEV_CHANGE_MTU=$(USE_RH_NETDEV_CHANGE_MTU)

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
