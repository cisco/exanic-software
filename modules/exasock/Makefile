ifneq ($(PATCHLEVEL),) # kbuild part of makefile
obj-m := exasock.o
exasock-objs := exasock-main.o exasock-dst.o exasock-ip.o exasock-udp.o exasock-tcp.o exasock-epoll.o exasock-stats.o

# detect kernel features that cannot be reliably detected by version
HAS_RT_GENID_GETTER := ${shell grep -c 'rt_genid(' $(srctree)/include/net/net_namespace.h}
HAS_RT_GENID_GETTER_IPV4 := ${shell grep -c 'rt_genid_ipv4(' $(srctree)/include/net/net_namespace.h}
ccflags-y := -D__HAS_RT_GENID_GETTER=$(HAS_RT_GENID_GETTER) -D__HAS_RT_GENID_GETTER_IPV4=$(HAS_RT_GENID_GETTER_IPV4)

else # normal part makefile

KDIR ?= /lib/modules/`uname -r`/build
KBUILD_EXTRA_SYMBOLS := $(CURDIR)/../exanic/Module.symvers

default:
	$(MAKE) -C $(KDIR) M=$$PWD KBUILD_EXTRA_SYMBOLS=$(KBUILD_EXTRA_SYMBOLS) modules
install:
	$(MAKE) -C $(KDIR) M=$$PWD modules_install
clean:
	$(MAKE) -C $(KDIR) M=$$PWD clean
	rm -f Module.markers Module.symvers

endif
