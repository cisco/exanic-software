ifneq ($(PATCHLEVEL),) # kbuild part of makefile
obj-m := exasock.o
exasock-objs := exasock-main.o exasock-dst.o exasock-ip.o exasock-udp.o exasock-tcp.o exasock-epoll.o exasock-stats.o

ifneq ($(TCP_LISTEN_SOCKET_PROFILING),)
  TCP_LISTEN_SOCKET_PROFILING_DEFINE=-DTCP_LISTEN_SOCKET_PROFILING
endif


# detect kernel features that cannot be reliably detected by version
BONDING_KO_HEADER := $(srctree)/include/net/bonding.h
HAS_RT_GENID_GETTER := ${shell grep -c 'rt_genid(' $(srctree)/include/net/net_namespace.h}
HAS_RT_GENID_GETTER_IPV4 := ${shell grep -c 'rt_genid_ipv4(' $(srctree)/include/net/net_namespace.h}
HAS_SIPHASH := ${shell test -e $(srctree)/include/linux/siphash.h && echo 1 || echo 0}
# Detect whether this kernel can support exasock-bonding
HAS_BONDING_KO_HEADER := ${shell test -e $(BONDING_KO_HEADER) && echo 1 || echo 0}
# Detect whether this is an RHEL with backported SYSFS
HAS_NETDEV_CLASS_CREATE_FILE_NS:=${shell grep -c 'netdev_class_create_file_ns' $(srctree)/include/linux/netdevice.h}
HAS_GENL_POLICY_IN_OPS:=${shell tr '\n' ' ' <$(srctree)/include/net/genetlink.h | grep -co 'struct genl_ops\s*{.*const struct nla_policy\s*\*policy;.*};'}
USE_SOCKPTR_T:=${shell grep -c 'sockptr_t' $(srctree)/include/net/sock.h}

ccflags-y := -D__HAS_RT_GENID_GETTER=$(HAS_RT_GENID_GETTER) -D__HAS_RT_GENID_GETTER_IPV4=$(HAS_RT_GENID_GETTER_IPV4) -D__HAS_SIPHASH=$(HAS_SIPHASH) \
	-D__HAS_BONDING_KO_HEADER=$(HAS_BONDING_KO_HEADER) -D__HAS_NETDEV_CLASS_CREATE_FILE_NS=$(HAS_NETDEV_CLASS_CREATE_FILE_NS) \
	-D__HAS_GENL_POLICY_IN_OPS=$(HAS_GENL_POLICY_IN_OPS) -D__USE_SOCKPTR_T=$(USE_SOCKPTR_T) $(TCP_LISTEN_SOCKET_PROFILING_DEFINE)

NO_PUBLIC_STRUCT_MSG:=NOTE: Exasock-bonding is not supported before Linux 3.19. \
		Upgrade your kernel, or backport the bonding.ko module \
		from a 3.19+ kernel to use exasock-bonding.ko.

# Detect whether or not the headers we're compiling
# against export bonding.h and `struct bonding {}`,
# which are necessary for exasock-bonding to compile.
ifneq ($(wildcard $(BONDING_KO_HEADER)),)
exasock-objs += exasock-bonding-main.o exasock-bonding-sysfs.o \
	exasock-bonding-dev.o exasock-bonding-monitor.o \
	exasock-bonding-rtnl.o
else
$(warning $(NO_PUBLIC_STRUCT_MSG))
endif

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
