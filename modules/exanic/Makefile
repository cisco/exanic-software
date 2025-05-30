ifneq ($(PATCHLEVEL),) # kbuild part of makefile
obj-m := exanic.o
exanic-objs := exanic-main.o exanic-filter.o exanic-ctx.o exanic-dev.o exanic-netdev.o exanic-ptp.o exanic-ate.o \
			   exanic-i2c.o exanic-sysfs.o exanic-phyops.o exanic-phyops-cmis.o

# detect kernel features that cannot be reliably detected by version
RH_ETHTOOL_OPS_EXT := ${shell egrep -c 'ethtool_ops_ext\b' $(srctree)/include/linux/ethtool.h}
HAS_NETDEVICE_DEV_PORT := ${shell grep -c 'dev_port' $(srctree)/include/linux/netdevice.h}
USE_RH_NETDEV_CHANGE_MTU := ${shell grep -c 'RH_KABI_RENAME.*ndo_change_mtu' $(srctree)/include/linux/netdevice.h}
HAS_KERNEL_ETHTOOL_COALESCE_STRUCT := ${shell egrep -c '^struct kernel_ethtool_coalesce' $(srctree)/include/linux/ethtool.h}
HAS_KERNEL_NDO_ETH_IOCTL := ${shell egrep -c "^\s*int\s*\(\*ndo_eth_ioctl\)" $(srctree)/include/linux/netdevice.h}
HAS_NAPI_WEIGHT_PARAM := ${shell grep -A 2 "netif_napi_add(" $(srctree)/include/linux/netdevice.h  | grep -c "int weight)" }
HAS_NAPI_RESCHEDULE := ${shell grep -c 'napi_reschedule' $(srctree)/include/linux/netdevice.h}
HAS_PCI_ERR_REPORTING := ${shell grep -c 'pci_enable_pcie_error_reporting' $(srctree)/include/linux/aer.h}
HAS_STRLCPY := ${shell grep -c 'strlcpy' $(srctree)/include/linux/string.h}
HAS_FLUSH_WQ_WARN := ${shell grep -c '__warn_flushing_systemwide_wq' $(srctree)/include/linux/workqueue.h}
HAS_PTP_CLOCK_ADJFREQ := ${shell grep -c 'adjfreq' $(srctree)/include/linux/ptp_clock_kernel.h}
HAS_GFP_TYPES_H := ${shell test -e $(srctree)/include/linux/gfp_types.h && echo 1 || echo 0}

ccflags-y := -D__HAS_NETDEVICE_DEV_PORT=$(HAS_NETDEVICE_DEV_PORT) -D__USE_RH_NETDEV_CHANGE_MTU=$(USE_RH_NETDEV_CHANGE_MTU) -D__RH_ETHTOOL_OPS_EXT=$(RH_ETHTOOL_OPS_EXT) -D__HAS_KERNEL_ETHTOOL_COALESCE=$(HAS_KERNEL_ETHTOOL_COALESCE_STRUCT) -D__HAS_KERNEL_NDO_ETH_IOCTL=$(HAS_KERNEL_NDO_ETH_IOCTL) -D__HAS_NAPI_WEIGHT_PARAM=$(HAS_NAPI_WEIGHT_PARAM) -D__HAS_NAPI_RESCHEDULE=$(HAS_NAPI_RESCHEDULE) -D__HAS_PCI_ERR_REPORTING=$(HAS_PCI_ERR_REPORTING) -D__HAS_STRLCPY=$(HAS_STRLCPY) -D__HAS_FLUSH_WQ_WARN=$(HAS_FLUSH_WQ_WARN) -D__HAS_PTP_CLOCK_ADJFREQ=$(HAS_PTP_CLOCK_ADJFREQ) -D__HAS_GFP_TYPES_H=$(HAS_GFP_TYPES_H) -fstack-protector-strong -Wformat -Wformat-security

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
