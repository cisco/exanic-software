PREFIX=/usr/local

all: modules bin
install: install-modules install-bin
uninstall: uninstall-modules uninstall-bin
clean: clean-modules clean-bin

modules:
	make -C modules/exanic
	make -C modules/exasock

install-modules:
	make -C modules/exanic install
	make -C modules/exasock install
	-[ -n "$(INSTALL_MOD_PATH)" ] || depmod -a

uninstall-modules:
	rm -f /lib/modules/`uname -r`/extra/exanic.ko
	rm -f /lib/modules/`uname -r`/extra/exasock.ko

clean-modules:
	make -C modules/exanic clean
	make -C modules/exasock clean

bin:
	make -C libs/exanic
	make -C libs/exasock
	make -C util

install-bin:
	make -C libs/exanic install PREFIX=$(PREFIX)
	make -C libs/exasock install PREFIX=$(PREFIX)
	make -C util install PREFIX=$(PREFIX)
	make -C scripts install PREFIX=$(PREFIX)

uninstall-bin:
	make -C libs/exanic uninstall PREFIX=$(PREFIX)
	make -C libs/exasock uninstall PREFIX=$(PREFIX)
	make -C util uninstall PREFIX=$(PREFIX)
	make -C scripts uninstall PREFIX=$(PREFIX)

clean-bin: # make bin wheelie clean
	make -C libs/exanic clean
	make -C libs/exasock clean
	make -C util clean
	make -C perf-test clean
	make -C examples/devkit clean
	make -C examples/exanic clean
	make -C examples/exasock clean
	make -C examples/filters clean

.PHONY: all install uninstall clean \
        modules install-modules uninstall-modules clean-modules \
        bin install-bin uninstall-bin clean-bin

