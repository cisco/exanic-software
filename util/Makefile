PREFIX=/usr/local
BINDIR=$(DESTDIR)$(PREFIX)/bin

CC=gcc
CFLAGS=-O3 -Wall -I../libs
LDLIBS=-L../libs/exanic -lexanic

HAVE_PTP_CLOCK_H:=${shell $(CC) $(CFLAGS) -include linux/ptp_clock.h -E -x c /dev/null >/dev/null 2>&1 && echo 1 || echo 0}
CONFIG_CFLAGS=-DHAVE_PTP_CLOCK_H=$(HAVE_PTP_CLOCK_H)

CFLAGS_LIBNL3:=${shell pkg-config --cflags libnl-3.0}
LDLIBS_LIBNL3=${shell pkg-config --libs libnl-3.0 libnl-genl-3.0}
EXASOCK_STAT_CFLAGS=-O3 -Wall -I../modules $(CFLAGS_LIBNL3)
EXASOCK_STAT_LDLIBS=$(LDLIBS_LIBNL3)

BIN=exanic-config exanic-capture exanic-clock-sync exanic-clock-check exanic-fwupdate
EXASOCK_STAT_BIN=exasock-stat

all: $(BIN) $(EXASOCK_STAT_BIN)

exanic-fwupdate: exanic-fwupdate.c
	$(CC) $(CFLAGS) $^ -o $@ $(LDLIBS)

exanic-config: exanic-config.c
	$(CC) $(CFLAGS) $(CONFIG_CFLAGS) $^ -o $@ $(LDLIBS) -lm -lrt

exanic-capture: exanic-capture.c
	$(CC) $(CFLAGS) $^ -o $@ $(LDLIBS) -lrt

exanic-clock-sync: exanic-clock-sync.c clock-sync/common.c clock-sync/phc_sys.c clock-sync/exanic_pps.c clock-sync/phc_phc.c clock-sync/sys_phc.c
	$(CC) $(CFLAGS) $(CONFIG_CFLAGS) $^ -o $@ $(LDLIBS) -lrt

exanic-clock-check: exanic-clock-check.c
	$(CC) $(CFLAGS) $^ -o $@ $(LDLIBS)

exasock-stat: exasock-stat.c
ifneq ($(CFLAGS_LIBNL3),)
	$(CC) $(EXASOCK_STAT_CFLAGS) $^ -o $@ $(EXASOCK_STAT_LDLIBS)
else
ifeq (${shell pkg-config --version},)
	$(info WARNING: Building of exasock-stat tool has been skipped (exasock-stat requires package pkg-config).)
else ifneq (${wildcard /etc/debian_version},)
	$(info WARNING: Building of exasock-stat tool has been skipped (exasock-stat requires package libnl-3-dev).)
else
	$(info WARNING: Building of exasock-stat tool has been skipped (exasock-stat requires package libnl3-devel).)
endif
	$(info ${shell echo "         If exasock-stat is needed, please install the required package and rebuild."})
endif

install: all
	rm -f $(BINDIR)/exanic-rx-raw # clean up old utility
	rm -f $(BINDIR)/exanic-prom-util # clean up old utility
	install -d $(BINDIR)
	install -m 0755 -D $(BIN) $(BINDIR)
ifneq ($(CFLAGS_LIBNL3),)
	install -m 0755 -D $(EXASOCK_STAT_BIN) $(BINDIR)
endif

uninstall:
	rm -f $(foreach file,$(BIN) $(EXASOCK_STAT_BIN),$(BINDIR)/$(file))

clean:
	rm -f $(BIN) $(EXASOCK_STAT_BIN)
