PREFIX=/usr/local
BINDIR=$(DESTDIR)$(PREFIX)/bin

CC=gcc
CFLAGS=-O3 -Wall -I../libs
LDLIBS=-L../libs/exanic -lexanic

HAVE_PTP_CLOCK_H:=${shell $(CC) $(CFLAGS) -include linux/ptp_clock.h -E -x c /dev/null >/dev/null 2>&1 && echo 1 || echo 0}
CONFIG_CFLAGS=-DHAVE_PTP_CLOCK_H=$(HAVE_PTP_CLOCK_H)

BIN=exanic-config exanic-capture exanic-clock-sync exanic-clock-check exanic-fwupdate 

all: $(BIN)
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

install: all
	rm -f $(BINDIR)/exanic-rx-raw # clean up old utility
	rm -f $(BINDIR)/exanic-prom-util # clean up old utility
	install -d $(BINDIR)
	install -m 0755 -D $(BIN) $(BINDIR)

uninstall:
	rm -f $(foreach file,$(BIN),$(BINDIR)/$(file))

clean:
	rm -f $(BIN)
