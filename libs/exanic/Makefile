PREFIX=/usr/local
INCDIR=$(DESTDIR)$(PREFIX)/include
LIBDIR=$(DESTDIR)$(PREFIX)/lib
DEVLIBDIR=$(LIBDIR)

CC=gcc
CFLAGS=-O3 -Wall -std=gnu99 -fPIC -D_FILE_OFFSET_BITS=64 -fstack-protector-strong -D_FORTIFY_SOURCE=2

LIB=libexanic.a
INCLUDES=config.h fifo_rx.h fifo_tx.h port.h time.h util.h filter.h firewall.h exanic.h register.h pcie_if.h fifo_if.h ioctl.h const.h hw_info.h
LIBOBJS=config.o fifo_rx.o fifo_tx.o port.o time.o util.o filter.o firewall.o exanic.o filter/rules.o filter/parser.o transceiver.o eeprom.o

all: $(LIB)

$(LIB): $(LIBOBJS)
	ar rcs $@ $^

install: all
	install -d $(DEVLIBDIR) $(INCDIR)/exanic
	install -m 0644 -D $(LIB) $(DEVLIBDIR)
	install -m 0644 -D $(INCLUDES) $(INCDIR)/exanic

uninstall:
	rm -f $(DEVLIBDIR)/$(LIB)
	rm -f $(INCDIR)/exanic/*
	-rmdir $(INCDIR)/exanic

clean:
	rm -f $(LIB) $(LIBOBJS)
	rm -rf docs

docs: $(INCLUDES)
	doxygen
