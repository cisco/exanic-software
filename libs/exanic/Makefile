PREFIX=/usr/local
INCDIR=$(DESTDIR)$(PREFIX)/include
LIBDIR=$(DESTDIR)$(PREFIX)/lib
DEVLIBDIR=$(LIBDIR)

CC=gcc
CFLAGS=-Wall -O3 -fPIC -D_FILE_OFFSET_BITS=64

LIB=libexanic.a
INCLUDES=config.h fifo_rx.h fifo_tx.h port.h sfp.h time.h util.h filter.h firewall.h exanic.h register.h pcie_if.h fifo_if.h ioctl.h const.h
LIBOBJS=config.o fifo_rx.o fifo_tx.o port.o sfp.o time.o util.o filter.o firewall.o exanic.o z1/i2c.o z1/port.o z10/i2c.o z10/zpu.o x4/i2c.o filter/rules.o filter/parser.o

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
