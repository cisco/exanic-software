PREFIX=/usr/local
INCDIR=$(DESTDIR)$(PREFIX)/include
LIBDIR=$(DESTDIR)$(PREFIX)/lib
DEVLIBDIR=$(LIBDIR)

CFLAGS=-fPIC -Wall -std=c99 -fvisibility=hidden -I.. -Iinclude
DEBUG_CFLAGS=-g
RELEASE_CFLAGS=-O3 -DNDEBUG
CC=gcc
LDFLAGS=-shared
LDLIBS=-ldl -lrt -lexanic -L../exanic

CORE_SRCS=structs.c udp.c tcp.c exanic.c sockets.c notify.c sys.c
SOCK_SRCS=socket/override.c socket/trace.c socket/socket.c socket/recv.c socket/send.c socket/select.c socket/signal.c socket/epoll.c
EXT_SRCS=extensions/tcp.c

PRELOAD_SRCS=$(CORE_SRCS) $(SOCK_SRCS) $(EXT_SRCS)

EXT_STUB_SRCS=extensions/stub.c

EXT_INCLUDES=include/exasock/extensions.h

DEBUG_PRELOAD_LIB=build/libexasock_preload_debug.so
RELEASE_PRELOAD_LIB=build/libexasock_preload.so

DEBUG_PRELOAD_OBJDIR=build/debug/preload
RELEASE_PRELOAD_OBJDIR=build/release/preload

DEBUG_PRELOAD_LIBOBJS=$(addprefix $(DEBUG_PRELOAD_OBJDIR)/,$(PRELOAD_SRCS:.c=.o))
RELEASE_PRELOAD_LIBOBJS=$(addprefix $(RELEASE_PRELOAD_OBJDIR)/,$(PRELOAD_SRCS:.c=.o))

PRELOAD_LIBS=$(DEBUG_PRELOAD_LIB) $(RELEASE_PRELOAD_LIB)

EXT_STUB_LIB=build/libexasock_ext.so
EXT_STUB_LIB_FULLNAME=libexasock_ext.so.1.0
EXT_STUB_LIB_SONAME=libexasock_ext.so.1
EXT_STUB_LIB_LINKNAME=libexasock_ext.so
EXT_STUB_LIB_LDFLAGS=-Wl,-soname,$(EXT_STUB_LIB_SONAME)

HAVE_NET_TSTAMP_H:=${shell $(CC) $(CFLAGS) -include linux/net_tstamp.h -E -x c /dev/null >/dev/null 2>&1 && echo 1 || echo 0}
CONFIG_CFLAGS=-DHAVE_NET_TSTAMP_H=$(HAVE_NET_TSTAMP_H)

.PHONY: debug release all clean

all: debug release

debug: $(DEBUG_PRELOAD_LIB) $(EXT_STUB_LIB)
release: $(RELEASE_PRELOAD_LIB) $(EXT_STUB_LIB)
clean:
	rm -rf build

$(DEBUG_PRELOAD_OBJDIR)/%.o: %.c
	@mkdir -p $(@D)
	$(CC) $(CFLAGS) $(CONFIG_CFLAGS) $(DEBUG_CFLAGS) -o $@ -c $<

$(RELEASE_PRELOAD_OBJDIR)/%.o: %.c
	@mkdir -p $(@D)
	$(CC) $(CFLAGS) $(CONFIG_CFLAGS) $(RELEASE_CFLAGS) -o $@ -c $<

$(DEBUG_PRELOAD_LIB): $(DEBUG_PRELOAD_LIBOBJS)
	$(CC) $(LDFLAGS) -o $@ $^ $(LDLIBS)

$(RELEASE_PRELOAD_LIB): $(RELEASE_PRELOAD_LIBOBJS)
	$(CC) $(LDFLAGS) -o $@ $^ $(LDLIBS)

$(EXT_STUB_LIB): $(EXT_STUB_SRCS)
	@mkdir -p $(@D)
	$(CC) $(CFLAGS) $(RELEASE_CFLAGS) $(LDFLAGS) $(EXT_STUB_LIB_LDFLAGS) -o $@ $^ $(LDLIBS)

install: all
	install -d $(LIBDIR)/exasock $(DEVLIBDIR) $(INCDIR)/exasock
	install -m 0755 -D $(PRELOAD_LIBS) $(LIBDIR)/exasock
	install -m 0755 -D $(EXT_STUB_LIB) $(LIBDIR)/$(EXT_STUB_LIB_FULLNAME)
	ln -sf $(EXT_STUB_LIB_FULLNAME) $(LIBDIR)/$(EXT_STUB_LIB_SONAME)
	ln -sf $(EXT_STUB_LIB_SONAME) $(DEVLIBDIR)/$(EXT_STUB_LIB_LINKNAME)
	install -m 0644 -D $(EXT_INCLUDES) $(INCDIR)/exasock

uninstall:
	rm -f $(LIBDIR)/exasock/*
	rm -f $(LIBDIR)/libexasock_ext.so.*
	rm -f $(DEVLIBDIR)/libexasock_ext.so
	-rmdir $(LIBDIR)/exasock
	rm -f $(INCDIR)/exasock/*
	-rmdir $(INCDIR)/exasock
