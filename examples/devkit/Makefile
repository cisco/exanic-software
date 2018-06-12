PREFIX=/usr/local
CC=gcc
CFLAGS=-O3 -Wall -I../../libs
LDLIBS=-L../../libs/exanic -lexanic

EXASOCK_CFLAGS=-I../../libs/exasock/include
EXASOCK_LDLIBS=-L../../libs/exasock/build -lexasock_ext

BIN=libexanic-responder-example exasock-tcp-responder-example custom-filter-example ping-example spam-example exanic-devkit-register-read exanic-devkit-register-write exanic-xvcserver exanic-devkit-multi-preload-tx-example
all: $(BIN)

exasock-tcp-responder-example: exasock-tcp-responder-example.c
	$(CC) $(CFLAGS) $(EXASOCK_CFLAGS) $^ -o $@ $(LDLIBS) $(EXASOCK_LDLIBS)

clean:
	rm -f $(BIN)
