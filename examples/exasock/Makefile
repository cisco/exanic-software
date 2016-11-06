CC=gcc
CFLAGS=-O3 -Wall -g

EXT_CFLAGS=-I../../libs -I../../libs/exasock/include
EXT_LDLIBS=-L../../libs/exanic -L../../libs/exasock/build -lexasock_ext -lexanic

BIN=multicast-echo tcp-raw-send udp-timestamp

all: $(BIN)
clean:
	rm -f $(BIN)

tcp-raw-send: tcp-raw-send.c
	$(CC) $(CFLAGS) $(EXT_CFLAGS) $^ $(LDLIBS) $(EXT_LDLIBS) -o $@
