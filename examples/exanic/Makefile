PREFIX=/usr/local
CC=gcc
CFLAGS=-O3 -Wall -I../../libs
LDLIBS=-L../../libs/exanic -lexanic

BIN=exanic-tx-preload
all: $(BIN) $(TEST_BIN)

exanic-tx-preload: exanic-tx-preload.c
	$(CC) $(CFLAGS) $^ -o $@ $(LDLIBS)

clean:
	rm -f $(BIN)
