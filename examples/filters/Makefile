PREFIX=/usr/local
CC=gcc
CFLAGS=-O3 -Wall -I../../libs
LDLIBS=-L../../libs/exanic -lexanic

BIN=exanic-hash-example exanic-ip-filter-specific exanic-mac-filter-specific exanic-filter-tx
all: $(BIN) $(TEST_BIN)

exanic-hash-example: exanic-hash-example.c filter-common.c
	$(CC) $(CFLAGS) $^ -o $@ $(LDLIBS)

exanic-ip-filter-specific: exanic-ip-filter-specific.c filter-common.c
	$(CC) $(CFLAGS) $^ -o $@ $(LDLIBS)

exanic-mac-filter-specific: exanic-mac-filter-specific.c filter-common.c
	$(CC) $(CFLAGS) $^ -o $@ $(LDLIBS)

exanic-filter-tx: exanic-filter-tx.c filter-common.c
	$(CC) $(CFLAGS) $^ -o $@ $(LDLIBS)

clean:
	rm -f $(BIN)
