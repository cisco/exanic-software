PREFIX=/usr/local
CC=gcc
CFLAGS=-O3 -Wall -I../../libs
LDLIBS=-L../../libs/exanic -lexanic -lpthread

BIN=exanic-tx-preload exanic-benchmarker exanic-benchmarker-stac-t0 exanic-rx-chunk-inplace

all: $(BIN) $(TEST_BIN)

exanic-tx-preload: exanic-tx-preload.c
	$(CC) $(CFLAGS) $^ -o $@ $(LDLIBS)

exanic-rx-chunk-inplace: exanic-rx-chunk-inplace.c
	$(CC) $(CFLAGS) $^ -o $@ $(LDLIBS)

exanic-benchmarker: exanic-benchmarker.c
	$(CC) $(CFLAGS) $^ -o $@ $(LDLIBS)

exanic-benchmarker-stac-t0: exanic-benchmarker-stac-t0.c
	$(CC) $(CFLAGS) $^ -o $@ $(LDLIBS)

clean:
	rm -f $(BIN)
