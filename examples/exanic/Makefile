PREFIX=/usr/local
CC=gcc
CFLAGS=-O3 -Wall -I../../libs
LDLIBS=-L../../libs/exanic -lexanic -lpthread

BIN=exanic-rx-frame exanic-tx-frame exanic-rx-chunk-inplace exanic-tx-preload exanic-benchmarker exanic-benchmarker-stac-t0

all: $(BIN) $(TEST_BIN)

exanic-rx-frame: exanic-rx-frame.c
	$(CC) $(CFLAGS) $^ -o $@ $(LDLIBS)

exanic-tx-frame: exanic-tx-frame.c
	$(CC) $(CFLAGS) $^ -o $@ $(LDLIBS)

exanic-rx-chunk-inplace: exanic-rx-chunk-inplace.c
	$(CC) $(CFLAGS) $^ -o $@ $(LDLIBS)

exanic-tx-preload: exanic-tx-preload.c
	$(CC) $(CFLAGS) $^ -o $@ $(LDLIBS)

exanic-benchmarker: exanic-benchmarker.c
	$(CC) $(CFLAGS) $^ -o $@ $(LDLIBS)

exanic-benchmarker-stac-t0: exanic-benchmarker-stac-t0.c
	$(CC) $(CFLAGS) $^ -o $@ $(LDLIBS)

clean:
	rm -f $(BIN)
