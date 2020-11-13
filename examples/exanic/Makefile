PREFIX=/usr/local
CC=gcc
CFLAGS=-O3 -Wall -I../../libs
LDLIBS=-L../../libs/exanic -lexanic -lpthread

BIN=exanic-rx-frame exanic-tx-frame exanic-rx-chunk-inplace exanic-tx-preload exanic-hpt-fiber-len exanic-measure exanic-benchmarker-stac-t0

all: $(BIN) $(TEST_BIN)

exanic-rx-frame: exanic-rx-frame.c
	$(CC) $(CFLAGS) $^ -o $@ $(LDLIBS)

exanic-tx-frame: exanic-tx-frame.c
	$(CC) $(CFLAGS) $^ -o $@ $(LDLIBS)

exanic-rx-chunk-inplace: exanic-rx-chunk-inplace.c
	$(CC) $(CFLAGS) $^ -o $@ $(LDLIBS)

exanic-tx-preload: exanic-tx-preload.c
	$(CC) $(CFLAGS) $^ -o $@ $(LDLIBS)

exanic-hpt-fiber-len: exanic-hpt-fiber-len.c
	$(CC) $(CFLAGS) $^ -o $@ $(LDLIBS)

exanic-measure: exanic-measure.c
	$(CC) $(CFLAGS) $^ -o $@ $(LDLIBS)

exanic-benchmarker-stac-t0: exanic-benchmarker-stac-t0.c
	$(CC) $(CFLAGS) $^ -o $@ $(LDLIBS)

clean:
	rm -f $(BIN)
