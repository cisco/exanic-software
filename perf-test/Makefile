CC=gcc
CPPFLAGS=-O3 -Wall -I../libs
EXANIC_LIBS=-L../libs/exanic -lexanic
EXANIC_TARGETS=exanic_loopback exanic_forward
IBVERBS_TARGETS=ibverbs_loopback ibverbs_forward
EF_VI_TARGETS=ef_vi_loopback ef_vi_forward
ALL_TARGETS=$(EXANIC_TARGETS) $(ZIP_TARGETS) $(IBVERBS_TARGETS) $(EF_VI_TARGETS)

default:
	@echo "make all:	Build all programs"
	@echo "make exanic:	Build all libexanic test programs"
	@echo "make ibverbs:	Build all libibverbs (Mellanox etc) test programs"
	@echo "make ef_vi:	Build all ef_vi (Solarflare) test programs"
	@echo "make clean:	Delete built files"

all: $(ALL_TARGETS)

exanic: $(EXANIC_TARGETS)

exanic_loopback: exanic_loopback.o util.o
	$(CC) $^ -o $@ $(EXANIC_LIBS)

exanic_forward: exanic_forward.o
	$(CC) $^ -o $@ $(EXANIC_LIBS)

ibverbs: $(IBVERBS_TARGETS)

ibverbs_loopback: ibverbs_loopback.o util.o
	$(CC) $^ -o $@ -libverbs

ibverbs_forward: ibverbs_forward.o
	$(CC) $^ -o $@ -libverbs

ef_vi: $(EF_VI_TARGETS)

ef_vi_loopback: ef_vi_loopback.o util.o
	$(CC) $^ -o $@ -lciul1

ef_vi_forward: ef_vi_forward.o
	$(CC) $^ -o $@ -lciul1

clean:
	rm -f $(ALL_TARGETS) *.o

