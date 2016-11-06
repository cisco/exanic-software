#include <stdio.h>
#include <string.h>
#include <exanic/exanic.h>
#include <exanic/fifo_tx.h>
#include <exanic/fifo_rx.h>
#include "util.h"

#define RX_BUFFER_SIZE 2048

int main(int argc, char *argv[])
{
    exanic_t *nic;
    exanic_tx_t *tx;
    exanic_rx_t *rx;
    const char *device;
    int tx_port, rx_port, data_size, count, samples;
    int raw_counts = 0;
    timing_t start, end, *stats;
    char rx_buffer[RX_BUFFER_SIZE];
    char *data;
    ssize_t size;

    if ((argc >= 2) && !strcmp(argv[1], "-r"))
    {
        raw_counts = 1;
        argv++;
        argc--;
    }

    if (argc < 6)
    {
        fprintf(stderr, "exanic_loopback: sends a packet out one port and waits for it on another, reporting timing statistics\n");
        fprintf(stderr, "  usage: exanic_loopback [-r] device tx_port rx_port data_size count\n");
        fprintf(stderr, "          -r prints raw cycle counts instead of the timing summary\n");
        return 1;
    }

    device = argv[1];
    tx_port = atoi(argv[2]);
    rx_port = atoi(argv[3]);
    data_size = atoi(argv[4]);
    count = atoi(argv[5]) + 1;

    data = malloc(data_size);
    init_packet(data, data_size);

    nic = exanic_acquire_handle(device);
    if (!nic)
    {
        fprintf(stderr, "exanic_acquire_handle: %s\n", exanic_get_last_error());
        return 1;
    }

    tx = exanic_acquire_tx_buffer(nic, tx_port, 0);
    if (!tx)
    {
        fprintf(stderr, "exanic_acquire_tx_buffer: %s\n", exanic_get_last_error());
        return 1;
    }

    rx = exanic_acquire_rx_buffer(nic, rx_port, 0);
    if (!rx)
    {
        fprintf(stderr, "exanic_acquire_rx_buffer: %s\n", exanic_get_last_error());
        return 1;
    }

    samples = 0;
    stats = malloc(count * sizeof(timing_t));
    while (samples < count)
    {
        timing_start(start);
        exanic_transmit_frame(tx, data, data_size);
        do {
            size = exanic_receive_frame(rx, rx_buffer, sizeof(rx_buffer), NULL);
        } while (size <= 0);
        timing_end(end);
        stats[samples++] = end-start;

        if ((size != data_size+4) || memcmp(rx_buffer, data, data_size))
            fprintf(stderr, "packet did not match (size=%d data_size=%d)\n", (int)size, data_size);
    }

    timing_print(stats, count, raw_counts);
    return 0;
}

