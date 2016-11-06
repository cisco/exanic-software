#include <stdio.h>
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
    int tx_port, rx_port;
    char rx_buffer[RX_BUFFER_SIZE];
    ssize_t size;

    if (argc < 4)
    {
        fprintf(stderr, "exanic_forward: waits for a packet on one port and forwards it out another\n");
        fprintf(stderr, "  usage: %s device rx_port tx_port\n", argv[0]);
        return 1;
    }

    device = argv[1];
    rx_port = atoi(argv[2]);
    tx_port = atoi(argv[3]);

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

    while (1)
    {
        do {
            size = exanic_receive_frame(rx, rx_buffer, sizeof(rx_buffer), NULL);
        } while (size <= 0);
        exanic_transmit_frame(tx, rx_buffer, size-4);
    }
    return 0;
}

