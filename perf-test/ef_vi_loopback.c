#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <net/if.h>
#include <etherfabric/vi.h>
#include <etherfabric/pd.h>
#include <etherfabric/memreg.h>
#include "util.h"

#define RX_BUFFER_SIZE 2048

int main(int argc, char *argv[])
{
    ef_driver_handle nic;
    ef_pd tx_pd, rx_pd;
    ef_memreg tx_memreg, rx_memreg;
    ef_vi tx_vi, rx_vi;
    ef_addr tx_dma_addr, rx_dma_addr;
    ef_filter_spec filter_spec;
    ef_event ev[EF_VI_EVENT_POLL_MIN_EVS];
    ef_request_id ids[EF_VI_TRANSMIT_BATCH];
    int status, tx_ifindex, rx_ifindex, data_size, count, samples, nev, i;
    const char *tx_iface, *rx_iface;
    char *rx_buffer;
    char *data;
    timing_t start, end, *stats;

    if (argc < 5)
    {
        fprintf(stderr, "ef_vi_loopback: sends a packet out one port and waits for it on another, reporting timing statistics\n");
        fprintf(stderr, "  usage: %s tx_iface rx_iface data_size count\n", argv[0]);
        return 1;
    }
    tx_iface = argv[1];
    rx_iface = argv[2];
    data_size = atoi(argv[3]);
    count = atoi(argv[4])+1;

    if (posix_memalign((void **)&data, 4096, data_size) < 0)
    {
        fprintf(stderr, "posix_memalign failed\n");
        return 1;
    }
    init_packet(data, data_size);

    if (posix_memalign((void **)&rx_buffer, 4096, RX_BUFFER_SIZE) < 0)
    {
        fprintf(stderr, "posix_memalign failed\n");
        return 1;
    }

    tx_ifindex = if_nametoindex(tx_iface);
    if (tx_ifindex < 0)
    {
        fprintf(stderr, "if_nametoindex(%s): %s\n", tx_iface, strerror(errno));
        return 1;
    }

    rx_ifindex = if_nametoindex(rx_iface);
    if (rx_ifindex < 0)
    {
        fprintf(stderr, "if_nametoindex(%s): %s\n", rx_iface, strerror(errno));
        return 1;
    }


    status = ef_driver_open(&nic);
    if (status < 0)
    {
        fprintf(stderr, "ef_driver_open: %s\n", strerror(errno));
        return 1;
    }


    status = ef_pd_alloc(&tx_pd, nic, tx_ifindex, 0);
    if (status < 0)
    {
        fprintf(stderr, "ef_pd_alloc: %s\n", strerror(errno));
        return 1;
    }

    status = ef_vi_alloc_from_pd(&tx_vi, nic, &tx_pd, nic, -1, -1, -1, NULL, -1, EF_VI_FLAGS_DEFAULT);
    if (status < 0)
    {
        fprintf(stderr, "ef_driver_open: %s\n", strerror(errno));
        return 1;
    }

    status = ef_memreg_alloc(&tx_memreg, nic, &tx_pd, nic, data, data_size);
    if (status < 0)
    {
        fprintf(stderr, "ef_memreg_alloc: %s\n", strerror(errno));
        return 1;
    }
    tx_dma_addr = ef_memreg_dma_addr(&tx_memreg, 0);


    status = ef_pd_alloc(&rx_pd, nic, rx_ifindex, 0);
    if (status < 0)
    {
        fprintf(stderr, "ef_pd_alloc: %s\n", strerror(errno));
        return 1;
    }

    status = ef_vi_alloc_from_pd(&rx_vi, nic, &rx_pd, nic, -1, -1, -1, NULL, -1, EF_VI_FLAGS_DEFAULT);
    if (status < 0)
    {
        fprintf(stderr, "ef_driver_open: %s\n", strerror(errno));
        return 1;
    }

    status = ef_memreg_alloc(&rx_memreg, nic, &rx_pd, nic, rx_buffer, RX_BUFFER_SIZE);
    if (status < 0)
    {
        fprintf(stderr, "ef_memreg_alloc: %s\n", strerror(errno));
        return 1;
    }
    rx_dma_addr = ef_memreg_dma_addr(&rx_memreg, 0);

    /* SFC9100: need to post RX descriptors in multiples of 8 */
    for (i = 0; i < 8; i++)
    {
        status = ef_vi_receive_post(&rx_vi, rx_dma_addr, 0);
        if (status < 0)
        {
            fprintf(stderr, "ef_vi_receive_post: %s\n", strerror(errno));
            return 1;
        }
    }

    ef_filter_spec_init(&filter_spec, EF_FILTER_FLAG_NONE);
    ef_filter_spec_set_multicast_all(&filter_spec);
    status = ef_vi_filter_add(&rx_vi, nic, &filter_spec, NULL);
    if (status < 0)
    {
        fprintf(stderr, "ef_vi_filter_add: %s\n", strerror(errno));
        return 1;
    }


    samples = 0;
    stats = malloc(count * sizeof(timing_t));
    while (samples < count)
    {
        timing_start(start);
        status = ef_vi_transmit(&tx_vi, tx_dma_addr, data_size, 0);
        if (status < 0)
            fprintf(stderr, "ef_vi_transmit: %s\n", strerror(errno));

        while (1)
        {
            nev = ef_eventq_poll(&rx_vi, ev, 2);
            for (i = 0; i < nev; i++)
                if (EF_EVENT_TYPE(ev[i]) == EF_EVENT_TYPE_RX)
                    break;
            if (i != nev)
                break;
        }
        timing_end(end);
        stats[samples++] = end-start;

        while (1)
        {
            nev = ef_eventq_poll(&tx_vi, ev, 2);
            for (i = 0; i < nev; i++)
                if (EF_EVENT_TYPE(ev[i]) == EF_EVENT_TYPE_TX)
                    break;
            if (i != nev)
                break;
        }
        ef_vi_transmit_unbundle(&tx_vi, &ev[i], ids);

        ef_vi_receive_post(&rx_vi, rx_dma_addr, 0);
    }

    timing_print(stats, count, 0);

    ef_memreg_free(&rx_memreg, nic);
    ef_vi_free(&rx_vi, nic);
    ef_pd_free(&rx_pd, nic);
    ef_memreg_free(&tx_memreg, nic);
    ef_vi_free(&tx_vi, nic);
    ef_pd_free(&tx_pd, nic);
    ef_driver_close(nic);
    return 0;
}

