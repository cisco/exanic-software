#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <net/if.h>
#include <etherfabric/vi.h>
#include <etherfabric/pd.h>
#include <etherfabric/memreg.h>

#define RX_BUFFER_SIZE 2048

int main(int argc, char *argv[])
{
    ef_driver_handle nic;
    ef_pd tx_pd, rx_pd;
    ef_memreg rx_memreg;
    ef_vi tx_vi, rx_vi;
    ef_addr rx_dma_addr;
    ef_filter_spec filter_spec;
    ef_event ev[2];
    int status, tx_ifindex, rx_ifindex, nev, len;
    const char *tx_iface, *rx_iface;
    char *rx_buffer;

    if (argc < 3)
    {
        fprintf(stderr, "ef_vi_forward: waits for a packet on one port and forwards it out another\n");
        fprintf(stderr, "  usage: %s tx_iface rx_iface\n", argv[0]);
        return 1;
    }
    tx_iface = argv[1];
    rx_iface = argv[2];

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

    status = ef_vi_receive_post(&rx_vi, rx_dma_addr, 0);
    if (status < 0)
    {
        fprintf(stderr, "ef_vi_receive_post: %s\n", strerror(errno));
        return 1;
    }

    ef_filter_spec_init(&filter_spec, EF_FILTER_FLAG_NONE);
    ef_filter_spec_set_multicast_all(&filter_spec);
    status = ef_vi_filter_add(&rx_vi, nic, &filter_spec, NULL);
    if (status < 0)
    {
        fprintf(stderr, "ef_vi_filter_add: %s\n", strerror(errno));
        return 1;
    }


    while (1)
    {
        while (1)
        {
            nev = ef_eventq_poll(&rx_vi, ev, 2);
            if (nev < 1)
                continue;
            if (EF_EVENT_TYPE(ev[0]) == EF_EVENT_TYPE_RX)
            {
                len = EF_EVENT_RX_BYTES(ev[0]);
                break;
            }
            if (nev < 2)
                continue;
            if (EF_EVENT_TYPE(ev[1]) == EF_EVENT_TYPE_RX)
            {
                len = EF_EVENT_RX_BYTES(ev[1]);
                break;
            }
        }
        ef_vi_transmit(&tx_vi, rx_dma_addr, len, 0);
        ef_vi_receive_post(&rx_vi, rx_dma_addr, 0);
    }

    ef_memreg_free(&rx_memreg, nic);
    ef_vi_free(&rx_vi, nic);
    ef_pd_free(&rx_pd, nic);
    ef_vi_free(&tx_vi, nic);
    ef_pd_free(&tx_pd, nic);
    ef_driver_close(nic);
    return 0;
}

