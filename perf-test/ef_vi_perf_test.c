#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <linux/if_ether.h>
#include <net/if.h>
#include <arpa/inet.h>

#include <etherfabric/vi.h>
#include <etherfabric/ef_vi.h>
#include <etherfabric/pd.h>
#include <etherfabric/memreg.h>
#include <etherfabric/pio.h>
#include <etherfabric/checksum.h>
#include <etherfabric/capabilities.h>

#include "util.h"

#define N_RX_BUFS       128u
#define BUF_SIZE        2048

#define ETH_SIZE        14
#define IP_SIZE         (ETH_SIZE + 20)
#define UDP_SIZE        (IP_SIZE + 8)

struct pkt_buf {
    struct pkt_buf* next;
    ef_addr         rx_dma_buf_addr;
    ef_addr         tx_dma_buf_addr;
    int             id;
    unsigned        dma_buf[1] EF_VI_ALIGN(EF_VI_DMA_ALIGN);
};

struct pkt_buf *rx_pkt_bufs[N_RX_BUFS];
struct pkt_buf *tx_pkt_buf;

/* Any IP can be chosen */
const uint32_t laddr_he = 0xac108564;  /* 172.16.133.100 */
const uint32_t raddr_he = 0xac010203;  /* 172.1.2.3 */
const uint16_t port_he = 8080;

static int ctpio_thresh, ctpio_fails;
static int data_size = 60;
static int rx_posted = 0;

static ef_memreg rx_memregs[N_RX_BUFS];
static ef_memreg fwd_memregs[N_RX_BUFS];

enum tx_modes {
    ctpio,
    tx_alts,
    pio,
    dma
};

enum filter_modes {
    filter_ucast,
    filter_mcast
};

typedef int (*perf_test)(ef_vi*, ef_vi*, timing_t*);
typedef void (*tx_method)(ef_vi*);

static struct {
    perf_test p_test;
    tx_method tx_func;
    int tx_flags;
    int tx_mode;
    int tx_cap;
    int filter_mode;
    int raw_counts;
} test_options;

/* Create a UDP packet */
static void init_udp_packet(void* pkt_buf, ef_vi *tx_vi, ef_driver_handle *nic)
{
    char buf[data_size];

    struct ethhdr eth_header;

    /* Broadcast dest MAC */
    memset(&eth_header.h_dest, 0xFF, 6);

    /* Source MAC is tx_vi's MAC */
    unsigned char src_mac[6];
    ef_vi_get_mac(tx_vi, *nic, src_mac);
    memcpy(&eth_header.h_source, &src_mac[0], 6);

    /* EtherType is IPv4 */
    eth_header.h_proto = htons(0x0800);
    memcpy(&buf[0], &eth_header, sizeof(struct ethhdr));

    struct iphdr ip_header = {
        .version = 0x04,
        .ihl = 0x05,
        .tos = 0x00,
        .tot_len = htons(data_size - ETH_SIZE),
        .id = 0x00,
        .frag_off = 0x00,
        .ttl = 0x05,
        .protocol = 0x11,
        .check = 0x00,
        .saddr = htonl(laddr_he),
        .daddr = htonl(raddr_he)
    };

    ip_header.check = ef_ip_checksum(&ip_header);
    memcpy(&buf[ETH_SIZE], &ip_header, sizeof(struct iphdr));

    struct udphdr udp_header = {
        .source = htons(port_he),
        .dest = htons(port_he),
        .len = htons((uint16_t)data_size - IP_SIZE),
        .check = 0x00
    };

    memcpy(&buf[IP_SIZE], &udp_header, sizeof(struct udphdr));

    /* Fill the UDP payload */
    init_packet(&buf[UDP_SIZE], data_size - UDP_SIZE);

    /* Calculate UDP checksum */
    struct iovec iov;
    iov.iov_base = &buf[UDP_SIZE];
    iov.iov_len = data_size - UDP_SIZE;

    /* Generate UDP checksum beforehand, so that we can compare this later. */
    uint16_t udp_csum = ef_udp_checksum(&ip_header, &udp_header, &iov, 1);

    memcpy(&buf[IP_SIZE + 6], &udp_csum, 2);
    memcpy(pkt_buf, &buf[0], data_size);
}

static inline void ctpio_send(ef_vi* vi)
{
    ef_vi_transmit_ctpio(vi, tx_pkt_buf->dma_buf, data_size, ctpio_thresh);
    TRY(ef_vi_transmit_ctpio_fallback(vi, tx_pkt_buf->tx_dma_buf_addr, data_size, 0));
}

static inline void dma_send(ef_vi* vi)
{
    TRY(ef_vi_transmit(vi, tx_pkt_buf->tx_dma_buf_addr, data_size, 0));
}

static inline void tx_alts_fill(ef_vi *vi)
{
    TRY(ef_vi_transmit_alt_stop(vi, 0));
    TRY(ef_vi_transmit_alt_select(vi, 0));
    dma_send(vi);
}

static inline void tx_alts_send(ef_vi* vi)
{
    TRY(ef_vi_transmit_alt_go(vi, 0));
    tx_alts_fill(vi);
}

static inline void pio_send(ef_vi* vi)
{
    TRY(ef_vi_transmit_pio(vi, 0, data_size, 0));
}

static inline void rx_post(ef_vi* vi)
{
    struct pkt_buf* pb = rx_pkt_bufs[rx_posted & (N_RX_BUFS - 1)];
    TRY(ef_vi_receive_post(vi, pb->rx_dma_buf_addr, pb->id));
}

/* Poll the event queue for RX vi */
static inline int poll_rx(ef_vi *rx_vi)
{
    static int      rx_ev = 0;
    static int      i = 0;
    static ef_event rx_evs[EF_VI_EVENT_POLL_MIN_EVS];
    int n_rx;
    ef_request_id   rx_ids[EF_VI_RECEIVE_BATCH];
    int status = 0;

    while (1)
    {
        for ( ; i < rx_ev; ++i)
            switch (EF_EVENT_TYPE(rx_evs[i])) {
            case EF_EVENT_TYPE_RX:
                ++i;
                return status;
            case EF_EVENT_TYPE_RX_MULTI:
            case EF_EVENT_TYPE_RX_MULTI_DISCARD:
                n_rx = ef_vi_receive_unbundle(rx_vi, &(rx_evs[i]), rx_ids);
                TEST(n_rx == 1);
                ++i;
                return 1;
            case EF_EVENT_TYPE_RX_DISCARD:
                if (EF_EVENT_RX_DISCARD_TYPE(rx_evs[i])
                    == EF_EVENT_RX_DISCARD_CRC_BAD) {
                 /* Likely a poisoned frame caused by underrun.
                    A fallback frame will follow. */
                    rx_posted++;
                    rx_post(rx_vi);
                    status = 1;
                    break;
                }
             /* Otherwise, fall through. */
            default:
                fprintf(stderr, "ERROR: unexpected event "EF_EVENT_FMT"\n",
                        EF_EVENT_PRI_ARG(rx_evs[i]));
                TEST(0);
                break;
            }
        rx_ev = ef_eventq_poll(rx_vi, rx_evs, sizeof(rx_evs) / sizeof(rx_evs[0]));
        i = 0;
    }

    return 0;
}

/* Poll the event queue for the TX vi
   Multiple TX events can be raised for a single transmit, so
   we do not return immediately on the first event raised */
static inline int poll_tx(ef_vi *tx_vi)
{
    int      tx_ev = 0;
    int      i = 0;
    ef_event tx_evs[EF_VI_EVENT_POLL_MIN_EVS];
    ef_request_id   tx_ids[EF_VI_TRANSMIT_BATCH];
    int      status = -1;

    while (status < 0)
    {
        for ( ; i < tx_ev; ++i )
        {
            switch (EF_EVENT_TYPE(tx_evs[i])) {
            case EF_EVENT_TYPE_TX_ALT:
                break;
            case EF_EVENT_TYPE_TX:
                ef_vi_transmit_unbundle(tx_vi, &(tx_evs[i]), tx_ids);

                /* Catches cases where a DMA fallback transmit is used
                   following a CTPIO send failure */
                if (test_options.tx_mode == ctpio && !EF_EVENT_TX_CTPIO(tx_evs[i]))
                {
                    status = 1;
                    break;
                }
                status = 0;
                break;
            default:
                fprintf(stderr, "ERROR: unexpected event "EF_EVENT_FMT"\n",
                        EF_EVENT_PRI_ARG(tx_evs[i]));
                TEST(0);
                status = 1;
                break;
            }
        }
        tx_ev = ef_eventq_poll(tx_vi, tx_evs, sizeof(tx_evs) / sizeof(tx_evs[0]));
        i = 0;
    }

    return status;
}

static inline int do_loopback(ef_vi *tx_vi, ef_vi *rx_vi,
                              timing_t *elapsed_cycles)
{
    int tx_status, rx_status;
    timing_t start, end;
    rx_status = 0;

    timing_start(start);
    test_options.tx_func(tx_vi);
    rx_status = poll_rx(rx_vi);
    timing_end(end);
    *elapsed_cycles = end - start;
    tx_status = poll_tx(tx_vi);

    /* Compare the received packet against the transmitted packet */
    if (rx_status == 0 &&
        memcmp(rx_pkt_bufs[rx_posted & (N_RX_BUFS - 1)]->dma_buf,
               tx_pkt_buf->dma_buf, data_size) != 0)
    {
        fprintf(stderr, "received packet did not match transmitted packet!\n");
        rx_status = 1;
    }

    rx_post(rx_vi);
    rx_posted++;
    return tx_status | rx_status;
}

static inline int do_forward(ef_vi *tx_vi, ef_vi *rx_vi,
                             timing_t *elapsed_cycles)
{
    int tx_status, rx_status;
    timing_t start, end;

    /* When using TX alternatives (preloading) the received frame will
       not be forwarded */
    if (test_options.tx_mode != tx_alts)
        tx_pkt_buf = rx_pkt_bufs[rx_posted & (N_RX_BUFS - 1)];

    timing_start(start);
    rx_status = poll_rx(rx_vi);

    /* If using PIO, copy the received packet to the PIO region */
    if (test_options.tx_mode == pio)
        ef_pio_memcpy(tx_vi, rx_pkt_bufs[rx_posted & (N_RX_BUFS - 1)]->dma_buf,
                      0, data_size);

    test_options.tx_func(tx_vi);
    timing_end(end);
    tx_status = poll_tx(tx_vi);
    *elapsed_cycles = end - start;
    rx_post(rx_vi);
    rx_posted++;

    return tx_status | rx_status;
}

static int do_init(const char *tx_iface, const char *rx_iface, ef_vi *tx_vi,
                   ef_vi *rx_vi)
{
    int tx_ifindex, rx_ifindex, i;
    ef_driver_handle nic;
    ef_pd tx_pd, rx_pd;
    ef_filter_spec filter_spec;
    ef_memreg tx_memreg;
    struct pkt_buf* pb;

    tx_ifindex = if_nametoindex(tx_iface);
    if(tx_ifindex < 0)
    {
        fprintf(stderr, "tx if_nametoindex(%s): %s\n", tx_iface, strerror(errno));
        return 1;
    }

    rx_ifindex = if_nametoindex(rx_iface);
    if(tx_ifindex < 0)
    {
        fprintf(stderr, "rx if_nametoindex(%s): %s\n", rx_iface, strerror(errno));
        return 1;
    }

    /* Get handle, protection domains and virtual interfaces */
    TRY(ef_driver_open(&nic));
    TRY(ef_pd_alloc(&tx_pd, nic, tx_ifindex, 0));
    TRY(ef_pd_alloc(&rx_pd, nic, rx_ifindex, 0));
    TRY(ef_vi_alloc_from_pd(tx_vi, nic, &tx_pd, nic, -1, -1, -1, NULL, -1,
                            test_options.tx_flags));
    TRY(ef_vi_alloc_from_pd(rx_vi, nic, &rx_pd, nic, -1, -1, -1, NULL, -1,
                            EF_VI_FLAGS_DEFAULT));

    /* Check if this NIC is capable of the selected TX mode */
    if(test_options.tx_mode < dma)
    {
        unsigned long cap_val;
        if(ef_vi_capabilities_get(nic, tx_ifindex, test_options.tx_cap, &cap_val) < 0)
        {
            fprintf(stderr, "Selected TX mode is not supported by this NIC.\n");
            return 1;
        }
    }

    /* Allocate a range of 4K pages for RX buffers */
    for (i = 0; i < N_RX_BUFS; i++)
    {
        void *p;
        TEST(posix_memalign(&p, 4096, BUF_SIZE) == 0);
        TRY(ef_memreg_alloc(&rx_memregs[i], nic, &rx_pd, nic, p, BUF_SIZE));

        /* Register the same memory with TX VI (this is needed for forwarding only) */
        TRY(ef_memreg_alloc(&fwd_memregs[i], nic, &tx_pd, nic, p, BUF_SIZE));

        rx_pkt_bufs[i] = (void*) ((char*) p);
        rx_pkt_bufs[i]->rx_dma_buf_addr = ef_memreg_dma_addr(&rx_memregs[i], 0);
        rx_pkt_bufs[i]->tx_dma_buf_addr = ef_memreg_dma_addr(&fwd_memregs[i], 0);
    }

    for (i = 0; i < N_RX_BUFS; i++)
    {
        pb = rx_pkt_bufs[i];
        pb->id = i;
        pb->rx_dma_buf_addr += offsetof(struct pkt_buf, dma_buf);
        pb->tx_dma_buf_addr += offsetof(struct pkt_buf, dma_buf);
    }

    /* Allocate TX buffering */
    void *tx_buf;
    TEST(posix_memalign(&tx_buf, 4096, BUF_SIZE) == 0);
    TRY(ef_memreg_alloc(&tx_memreg, nic, &tx_pd, nic, tx_buf, BUF_SIZE));

    /* Fill TX buffer with a packet */
    tx_pkt_buf = tx_buf;
    tx_pkt_buf->tx_dma_buf_addr = ef_memreg_dma_addr(&tx_memreg, 0);
    tx_pkt_buf->tx_dma_buf_addr += offsetof(struct pkt_buf, dma_buf);
    init_udp_packet(tx_pkt_buf->dma_buf, tx_vi, &nic);

    /* If using TX alternatives, buffer a packet onto the NIC */
    if (test_options.tx_mode == tx_alts)
    {
        TRY(ef_vi_transmit_alt_alloc(tx_vi, nic, 1, BUF_SIZE));

        /* Check that the packet will fit in the available buffer space */
        struct ef_vi_transmit_alt_overhead overhead;
        TRY(ef_vi_transmit_alt_query_overhead(tx_vi, &overhead));
        int pkt_bytes = ef_vi_transmit_alt_usage(&overhead, data_size);
        TEST(pkt_bytes <= BUF_SIZE);

        /* Send a packet to the buffer */
        tx_alts_fill(tx_vi);
    }
    else if (test_options.tx_mode == pio)
    {
        ef_pio tx_pio;
        ef_pio_alloc(&tx_pio, nic, &tx_pd, -1, nic);
        TRY(ef_pio_link_vi(&tx_pio, nic, tx_vi, nic));
        TRY(ef_pio_memcpy(tx_vi, tx_pkt_buf->dma_buf, 0, data_size));
    }

    ef_filter_spec_init(&filter_spec, EF_FILTER_FLAG_NONE);

    if (test_options.filter_mode == filter_ucast)
        ef_filter_spec_set_ip4_local(&filter_spec, IPPROTO_UDP, htonl(raddr_he),
                                     htons(port_he));
    else
        ef_filter_spec_set_multicast_all(&filter_spec);

    TRY(ef_vi_filter_add(rx_vi, nic, &filter_spec, NULL));

    for (i = 0; i < N_RX_BUFS; i++)
    {
        rx_post(rx_vi);
        rx_posted++;
    }

    return 0;
}

static int set_tx_option(char *option)
{
    if (strcmp(option, "ctpio") == 0)
    {
        test_options.tx_func = ctpio_send;
        test_options.tx_flags = EF_VI_TX_CTPIO;
        test_options.tx_mode = ctpio;
        test_options.tx_cap = EF_VI_CAP_CTPIO;
    }
    else if (strcmp(option, "tx_alts") == 0)
    {
        test_options.tx_func = tx_alts_send;
        test_options.tx_flags = EF_VI_TX_ALT;
        test_options.tx_mode = tx_alts;
        test_options.tx_cap = EF_VI_CAP_TX_ALTERNATIVES;
    }
    else if (strcmp(option, "pio") == 0)
    {
        test_options.tx_func = pio_send;
        test_options.tx_flags = EF_VI_FLAGS_DEFAULT;
        test_options.tx_mode = pio;
        test_options.tx_cap = EF_VI_CAP_PIO;
    }
    else if (strcmp(option, "dma") == 0)
    {
        test_options.tx_func = dma_send;
        test_options.tx_flags = EF_VI_FLAGS_DEFAULT;
        test_options.tx_mode = dma;
    }
    else
        return 1;
    return 0;
}

int main(int argc, char* argv[])
{
    ef_vi tx_vi, rx_vi;
    const char *tx_iface = NULL;
    const char *rx_iface = NULL;
    const char *filter_option = NULL;
    int count = 1000000;
    int warmups = 10000;
    int good_samples, i, status, c;
    timing_t elapsed_cycles;
    timing_t *stats;

    /* Set default test options to run as fast as possible in loopback mode */
    ctpio_thresh = data_size;
    set_tx_option("ctpio");
    test_options.filter_mode = filter_ucast;
    test_options.p_test = do_loopback;
    test_options.raw_counts = 0;

    if (argc < 2)
        goto usage_error;

    while ((c = getopt(argc, argv, "m:R:T:t:r:s:c:w:f:b:x:")) != -1)
    {
        switch(c)
        {
        case 'm':
            if (strcmp(optarg, "loopback") == 0)
                test_options.p_test = do_loopback;
            else if (strcmp(optarg, "forward") == 0)
                test_options.p_test = do_forward;
            break;
        case 'T':
            if (set_tx_option(optarg) == 1)
                goto usage_error;
            break;
        case 't':
            tx_iface = optarg;
            break;
        case 'r':
            rx_iface = optarg;
            break;
        case 's':
            data_size = atoi(optarg);
            break;
        case 'c':
            count = atoi(optarg);
            break;
        case 'w':
            warmups = atoi(optarg);
            break;
        case 'f':
            filter_option = optarg;
            if (strcmp(filter_option, "ucast") == 0)
                test_options.filter_mode = filter_ucast;
            else if (strcmp(filter_option, "mcast") == 0)
                test_options.filter_mode = filter_mcast;
            break;
        case 'b':
            ctpio_thresh = atoi(optarg);
            break;
        case 'a':
            test_options.raw_counts = 1;
            break;
        default:
            goto usage_error;
        }
    }

    if (test_options.tx_mode == -1)
        goto usage_error;

    if (tx_iface == NULL)
    {
        fprintf(stderr, "tx interface name not specified!\n");
        goto usage_error;
    }

    if (rx_iface == NULL)
    {
        fprintf(stderr, "rx interface name not specified!\n");
        goto usage_error;
    }

    if (data_size > 1500)
        goto packet_size_error;

    good_samples = 0;
    stats = malloc(count * sizeof(timing_t));

    if (do_init(tx_iface, rx_iface, &tx_vi, &rx_vi) == 1)
        return 1;

    for (i = 0; i < warmups; i++)
        test_options.p_test(&tx_vi, &rx_vi, &elapsed_cycles);

    for (i = 0; i < count; i++)
    {
        status = test_options.p_test(&tx_vi, &rx_vi, &elapsed_cycles);
        if (status == 0)
            stats[good_samples++] = elapsed_cycles;
        else if (test_options.tx_mode == ctpio)
            ctpio_fails++;
    }

    timing_print(stats, good_samples, 0);

    printf("Samples counted: %d\n", good_samples);
    if (test_options.tx_mode == ctpio)
        printf("CTPIO failures: %d\n", ctpio_fails);

    return 0;

usage_error:
    fprintf(stderr, "ef_vi_perf_test: Measure the latency performance of SolarFlare NICs with ef_vi\n");
    fprintf(stderr, "Usage: %s -m test_mode -t tx_iface -r rx_iface\n", argv[0]);
    fprintf(stderr, "          [-T txmode] [-s size] [-c count] [-w warmups]\n");
    fprintf(stderr, "          [-f filtermode] [-x rx_buf_size] [-b ctpio_buffering] [-a]\n");
    fprintf(stderr, "  -m specify the test mode (loopback/forward)\n");
    fprintf(stderr, "  -t/-r: specify the TX/RX interface name\n");
    fprintf(stderr, "  -T specify the TX mode. Supported options are ctpio, tx_alts, pio, dma\n");
    fprintf(stderr, "  -s specify the packet size to send (default 60)\n");
    fprintf(stderr, "  -c specify how many packets to send (default 1000000)\n");
    fprintf(stderr, "  -w specify how many warmup packets to send (default 10000)\n");
    fprintf(stderr, "  -f specify the receive filter mode (ucast/mcast)\n");
    fprintf(stderr, "  -b specify the amount of buffering to use with CTPIO mode\n");
    fprintf(stderr, "  -a print raw cycle counts instead of a percentile breakdown\n");
    return 1;

packet_size_error:
    fprintf(stderr, "Packet size is too big: %d (must be <= 1500)\n", data_size);
    return 1;
}
