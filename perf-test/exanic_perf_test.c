#include <stdio.h>
#include <string.h>
#include <sys/param.h>
#include <unistd.h>

#include <exanic/exanic.h>
#include <exanic/fifo_tx.h>
#include <exanic/fifo_rx.h>

#include "util.h"

#define RX_BUFFER_SIZE 2048

typedef int (*perf_test)(timing_t*);
typedef void (*tx_method)();
typedef int (*rx_method)(timing_t*);

static struct {
    perf_test p_test;
    tx_method tx_func;
    rx_method rx_func;
    int rx_port;
    int tx_port;
    int count;
    int data_size;
    int warmups;
    int raw_counts;
} test_options;

static exanic_tx_t *tx;
static exanic_rx_t *rx;
static timing_t *stats;
static char *rx_buffer, *tx_data;
static int more_chunks, rx_compare_size;
static uint32_t chunk_id;

/* Preload a frame onto the NIC. */
static void preload_frame(int length)
{
    struct tx_chunk *chunk = (struct tx_chunk *) (tx->buffer);
    size_t padding = exanic_payload_padding_bytes(EXANIC_TX_TYPE_RAW);

    chunk->feedback_id = 0x0000;            /* Not applicable. */
    chunk->feedback_slot_index = 0x8000;    /* No feedback. */
    chunk->length = padding + length ;      /* Frame size + padding. */
    chunk->type = EXANIC_TX_TYPE_RAW;       /* Only supported transmit type. */
    chunk->flags = 0;

    memcpy(chunk->payload + padding, tx_data, test_options.data_size);

    /* Force the write combining buffers to be flushed after preloading a frame. */
    tx->exanic->registers[REG_EXANIC_INDEX(REG_EXANIC_PCIE_IF_VER)]
        = 0xDEADBEEF;
}

/* Send the preloaded frame */
static inline void tx_preloaded()
{
    tx->exanic->registers[REG_PORT_INDEX(tx->port_number, REG_PORT_TX_COMMAND)]
        = tx->buffer_offset;
}

static inline void tx_frame()
{
    exanic_transmit_frame(tx, tx_data, test_options.data_size);
}

static inline int rx_chunk_inplace(timing_t *end)
{
    static int size;
    do {
        size = exanic_receive_chunk_inplace(rx, &rx_buffer, &chunk_id,
                                            &more_chunks);
    } while (size <= 0);

    if (end != NULL)
        timing_end(*end);

    return size;
}

static inline int rx_frame(timing_t *end)
{
    static int size;

    do {
        size = exanic_receive_frame(rx, rx_buffer, RX_BUFFER_SIZE, NULL);
    } while (size <= 0);

    if (end != NULL)
        timing_end(*end);

    return size;
}

static int do_loopback(timing_t *elapsed_time)
{
    int size, rx_status;
    timing_t start, end;

    rx_status = 0;
    *elapsed_time = 0;
    timing_start(start);
    test_options.tx_func();
    size = test_options.rx_func(&end);
    *elapsed_time = end - start;

    if (size > 0)
    {
        if (memcmp(rx_buffer, tx_data, rx_compare_size) != 0)
        {
            fprintf(stderr, "packet contents did not match!\n");
            rx_status = 1;
        }

        if (more_chunks == 1)
            exanic_receive_abort(rx);
    }
    else
        rx_status = 1;

    return rx_status;
}

static int do_forward(timing_t *elapsed_time)
{
    timing_t start, end;
    int rx_status, size;
    rx_status = 0;
    *elapsed_time = 0;

    timing_start(start);
    size = test_options.rx_func(NULL);
    test_options.data_size = size;
    test_options.tx_func();
    timing_end(end);
    *elapsed_time = end - start;

    if (size > 0 && more_chunks == 1)
        exanic_receive_abort(rx);

    return rx_status;
}

int main(int argc, char *argv[])
{
    exanic_t *exanic;
    char *device = NULL;
    int c, i, good_samples, status;
    timing_t elapsed_time;

    /* Default to loopback between port 0 and 1 */
    test_options.p_test = do_loopback;
    test_options.tx_port = 0;
    test_options.tx_func = tx_preloaded;
    test_options.rx_port = 1;
    test_options.rx_func = rx_chunk_inplace;
    test_options.count = 1000000;
    test_options.data_size = 60;
    test_options.warmups = 100000;
    test_options.raw_counts = 0;
    rx_compare_size = 60;

    while (( c = getopt(argc, argv, "m:d:t:r:T:R:s:c:aw:")) != -1)
    {
        switch(c)
        {
        case 'm':
            if(strcmp(optarg, "loopback") == 0)
                test_options.p_test = do_loopback;
            else if (strcmp(optarg, "forward") == 0)
                test_options.p_test = do_forward ;
            else
                goto usage_error;
            break;
        case 'd':
            device = optarg;
            break;
        case 't':
            test_options.tx_port = atoi(optarg);
            break;
        case 'r':
            test_options.rx_port = atoi(optarg);
            break;
        case 'T':
            if(strcmp(optarg, "frame") == 0)
                test_options.tx_func = tx_frame;
            else if (strcmp(optarg, "preloaded") == 0)
                test_options.tx_func = tx_preloaded;
            else
                goto usage_error;
            break;
        case 'R':
            if(strcmp(optarg, "frame") == 0)
            {
                test_options.rx_func = rx_frame;
                rx_compare_size = test_options.data_size - 4;
            }
            else if (strcmp(optarg, "chunk_inplace") == 0)
            {
                test_options.rx_func = rx_chunk_inplace;
                rx_compare_size = MIN(120, test_options.data_size - 4);
            }
            else
                goto usage_error;
            break;
        case 's':
            test_options.data_size = atoi(optarg);
            break;
        case 'c':
            test_options.count = atoi(optarg);
            break;
        case 'a':
            test_options.raw_counts = 1;
            break;
        case 'w':
            test_options.warmups = atoi(optarg);
            break;
        default:
            goto usage_error;
        }
    }

    if (device == NULL)
    {
        fprintf(stderr, "No device name specified\n");
        goto usage_error;
    }

    EXA_TRY(exanic = exanic_acquire_handle(device));
    EXA_TRY(tx = exanic_acquire_tx_buffer(exanic, test_options.tx_port, 0));
    EXA_TRY(rx = exanic_acquire_rx_buffer(exanic, test_options.rx_port, 0));

    rx_buffer = malloc(RX_BUFFER_SIZE);

    /* Create a packet to send if using loopback mode, or preloading.
       Otherwise, the received packet will be sent */
    if (test_options.p_test == do_loopback || test_options.tx_func == tx_preloaded)
    {
        tx_data = malloc(test_options.data_size);
        init_packet(tx_data, test_options.data_size);
    }
    else
        tx_data = rx_buffer;

    stats = malloc(sizeof(timing_t) * test_options.count);
    good_samples = 0;
    status = 0;

    /* Preload a frame if using tx_preloaded */
    if (test_options.tx_func == tx_preloaded)
        preload_frame(test_options.data_size);

    for (i = 0; i < test_options.warmups; i++)
        test_options.p_test(&elapsed_time);

    for (i = 0; i < test_options.count; i++)
    {
        status = test_options.p_test(&elapsed_time);
        if (status == 0)
            stats[good_samples++] = elapsed_time;
    }

    timing_print(stats, good_samples, test_options.raw_counts);
    return 0;

usage_error:
    fprintf(stderr, "exanic_perf_test: Measure the latency performance of ExaNICs with libexanic\n");
    fprintf(stderr, "Usage: %s -d device\n", argv[0]);
    fprintf(stderr, "         [-m testmode] [-t txport] [-r rxport]\n");
    fprintf(stderr, "         [-T txmode] [-R rxmode]\n");
    fprintf(stderr, "         [-s size] [-c count] [-w warmups] [-a]\n");
    fprintf(stderr, "  -m: specify the test mode (loopback/forward)\n");
    fprintf(stderr, "  -d: specify the exanic device name (e.g. exanic0)\n");
    fprintf(stderr, "  -t/-r set the port to transmit/receive packets on\n");
    fprintf(stderr, "  -T set the method to transmit packets (frame/preloaded)\n");
    fprintf(stderr, "  -R set the method to receive packets (frame/chunk_inplace)\n");
    fprintf(stderr, "  -s: specify the packet size to send (default 60)\n");
    fprintf(stderr, "  -c: specify how many packets to send (default 1000000)\n");
    fprintf(stderr, "  -w: specify how many warmup frames to send (default 100000)\n");
    fprintf(stderr, "  -a: print raw cycle counts instead of a percentile breakdown\n");
    return 1;
}
