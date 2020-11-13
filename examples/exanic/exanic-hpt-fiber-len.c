/*
 * This is an example application to show the power of picosecond timestamps
 * which are available using ExaNIC HPT
 *
 * The example shows how to estimate fiber/DAC cable lengths where the
 * propagation speeds are known.
 *
 */

#include <stdio.h>
#include <string.h>
#include <time.h>
#include <getopt.h>

#include <exanic/exanic.h>
#include <exanic/fifo_tx.h>
#include <exanic/fifo_rx.h>
#include <exanic/register.h>
#include <exanic/time.h>
#include <exanic/util.h>

#include "util.h"

#define RX_BUFFER_SIZE 2048
#define SR_SFP_LATENCY                0.9   /* 900ps RX+TX */
#define NANOS_PER_METER_FIBER         4.98
#define NANOS_PER_METER_TWINAX_AWG30  4.45
#define NANOS_PER_METER_TWINAX_AWG24  4.76
#define FEET_PER_METER                3.28084
#define NANOS_PER_SECOND              (1000 * 1000 * 1000)
#define PICOS_PER_NANO                1000

typedef enum
{
    MEDIA_TYPE_FIBRE, MEDIA_TYPE_AWG24, MEDIA_TYPE_AWG30, MEDIA_TYPE_UNKNOWN,
} media_type;

static int compare_double (const void *a, const void *b)
{
    double fa = *(const double*) a;
    double fb = *(const double*) b;
    return (fa > fb) - (fa < fb);
}

static inline void init_packet (char *data, int data_size)
{
    int i;
    for (i = 0; i < data_size; i++)
        data[i] = i + 'a';

    if (data_size < 6)
    {
        fprintf (stderr, "packet too short\n");
        return;
    }
    /* dest addr = broadcast */
    memset(data, 0xff, 6);
    memset(data + 6, 0xaa, 6);
    memset(data + 12, 0xCC, 2);
    *(uint64_t*)(data + 14) = 0;
}


static inline void bump_packet_seq (char *data)
{
    (*(uint64_t*)(data + 14))++;
}

static inline media_type parse_media_type (void)
{
    if (strcmp (optarg, "fibre") == 0)
        return MEDIA_TYPE_FIBRE;
    else if (strcmp (optarg, "fiber") == 0)
        return MEDIA_TYPE_FIBRE;
    else if (strcmp (optarg, "awg24") == 0)
        return MEDIA_TYPE_AWG24;
    else if (strcmp (optarg, "awg30") == 0)
        return MEDIA_TYPE_AWG30;
    else return MEDIA_TYPE_UNKNOWN;

}

static inline float get_nanos_per_metre (media_type media)
{
    switch (media)
    {
    case MEDIA_TYPE_FIBRE: return NANOS_PER_METER_FIBER;
    case MEDIA_TYPE_AWG24: return NANOS_PER_METER_TWINAX_AWG24;
    case MEDIA_TYPE_AWG30: return NANOS_PER_METER_TWINAX_AWG30;
    case MEDIA_TYPE_UNKNOWN:
        /* Can't get here */
        return -1.0;
    }

    /*Can't get here */
    return -1.0;
}


/*
 * This function tries to calculate the compensation required to adjust measured
 * by taking into account the time it takes for a signal to propagate from the
 * edge of the transceiver to the moment that a timestamp is taken.
 */
static inline float get_latency_offset_ns (int tx_port, int rx_port)
{
    /* Constant offset to get into/out of the FPGA */
    float offset = 33;

    /* Account for the different track lengths between TX/RX pairs */
    if (tx_port == 0 && rx_port == 0)
        offset += 0.1;
    else if (tx_port == 1 && rx_port == 0)
        offset += 0.625;
    else if (tx_port == 0 && rx_port == 1)
        offset += 0.375;
    else if (tx_port == 1 && rx_port == 1)
        offset += 0.85;

    return offset;
}



int main (int argc, char *argv[])
{
    exanic_t *nic;
    exanic_tx_t *tx;
    exanic_rx_t *rx;
    double *stats;
    char rx_buffer[RX_BUFFER_SIZE];
    char *data;
    ssize_t size;
    int c, data_size, samples, err = 0;

    /* Configure sensible defaults */
    const char *device = NULL;
    int tx_port = 0;
    int rx_port = 0;
    media_type media = MEDIA_TYPE_UNKNOWN;
    int packet_size = 64;
    int count = 1000;
    int feet = 0; //Report results in feet

    /* No args supplied */
    if (argc < 2)
        goto usage_error;

    while ((c = getopt (argc, argv, "d:t:r:m:s:c:fh")) != -1)
    {
        switch (c)
        {
        case 'd':
            device = optarg;
            break;
        case 't':
            tx_port = atoi(optarg);
            break;
        case 'r':
            rx_port = atoi(optarg);
            break;
        case 'm':
            media = parse_media_type();
            break;
        case 'c':
            count = atoi(optarg);
            break;
        case 'f':
            feet = 1;
            break;
        default:
            goto usage_error;
        }
    }


    if (media == MEDIA_TYPE_UNKNOWN)
    {
        fprintf (stderr, "Error: Cannot estimate cable length without a "
                 "media type\n\n");
        goto usage_error;
    }


    data_size = packet_size - 4;
    data = malloc (data_size);
    init_packet (data, data_size);

    nic = exanic_acquire_handle(device);
    if (!nic)
    {
        fprintf (stderr, "exanic_acquire_handle: %s\n",
                 exanic_get_last_error());
        err = 1;
        goto err_acquire_handle;
    }

    if (exanic_get_hw_type(nic) != EXANIC_HW_X10_HPT)
    {
        fprintf (stderr, "Error: %s is not an ExaNIC-HPT with high-res "
                 "timestamping.\n",
                 device);
        exit(-1);
    }


    rx = exanic_acquire_rx_buffer(nic, rx_port, 0);
    if (!rx)
    {
        fprintf (stderr, "exanic_acquire_rx_buffer: %s\n",
                 exanic_get_last_error());
        err = 1;
        goto err_acquire_rx;
    }

    tx = exanic_acquire_tx_buffer(nic, tx_port, 0);
    if (!tx)
    {
        fprintf (stderr, "exanic_acquire_tx_buffer: %s\n",
                 exanic_get_last_error());
        err = 1;
        goto err_acquire_tx;
    }

    int bypass_only = is_bypass(nic, device, tx_port);
    if (bypass_only < 0)
    {
        goto err_bypass;
    }
    if (!bypass_only)
    {
        fprintf (stderr, "Error: %s:%i must be in bypass only mode to proceed\n",
                 device, tx_port);
        goto err_bypass;
    }

    samples = 0;
    stats = malloc (count * sizeof(double));
    while (samples < count)
    {
        exanic_cycles32_t old_start, start, end;
        exanic_cycles_t start_expanded, end_expanded, time_delta_cycles;
        struct exanic_timespecps tsps;
        double time_delta_ns;

        old_start = exanic_get_tx_timestamp(tx);
        exanic_transmit_frame(tx, data, data_size);

        do
        {
            /* Wait for TX frame to leave the NIC */
            start = exanic_get_tx_timestamp(tx);
        }
        while (old_start == start);
        start_expanded = exanic_expand_timestamp(nic, start);


        do
        {
            /* Wait for RX frame to arive at the NIC */
            size = exanic_receive_frame(rx, rx_buffer, sizeof(rx_buffer),
                                         &end);
        }
        while (size <= 0);

        if (size != data_size + 4)
        {
            fprintf(stderr, "Error: Packet %i did not match (size=%d data_size=%d)\n",
                     samples, (int) size, data_size + 4);
            exit(1);
        }

        if (memcmp(rx_buffer, data, data_size))
        {
            fprintf(stderr, "Error: Packet %i contents has changed\n", samples);
            exit(1);
        }

        bump_packet_seq(data);

        end_expanded = exanic_expand_timestamp (nic, end);
        time_delta_cycles = end_expanded - start_expanded;
        exanic_cycles_to_timespecps (nic, time_delta_cycles, &tsps);
        time_delta_ns = (double) tsps.tv_psec / PICOS_PER_NANO
            + (double) tsps.tv_sec * NANOS_PER_SECOND;

        stats[samples] = time_delta_ns
            - get_latency_offset_ns (tx_port, rx_port);

        if(samples && (samples % 100000 == 0))
        {
            printf("Taken %i samples\n", samples);
        }
        samples++;
    }

    qsort(stats, count, sizeof(double), compare_double);

    const float nanos_per_meter = get_nanos_per_metre(media);
    const float min_length = (float) stats[0] / nanos_per_meter;
    const float med_length = (float) stats[count / 2] /  nanos_per_meter;
    const float max_length = (float) stats[count -1] /  nanos_per_meter;

    if(feet)
    {
        float min_length_ft = min_length * FEET_PER_METER;
        float med_length_ft = med_length * FEET_PER_METER;
        float max_length_ft = max_length * FEET_PER_METER;
        printf("\nFiber length estimated to be %.2ff [%.2ff,%.2ff] \n",
                med_length_ft, min_length_ft, max_length_ft);
    }
    else
    {
        printf("\nFiber length estimated to be %.2fm [%.2fm,%.2fm] \n",
                min_length, med_length, max_length);
    }

    /* Fall through to cleanup code */
err_bypass:
    exanic_release_tx_buffer(tx);
err_acquire_tx:
    exanic_release_rx_buffer(rx);
err_acquire_rx:
    exanic_release_handle(nic);
err_acquire_handle:
    return err;

usage_error:
    fprintf (stderr, "Usage: %s -d device -t txport -r rxport \n", argv[0]);
    fprintf (stderr, "           -m media [-c count] [-f] [-h] \n");
    fprintf (stderr, "  -d: Specify the exanic device name (e.g. exanic0)\n");
    fprintf (stderr, "  -t: TX port on the exanic (default 0)\n");
    fprintf (stderr, "  -r  RX port on the exanic (default 0)\n");
    fprintf (stderr, "  -m: Media type, valid values are [fiber, awg24, awg30]\n");
    fprintf (stderr, "  -c: Number of packets to send (default 1000)\n");
    fprintf (stderr, "  -f: Report results in feet\n");
    fprintf (stderr, "  -h: Print this usage information\n\n");
    return 1;
}
