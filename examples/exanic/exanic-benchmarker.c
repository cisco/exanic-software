/*
 * This is an example of a benchmarking application written primarily for
 * use with ExaNIC HPT (though nothing prevents it from being used with other
 * devices such as the X10/X40).
 *
 * The application is intended to be used to benchmark external devices and
 * cables. It can be used to estimate cable lengths where the propagation
 * speeds are known, or to estimate the delay measured from TX to RX through
 * some device where both cable lengths and propagation delays are known.
 *
 * The application also reports raw measured values which can be used for
 * calibration and high precision benchmarking.
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

#define RX_BUFFER_SIZE 2048
#define SR_SFP_LATENCY                0.9   /* 900ps RX+TX */
#define NANOS_PER_METER_FIBER         4.98
#define NANOS_PER_METER_TWINAX_AWG30  4.45
#define NANOS_PER_METER_TWINAX_AWG24  4.76

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

void init_packet (char *data, int data_size)
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
    memset (data, 0xff, 6);
    memset (data + 6, 0xaa, 6);
    memset (data + 12, 0xCC, 2);
    *(uint64_t*)(data + 14) = 0;
}


void bump_packet_seq (char *data)
{
    (*(uint64_t*)(data + 14))++;
}

media_type parse_media_type (void)
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

float get_latency_offset_htp_ns (exanic_t* nic, int tx_port, int rx_port,
                                 media_type media, float tx_cable_len,
                                 float rx_cable_len)
{

    /* Constant offset to get into/out of the FPGA */
    float offset = 0;

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

/*
 * This function tries to calculate the compensation required to adjust measured
 * by taking into account for the time it takes for a signal to propagate from
 * the edge of the transceiver to the moment that a timestamp is taken.
 */
float get_latency_offset_ns (exanic_t* nic, int tx_port, int rx_port,
                             media_type media, float tx_cable_len,
                             float rx_cable_len)
{
    /* Constant offset to get into/out of the FPGA */
    float offset = 33;

    /* NIC specific compensation */
    switch (exanic_get_hw_type (nic))
    {
        case EXANIC_HW_X10_HPT:
            offset += get_latency_offset_htp_ns (nic, tx_port, rx_port, media,
                                                 tx_cable_len, rx_cable_len);
            break;
        default:
            break;
    }

    /* Account for cable length */
    switch (media)
    {
        case MEDIA_TYPE_FIBRE:
            offset += SR_SFP_LATENCY;
            offset += NANOS_PER_METER_FIBER * tx_cable_len;
            offset += NANOS_PER_METER_FIBER * rx_cable_len;
            break;
        case MEDIA_TYPE_AWG24:
            offset += NANOS_PER_METER_TWINAX_AWG24 * tx_cable_len;
            offset += NANOS_PER_METER_TWINAX_AWG24 * rx_cable_len;
            break;
        case MEDIA_TYPE_AWG30:
            offset += NANOS_PER_METER_TWINAX_AWG30 * tx_cable_len;
            offset += NANOS_PER_METER_TWINAX_AWG30 * rx_cable_len;
            break;
        case MEDIA_TYPE_UNKNOWN:
            /* Can't get here ? */
            break;
    }

    return offset;
}

int main (int argc, char *argv[])
{
    exanic_t *nic;
    exanic_tx_t *tx;
    exanic_rx_t *rx;
    exanic_cycles32_t old_start, start, end;
    double *stats;
    char rx_buffer[RX_BUFFER_SIZE];
    char *data;
    ssize_t size;
    FILE *savefp = NULL;
    int err = 0;
    int cable_est = 0;
    int raw = 0;

    /* Configure sensible defaults */
    const char *device = NULL;
    const char *savefile = NULL;
    int tx_port = 0;
    int rx_port = 0;
    float tx_cable_len = 0;
    float rx_cable_len = 0;
    int timeout_ns = 100 * 1000; /* 10us */
    media_type tx_type = MEDIA_TYPE_UNKNOWN;
    media_type rx_type = MEDIA_TYPE_UNKNOWN;
    int packet_size = 64;
    int count = 1000;

    /* No args supplied */
    if (argc < 2)
    {
        goto usage_error;
    }

    int c;
    while ((c = getopt (argc, argv, "d:w:p:P:l:L:t:T:s:c:EROh")) != -1)
    {
        switch (c)
        {
            case 'd':
                device = optarg;
                break;
            case 'w':
                savefile = optarg;
                break;
            case 'p':
                tx_port = atoi (optarg);
                break;
            case 'P':
                rx_port = atoi (optarg);
                break;
            case 'l':
                tx_cable_len = atof (optarg);
                break;
            case 'L':
                rx_cable_len = atof (optarg);
                break;
            case 't':
                tx_type = parse_media_type ();
                break;
            case 'T':
                rx_type = parse_media_type ();
                break;
            case 's':
                packet_size = atoi (optarg);
                break;
            case 'c':
                count = atoi (optarg);
                break;
            case 'E':
                cable_est = 1;
                break;
            case 'R':
                raw = 1;
                break;
            default:
                goto usage_error;
        }
    }

    if (cable_est)
    {
        if (raw)
        {
            fprintf (stderr, "Error: Cannot estimate cable length in raw "
                     "mode\n\n");
            err = 1;
            goto usage_error;
        }

        if (tx_type != rx_type)
        {
            fprintf (stderr, "Error: Cannot estimate cable length for mixed "
                     "media types\n\n");
            err = 1;
            goto usage_error;
        }

        if (rx_cable_len > 0 || tx_cable_len > 0)
        {
            fprintf (stderr, "Error: Cannot estimate cable length if length "
                     "already specified\n\n");
            err = 1;
            goto usage_error;
        }

        if (tx_type == MEDIA_TYPE_UNKNOWN)
        {
            fprintf (stderr, "Error: Cannot estimate cable length without a "
                     "media type\n\n");
            err = 1;
            goto usage_error;
        }
    }
    else if (raw){
        if (rx_cable_len > 0 || tx_cable_len > 0)
        {
            fprintf (stderr, "Warning: Ignorning cable length in raw mode\n\n");
        }

        if (tx_type != MEDIA_TYPE_UNKNOWN)
        {
            fprintf (stderr, "Warning: Ignoring tx media type in raw mode\n\n");
        }
        if (rx_type != MEDIA_TYPE_UNKNOWN)
        {
            fprintf (stderr, "Warning: Ignoring rx media type in raw mode\n\n");
        }
    }
    else
    {
        if (rx_type == MEDIA_TYPE_UNKNOWN)
        {
            fprintf (stderr, "Error: RX media type required for latency "
                     "measurement\n\n");
            err = 1;
            goto usage_error;
        }

        if (tx_type == MEDIA_TYPE_UNKNOWN)
        {
            fprintf (stderr, "Error: TX media type required for latency "
                     "measurement\n\n");
            err = 1;
            goto usage_error;
        }

        if (rx_cable_len == 0)
        {
            fprintf (stderr, "Error: Cannot set RXx media type with zero cable "
                     "length\n\n");
            err = 1;
            goto usage_error;
        }

        if (tx_cable_len == 0)
        {
            fprintf (stderr, "Error: Cannot set TX media type with zero cable "
                     "length\n\n");
            err = 1;
            goto usage_error;
        }
    }

    if (savefile != NULL)
    {
        if (strcmp (savefile, "-") == 0)
            savefp = stdout;
        else
        {
            savefp = fopen (savefile, "w");
            if (!savefp)
            {
                perror (savefile);
                goto err_open_savefile;
            }
        }
    }

    int data_size = packet_size - 4;
    data = malloc (data_size);
    init_packet (data, data_size);

    nic = exanic_acquire_handle (device);
    if (!nic)
    {
        fprintf (stderr, "exanic_acquire_handle: %s\n",
                 exanic_get_last_error ());
        err = 1;
        goto err_acquire_handle;
    }

    if (exanic_get_hw_type (nic) != EXANIC_HW_X10_HPT)
    {
        fprintf (stderr, "Warning: %s is not an ExaNIC-HPT with high-res "
                 "timestamping.\n",
                 device);
    }

    rx = exanic_acquire_rx_buffer (nic, rx_port, 0);
    if (!rx)
    {
        fprintf (stderr, "exanic_acquire_rx_buffer: %s\n",
                 exanic_get_last_error ());
        err = 1;
        goto err_acquire_rx;
    }

    tx = exanic_acquire_tx_buffer (nic, tx_port, 0);
    if (!tx)
    {
        fprintf (stderr, "exanic_acquire_tx_buffer: %s\n",
                 exanic_get_last_error ());
        err = 1;
        goto err_acquire_tx;
    }

    int samples = 0;
    stats = malloc (count * sizeof(double));
    while (samples < count)
    {
        old_start = exanic_get_tx_timestamp (tx);
        exanic_transmit_frame (tx, data, data_size);

        struct timespec now;
        clock_gettime(CLOCK_REALTIME,&now);
        int64_t start_ns = now.tv_sec * 1000 * 1000 * 1000 + now.tv_nsec;
        int64_t now_ns = start_ns;
        do
        {
            /* Wait for TX frame to leave the NIC */
            start = exanic_get_tx_timestamp (tx);
            clock_gettime(CLOCK_REALTIME,&now);
            now_ns = now.tv_sec * 1000 * 1000 * 1000 + now.tv_nsec;
        }
        while (old_start == start);
        const uint64_t start_expanded = exanic_expand_timestamp (nic, start);


        clock_gettime(CLOCK_REALTIME,&now);
        start_ns = now.tv_sec * 1000 * 1000 * 1000 + now.tv_nsec;
        now_ns = start_ns;
        do
        {
            size = exanic_receive_frame (rx, rx_buffer, sizeof(rx_buffer),
                                         &end);
            clock_gettime(CLOCK_REALTIME,&now);
            now_ns = now.tv_sec * 1000 * 1000 * 1000 + now.tv_nsec;
        }
        while (size <= 0);

        const uint64_t end_expanded = exanic_expand_timestamp (nic, end);

        if (size != data_size + 4)
            fprintf (stderr, "packet %i did not match (size=%d data_size=%d)\n",
                     samples, (int) size, data_size + 4);


        if ( memcmp (rx_buffer, data, data_size) )
            fprintf (stderr, "packet %i contents has changed\n", samples);

        bump_packet_seq(data);


        const exanic_cycles_t end_expanded = exanic_expand_timestamp (nic, end);

        const exanic_cycles_t time_delta_cycles = end_expanded - start_expanded;
        struct exanic_timespecps tsps = {};
        exanic_cycles_to_timespecps (nic, time_delta_cycles, &tsps);
        const double time_delta_ns = (double) tsps.tv_psec / 1000
                + (double) tsps.tv_sec * 1000000000;

        if (raw)
        {
            stats[samples] = time_delta_ns;
        }
        else
        {
            stats[samples] = time_delta_ns
                    - get_latency_offset_ns (nic, tx_port, rx_port, rx_type,
                                             tx_cable_len, rx_cable_len);
        }
        if(samples && (samples % 100000 == 0))
        {
            printf("Taken %i samples\n", samples);
        }
        samples++;


    }

    if (savefp)
    {
        int i;
        for (i = 0; i < count; i++)
        {
            fprintf (savefp, "sample: %d, latency: %lf\n", i,
                     (double) stats[i]);
        }
    }

    qsort (stats, count, sizeof(double), compare_double);
    if (count >= 1000)
    {
        int i = 0;
        double sum = 0;
        for(i = 0; i < count; i++)
        {
            sum += stats[i];
        }
        const double average = sum / count;
        printf("Average: %.2f\n", average);


        float percentiles[11] = { 99.999, 99, 95, 90, 75, 50, 25, 10, 5, 1, 0 };
        float ordinal_rank;
        for (i = 0; i < 11; i++)
        {
            ordinal_rank = (percentiles[i] / 100 * count);
            printf ("Percentile %.2f = %.2f ns\n", percentiles[i],
                    stats[(int) ordinal_rank]);
        }
    }
    else
    {
        printf ("(Percentile breakdown only available with sample size >= "
                "1000)\n");
        printf ("min = %.2fns, median = %.2fns, max = %.2fns\n", stats[0],
                stats[count / 2], stats[count - 1]);
    }

    if (cable_est)
    {
        switch (tx_type)
        {
            case MEDIA_TYPE_FIBRE:
            {
                float length = (float) stats[count / 2] / NANOS_PER_METER_FIBER;
                printf ("\nFiber length estimated to be %.2fm\n", length);
                break;
            }
            case MEDIA_TYPE_AWG24:
            {
                float length = (float) stats[count / 2] /
                NANOS_PER_METER_TWINAX_AWG24;
                printf ("Twinax length estimated to be %.2fm    (assuming AWG24"
                        " cable, typically used for 3m or less)\n",
                        length);
                break;
            }
            case MEDIA_TYPE_AWG30:
            {
                float length = (float) stats[count / 2] /
                NANOS_PER_METER_TWINAX_AWG30;
                printf ("Twinax length estimated to be %.2fm    (assuming AWG30 "
                        "cable, typically used for 3m or more)\n\n",
                        length);
                break;
            }
            case MEDIA_TYPE_UNKNOWN:
                /* Can't get here */
                break;

        }
    }

    /* Fall through to cleanup code */

    exanic_release_tx_buffer (tx);
    err_acquire_tx: exanic_release_rx_buffer (rx);
    err_acquire_rx: exanic_release_handle (nic);
    err_acquire_handle: if (savefp != NULL) fclose (savefp);
    err_open_savefile: return err;

    usage_error: fprintf (stderr, "Usage: %s -d device\n", argv[0]);
    fprintf (stderr, "           [-w fileout] [-p txport] [-P rxport] \n");
    fprintf (
            stderr,
            "           [-l txcablelen] [-L rxcablelen] [-t txmedia] [-T rxmedia] \n");
    fprintf (
            stderr,
            "           [-s packetsize] [-c count] [-E estlen] [-X nocomp] [-h] \n");
    fprintf (stderr, "  -d: specify the exanic device name (e.g. exanic0)\n");
    fprintf (stderr, "  -w: dump raw results to given file (- for stdout)\n");
    fprintf (stderr, "  -p -P: TX/RX port on the exanic (default 0/0)\n");
    fprintf (
            stderr,
            "  -l -L: TX/RX cable length in meters (e.g. 1.2) (default 0/0)\n");
    fprintf (
            stderr,
            "  -t -T: TX/RX media type. Valid values are [fibre|awg24|awg30]\n");
    fprintf (stderr, "  -s: packet size in bytes (e.g. 64) (default 64)\n");
    fprintf (stderr, "  -c: number of packets to send (default 1000)\n");
    fprintf (stderr,
             "  -E: estimate the length of fibre attached to the device\n");
    fprintf (stderr, "  -R: report raw values from the capture.\n");
    fprintf (stderr, "  -h: print this usage information\n\n");
    return 1;
}
