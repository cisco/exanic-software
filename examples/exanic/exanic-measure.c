/*
 * This is an example of a measurement application written primarily for
 * use with ExaNIC HPT (though it can be used with other devices such as the
 * ExaNIC X10/X25/X40/X100).
 *
 * The application is intended to be used to benchmark external devices with
 * high precision. To use the application:
 * 1. First measure a device of zero latency (e.g. an optical coupler).
 *    This will give a calibration estimate of the "offset" including cabling
 *    delays and internal NIC delays. The "average" number reported is the
 *    result.
 * 2. Then replace the optical coupler with the device that has an unknown
 *        latency (using the same cables as in step 1) and apply the -O offset
 *        parameter, with the measurement from step 1. Your result will now be high
 *        precision, compensated for cabling delays and NIC internal delays.
 */

#include <stdio.h>
#include <string.h>
#include <time.h>
#include <getopt.h>
#include <linux/ethtool.h>
#include <time.h>

#include <exanic/exanic.h>
#include <exanic/fifo_tx.h>
#include <exanic/fifo_rx.h>
#include <exanic/register.h>
#include <exanic/time.h>
#include <exanic/util.h>

#include "util.h"

#define RX_BUFFER_SIZE 2048

typedef struct {
    uint64_t seq_num;
    uint64_t tx_cpu_ns;
    uint64_t tx_nic_ns;
    uint64_t rx_nic_ns;
    uint64_t rx_cpu_ns;

    double latency;
    uint64_t cpu_delay_ns;
} sample;

static int compare_sample (const void *a, const void *b)
{
    const sample* as = (const sample*) a;
    const sample* bs = (const sample*) b;

    return (as->latency > bs->latency) -
        (as->latency < bs->latency);
}

static inline void init_packet (char *data, int data_size)
{
    int i;
    for (i = 0; i < data_size; i++)
        data[i] = i + 'a';

    if (data_size < 6)
    {
        fprintf(stderr, "packet too short\n");
        return;
    }
    /* dest addr = broadcast */
    memset(data, 0xff, 6);
    memset(data + 6, 0xaa, 6);
    memset(data + 12, 0xCC, 2);
    *(uint64_t*)(data + 14) = 0;
}

static inline uint64_t get_frame_seq (char *data)
{
    return (*(uint64_t*)(data + 14));
}


static inline void bump_frame_seq (char *data)
{
    (*(uint64_t*)(data + 14))++;
}

static inline int64_t timenow_ns()
{
    struct timespec now = {0};
    clock_gettime(CLOCK_REALTIME,&now);
    return now.tv_nsec + now.tv_sec * 1000 * 1000 *1000;
}

int main (int argc, char *argv[])
{
    exanic_t *nic;
    exanic_tx_t *tx;
    exanic_rx_t *rx;
    sample *stats;
    char rx_buffer[RX_BUFFER_SIZE];
    char *data;
    ssize_t size;
    FILE *savefp = NULL;
    int c, data_size, samples, err = 0;

    /* Configure sensible defaults */
    const char *device = NULL;
    const char *savefile = NULL;
    int tx_port = 0;
    int rx_port = 0;
    int packet_size = 64;
    int count = 1000;
    int integrity_check = 0;
    int64_t drop_timeout_ns = 0;
    int tx_only = 0;
    int rx_only = 0;

    float offset = 0;

    /* No args supplied */
    if (argc < 2)
        goto usage_error;

    while ((c = getopt(argc, argv, "d:w:t:r:s:c:O:hID:TR")) != -1)
    {
        switch (c)
        {
        case 'd':
            device = optarg;
            break;
        case 'w':
            savefile = optarg;
            break;
        case 't':
            tx_port = atoi(optarg);
            break;
        case 'r':
            rx_port = atoi(optarg);
            break;
        case 's':
            packet_size = atoi(optarg);
            break;
        case 'c':
            count = atoi(optarg);
            break;
        case 'O':
            offset = atof(optarg);
            break;
        case 'I':
            integrity_check = 1;
            break;
        case 'D':
            drop_timeout_ns = atoll(optarg);
            break;
        case 'T':
            tx_only = 1;
            break;
        case 'R':
            rx_only = 1;
            break;
        default:
            goto usage_error;
        }
    }

    if (tx_only && rx_only)
    {
        fprintf(stderr, "Error: TX Only and RX Only flags are mutually exclusive\n");
        exit(1);
    }


    if (savefile != NULL)
    {
        if (strcmp(savefile, "-") == 0)
            savefp = stdout;
        else
        {
            savefp = fopen(savefile, "w");
            if (!savefp)
            {
                perror(savefile);
                goto err_open_savefile;
            }
        }
    }

    data_size = packet_size - 4;
    data = malloc(data_size);
    init_packet(data, data_size);

    nic = exanic_acquire_handle(device);
    if (!nic)
    {
        fprintf(stderr, "exanic_acquire_handle: %s\n",
                 exanic_get_last_error());
        err = 1;
        goto err_acquire_handle;
    }

    rx = exanic_acquire_rx_buffer(nic, rx_port, 0);
    if (!rx)
    {
        fprintf(stderr, "exanic_acquire_rx_buffer: %s\n",
                 exanic_get_last_error());
        err = 1;
        goto err_acquire_rx;
    }

    tx = exanic_acquire_tx_buffer(nic, tx_port, 0);
    if (!tx)
    {
        fprintf(stderr, "exanic_acquire_tx_buffer: %s\n",
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
        fprintf(stderr, "Error: %s:%i must be in bypass only mode to proceed\n",
                 device, tx_port);
        goto err_bypass;
    }

    samples = 0;
    stats = (sample*) calloc(count, sizeof(sample));
    while (samples < count)
    {
        exanic_cycles32_t old_start, start, end;
        exanic_cycles_t start_expanded = 0;
        exanic_cycles_t end_expanded = 0;
        exanic_cycles_t time_delta_cycles = 0;
        struct exanic_timespecps tsps;
        double time_delta_ns = 0;
        int64_t now_cpu_ns = 0;
        int64_t tx_cpus_ns = 0;
        int64_t rx_stop_cpu_ns = 0;
        int64_t rx_start_cpu_ns = 0;

    send_frame:
        if(!rx_only)
        {
            tx_cpus_ns = timenow_ns();
            old_start = exanic_get_tx_timestamp(tx);
            exanic_transmit_frame(tx, data, data_size);
            do
            {
                /* Wait for TX frame to leave the NIC */
                start = exanic_get_tx_timestamp(tx);
            }
            while (old_start == start);
            start_expanded = exanic_expand_timestamp(nic, start);
        }

        if(!tx_only)
        {
            size = -1;
            rx_start_cpu_ns = timenow_ns();
            for(int i = 0; size <= 0; i++ )
            {
                /* Wait for RX frame to arive at the NIC */
                size = exanic_receive_frame(rx, rx_buffer, sizeof(rx_buffer),
                                             &end);

                /*
                 * This little routine slows down the rate at which we check the
                 * time just to ease load on the CPU
                 */
                if(drop_timeout_ns > 0 && i > 1000 * 1000)
                {
                    now_cpu_ns = timenow_ns();
                    if (now_cpu_ns > rx_start_cpu_ns + drop_timeout_ns)
                    {
                        fprintf(stderr,"Warning: Dropped frame with sequence number %li",
                                get_frame_seq(data));
                        bump_frame_seq(data);
                        goto send_frame;
                    }

                    i = 0;
                }
            }

            rx_stop_cpu_ns = timenow_ns();

            if(integrity_check)
            {
                if (size != data_size + 4)
                    fprintf(stderr, "Warning packet %li did not match (size=%d data_size=%d)\n",
                             get_frame_seq(data), (int) size, data_size + 4);

                if (memcmp(rx_buffer, data, data_size))
                    fprintf(stderr, "packet %li contents has changed\n",
                             get_frame_seq(data));
            }
        }

        bump_frame_seq(data);

        end_expanded = exanic_expand_timestamp(nic, end);
        time_delta_cycles = end_expanded - start_expanded;
        exanic_cycles_to_timespecps(nic, time_delta_cycles, &tsps);
        time_delta_ns = (double) tsps.tv_psec / 1000
            + (double) tsps.tv_sec * 1000000000;

        stats[samples].seq_num   = get_frame_seq(data);
        stats[samples].tx_cpu_ns = tx_cpus_ns;
        stats[samples].tx_nic_ns = exanic_cycles_to_ns(nic,start_expanded);
        stats[samples].rx_nic_ns = exanic_cycles_to_ns(nic,end_expanded);
        stats[samples].rx_cpu_ns = rx_stop_cpu_ns;

        stats[samples].latency = time_delta_ns - offset;
        stats[samples].cpu_delay_ns = rx_stop_cpu_ns - tx_cpus_ns;

        if(samples && (samples % 100000 == 0))
        {
            printf("Taken %i samples\n", samples);
        }
        samples++;
    }

    if (savefp)
    {
        fprintf (savefp, "Sample, Latency, Sequence, CPU_DELAY_NS, TX_NIC_NS, RX_NIC_NS, TX_CPU_NS, RX_CPU_NS\n");
        int i;
        for (i = 0; i < count; i++)
        {
            fprintf (savefp, "%i, %0.2lf, %li, %li, %li, %li, %li, %li\n",
                     i,
                     stats[i].latency,
                     stats[i].seq_num,
                     stats[i].cpu_delay_ns,
                     stats[i].tx_nic_ns,
                     stats[i].rx_nic_ns,
                     stats[i].tx_cpu_ns,
                     stats[i].rx_cpu_ns
                );
        }
    }

    if (!(tx_only || rx_only))
    {
        qsort(stats, count, sizeof(sample), compare_sample);
        if (count >= 1000)
        {
            int i = 0;
            double sum = 0, average;
            float percentiles[11] = { 99.999, 99, 95, 90, 75, 50, 25, 10, 5, 1, 0 };

            for(i = 0; i < count; i++)
                sum += stats[i].latency;
            average = sum / count;
            printf("Average: %.2f\n", average);

            for (i = 0; i < 11; i++)
            {
                float ordinal_rank = (percentiles[i] / 100 * count);
                printf ("Percentile %.2lf = %.2lf ns\n", percentiles[i],
                        stats[(int) ordinal_rank].latency);
            }
        }
        else
        {
            printf ("(Percentile breakdown only available with sample size >= "
                    "1000)\n");
            printf ("min = %.2fns, median = %.2fns, max = %.2fns\n",
                    stats[0].latency,
                    stats[count / 2].latency,
                    stats[count - 1].latency);
        }
    }

    /* Fall through to cleanup code */
err_bypass:
    exanic_release_tx_buffer(tx);
err_acquire_tx:
    exanic_release_rx_buffer(rx);
err_acquire_rx:
    exanic_release_handle(nic);
err_acquire_handle:
    if (savefp != NULL) fclose(savefp);
err_open_savefile: return err;

usage_error:
    fprintf (stderr, "Usage: %s -d device -t txport -r rxport\n", argv[0]);
    fprintf (stderr, "           [-w fileout] [-s packetsize] [-c count] \n");
    fprintf (stderr, "           [-O offset] [-D droptimeout] [-I] [-T] [-R]\n");
    fprintf (stderr, "  -d: Specify the exanic device name (e.g. exanic0)\n");
    fprintf (stderr, "  -t: TX port on the exanic (default 0)\n");
    fprintf (stderr, "  -r: RX port on the exanic (default 0)\n");
    fprintf (stderr, "  -w: Dump sample to given file (- for stdout)\n");
    fprintf (stderr, "  -s: TX packet size in bytes (e.g. 64) (default 64)\n");
    fprintf (stderr, "  -c: Number of packets to send (default 1000)\n");
    fprintf (stderr, "  -O: Apply a fixed nanosecond offset to measurements\n");
    fprintf (stderr, "  -D: Nanoseconds to wait before assuming fame is dropped\n");
    fprintf (stderr, "  -I: Check packet integrity (packets are unchanged)\n");
    fprintf (stderr, "  -T: Transmit only. Do not try to receive\n");
    fprintf (stderr, "  -R: Receive only. Do not try to transmit\n");
    fprintf (stderr, "  -h: Print this usage information\n\n");
    return 1;
}
