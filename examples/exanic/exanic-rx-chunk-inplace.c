/* 
 * A demonstration of the exanic_receive_chunk_inplace() function. This demo
 * tests the ability of the host to receive chunks/frames and reports the speed
 * at which they are received.
 */

#include <stdio.h>
#include <time.h>

#include <exanic/exanic.h>
#include <exanic/fifo_rx.h>

typedef struct
{
    double errors;
    double frags;
    double frames;
    double swovfls;
    double bytes;
    double loops;
} stats_t;

static stats_t stats_prev = {0};

static inline stats_t stats_subtract(stats_t* lhs, stats_t* rhs)
{
    stats_t result = {0};
    result.errors    = lhs->errors    - rhs->errors;
    result.frags     = lhs->frags     - rhs->frags;
    result.frames    = lhs->frames    - rhs->frames;
    result.swovfls   = lhs->swovfls   - rhs->swovfls;
    result.bytes     = lhs->bytes  - rhs->bytes;
    result.loops     = lhs->loops   - rhs->loops;
    return result;
}

static inline stats_t stats_div(stats_t* lhs, double div)
{
    stats_t result = {0};
    result.errors    = lhs->errors    / div;
    result.frags     = lhs->frags     / div;
    result.frames    = lhs->frames    / div;
    result.swovfls   = lhs->swovfls   / div;
    result.bytes     = lhs->bytes     / div;
    result.loops     = lhs->loops     / div;
    return result;
}

static inline void do_stats(stats_t* stats, int64_t timenow_ns, 
    int64_t timedelta_ns)
{
    if (stats_prev.loops == 0)
        stats_prev = *stats;

    stats_t delta = stats_subtract(stats, &stats_prev);
    stats_t rates = stats_div(&delta, timedelta_ns / 1000);

    printf("%li - frames: %.0lf (%.3lfMpps), frags: %.0lf (%.3lfMfrg/s), bytes:"
           " %.0lf (%.3lfMB/s), errors: %.0lf, swovfls: %.0lf\n",
           timenow_ns,
           stats->frames,rates.frames,
           stats->frags, rates.frags,
           stats->bytes, rates.bytes,
           stats->errors,
           stats->swovfls);

    stats_prev = *stats;
}

static inline int64_t timenow_ns()
{
    struct timespec now_ts = {0};
    clock_gettime(CLOCK_REALTIME, &now_ts);
    return now_ts.tv_sec * 1000ULL * 1000 * 1000 + now_ts.tv_nsec;
}


int main(int argc, char *argv[])
{
    exanic_t *nic;
    exanic_rx_t *rx;
    const char *device;
    int rx_port;
    ssize_t size;

    if (argc < 3)
    {
        fprintf(stderr, "%s:\n", argv[0]);
        fprintf(stderr, "  usage: %s device rx_port\n", argv[0]);
        return 1;
    }

    device = argv[1];
    rx_port = atoi(argv[2]);

    nic = exanic_acquire_handle(device);
    if (!nic)
    {
        fprintf(stderr, "exanic_acquire_handle: %s\n", exanic_get_last_error());
        return 1;
    }

    rx = exanic_acquire_rx_buffer(nic, rx_port, 0);
    if (!rx)
    {
        fprintf(stderr, "exanic_acquire_rx_buffer: %s\n", 
            exanic_get_last_error());
        return 1;
    }

    char* rx_buff_ptr = NULL;
    uint32_t chunk_id = -1;
    int more_chunks = 0;
    struct rx_chunk_info info = {0};

    stats_t stats_total = {0};

    uint64_t now_ns = 0;
    uint64_t timestart_ns = timenow_ns();
    const int64_t timeout_ns = 1000ULL * 1000 * 1000; /* 1 second timeout */
    int64_t stats_relax = 0;

    while (1)
    {
            stats_total.loops++;
            size = exanic_receive_chunk_inplace_ex (rx, &rx_buff_ptr, &chunk_id,
                                                    &more_chunks, &info);

            if (size > 0)
            {
                /* Got a valid fragment */
                stats_total.frags++;
                stats_total.bytes += size;
                if (!more_chunks)
                    stats_total.frames++;
            }
            else if (size < 0)
            {
                /* Error occurred */
                if (size == -EXANIC_RX_FRAME_SWOVFL)
                    stats_total.swovfls++;
                else
                    stats_total.errors++;
            }

            /* Try not to check the time too often */
            stats_relax++;
            if (stats_relax > 1000 * 1000)
            {
                stats_relax = 0;
                now_ns = timenow_ns();

                if (now_ns > timestart_ns + timeout_ns)
                {
                    do_stats(&stats_total, now_ns, timeout_ns);
                    timestart_ns = now_ns;
                }
            }
    }
    return 0;
}

