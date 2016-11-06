#include <stdio.h>
#include <string.h>
#include <sys/time.h>

#include <exanic/exanic.h>
#include <exanic/pcie_if.h>
#include <exanic/register.h>
#include <exanic/time.h>

/* Emit warning if difference is greater than 100ms */
#define MAX_HOST_DELTA_NS 100000000

/* Emit warning if exanic differs by more than 500us */
#define MAX_EXANIC_DELTA_NS 500000

/* Spin until the next microsecond boundary */
void gettimeofday_spin(struct timeval *tv)
{
    struct timeval t;
    gettimeofday(&t, NULL);
    do
        gettimeofday(tv, NULL);
    while (t.tv_sec == tv->tv_sec && t.tv_usec == tv->tv_usec);
}

int main(int argc, char *argv[])
{
    char *device0, *device1;

    if (argc == 2)
    {
        device0 = argv[1];
        device1 = NULL;
    }
    else if (argc == 3)
    {
        device0 = argv[1];
        device1 = argv[2];
    }
    else
        goto usage_error;

    if (device1 == NULL)
    {
        /* Compare to host clock */
        exanic_t *exanic;
        uint32_t exanic_tick;
        uint64_t exanic_time_ns;
        uint64_t host_time_us;
        int64_t time_diff_ns;
        struct timeval tv;

        if ((exanic = exanic_acquire_handle(device0)) == NULL)
        {
            fprintf(stderr, "%s: %s\n", device0, exanic_get_last_error());
            return 1;
        }

        gettimeofday_spin(&tv);
        exanic_tick = exanic_register_read(exanic, REG_EXANIC_HW_TIME);
        exanic_time_ns = exanic_timestamp_to_counter(exanic, exanic_tick);
        host_time_us = tv.tv_sec * 1000000 + tv.tv_usec;
        time_diff_ns = exanic_time_ns - host_time_us * 1000;

        printf("Device %s: %u ticks (%lu ns since epoch)\n",
                device0, exanic_tick, exanic_time_ns);
        printf("Host clock: %lu us since epoch\n", host_time_us);
        printf("Difference: %ld ns\n", time_diff_ns);

        exanic_release_handle(exanic);
        return 0;
    }
    else
    {
        /* Compare to exanic clock */
        exanic_t *exanic0, *exanic1;
        uint32_t exanic0_tick, exanic0_tock, exanic1_tick, exanic1_tock;
        uint64_t exanic0_time_ns, exanic1_time_ns;
        int64_t time_diff_ns;

        if ((exanic0 = exanic_acquire_handle(device0)) == NULL)
        {
            fprintf(stderr, "%s: %s\n", device0, exanic_get_last_error());
            return 1;
        }

        if ((exanic1 = exanic_acquire_handle(device1)) == NULL)
        {
            fprintf(stderr, "%s: %s\n", device1, exanic_get_last_error());
            exanic_release_handle(exanic0);
            return 1;
        }

        /* Read twice in different order to cancel out latency */
        exanic0_tick = exanic_register_read(exanic0, REG_EXANIC_HW_TIME);
        exanic1_tick = exanic_register_read(exanic1, REG_EXANIC_HW_TIME);
        exanic1_tock = exanic_register_read(exanic1, REG_EXANIC_HW_TIME);
        exanic0_tock = exanic_register_read(exanic0, REG_EXANIC_HW_TIME);
        exanic0_tick += (exanic0_tock - exanic0_tick) / 2;
        exanic1_tick += (exanic1_tock - exanic1_tick) / 2;
        exanic0_time_ns = exanic_timestamp_to_counter(exanic0, exanic0_tick);
        exanic1_time_ns = exanic_timestamp_to_counter(exanic1, exanic1_tick);
        time_diff_ns = exanic0_time_ns - exanic1_time_ns;

        printf("Device %s: %u ticks (%lu ns since epoch)\n",
                device0, exanic0_tick, exanic0_time_ns);
        printf("Device %s: %u ticks (%lu ns since epoch)\n",
                device1, exanic1_tick, exanic1_time_ns);
        printf("Difference: %ld ns\n", time_diff_ns);

        exanic_release_handle(exanic0);
        exanic_release_handle(exanic1);
        return 0;
    }

usage_error:
    fprintf(stderr, "Usage: %s <exanic> [<exanic>]\n\n"
            "Compares the exanic clock to the host or another exanic.\n",
            argv[0]);
    return 1;
}
