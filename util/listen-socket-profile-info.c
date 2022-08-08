#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <arpa/inet.h>
#include <getopt.h>
#include <fcntl.h>
#include <errno.h>
#include <signal.h>
#include <sched.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <malloc.h>
#include <unistd.h>
#include <assert.h>


#include "exasock/kernel/structs.h"
#include "exasock/kernel/api.h"
#include "exasock/lock.h"

#define EXASOCK_DEVICE "/dev/exasock"
#define NUM_PERCENTILES 11


struct listen_socket_profile_info* profile_info_kernel_ptr;
uint32_t current_profiler_index = 0;
uint32_t registered;
struct tcp_socket_profile* connections_profile_ptr;
uint32_t allocated;
uint32_t slots_remaining;
uint32_t current_slot;

enum
{
    PENDING_PERIOD_PERCENTILE,
    ACCEPT_PERIOD_PERCENTILE,
    ESTABLISHMENT_PERIOD_PERCENTILE
};



static int compare_period_samples (const void *a, const void *b);

const char* period_types_strings[] =
{
        "PENDING_PERIOD",
        "ACCEPT_PERIOD",
        "ESTABLISHMENT_PERIOD"
};

const char *tcp_state_strings[EXA_TCP_TIME_WAIT + 1] =
{
    "EXA_TCP_CLOSED",
    "EXA_TCP_LISTEN",
    "EXA_TCP_SYN_SENT",
    "EXA_TCP_SYN_RCVD",
    "EXA_TCP_ESTABLISHED",
    "EXA_TCP_CLOSE_WAIT",
    "EXA_TCP_FIN_WAIT_1",
    "EXA_TCP_FIN_WAIT_2",
    "EXA_TCP_CLOSING",
    "EXA_TCP_LAST_ACK",
    "EXA_TCP_TIME_WAIT",
};



static int compare_period_samples (const void *a, const void *b)
{
    const long int * left = (const long int* )a;
    const long int * right = (const long int* )b;

    return *left - *right;
}

void measure_period_percentile(int measurement_type, struct tcp_socket_profile* conn_info_ptr, int size)
{
    double sum = 0, average;
    int i = 0;
    long int* data_ptr = NULL;
    static const float percentiles[NUM_PERCENTILES] = { 99.999, 99, 95, 90, 75, 50, 25, 10, 5, 1, 0 };

    data_ptr = (long int*)malloc(sizeof(long int) * size);
    if (data_ptr == NULL)
    {
        printf("malloc error\n");
        return;
    }
    for (i = 0; i < size; i++)
    {
        switch(measurement_type)
        {
        case PENDING_PERIOD_PERCENTILE:
            data_ptr[i] = conn_info_ptr[i].pending_period.tv_nsec / 1000;
            if (data_ptr[i] == 999999)
                printf("%lu\n", conn_info_ptr[i].pending_period.tv_nsec);
            break;

        case ACCEPT_PERIOD_PERCENTILE:
            data_ptr[i] = conn_info_ptr[i].accept_period.tv_nsec / 1000;
            break;

        case ESTABLISHMENT_PERIOD_PERCENTILE:
            data_ptr[i] = conn_info_ptr[i].establishment_period.tv_nsec / 1000;
            break;
        default:
            printf("unknown period type\n");
            return;
            break;
        }
    }

    qsort(data_ptr, size, sizeof(long int), compare_period_samples);

    /* Calculate average */
    for (i = 0 ; i < size; i++)
        sum += data_ptr[i];
    average = sum / size;
    printf("Average for %s = %.2lf us\n", period_types_strings[measurement_type], average);

    /* Calculate percentile */
    printf("Percentiles for %s\n", period_types_strings[measurement_type]);
    for (i = 0; i < NUM_PERCENTILES; i++)
    {
        float ordinal_rank = (percentiles[i] / 100 * size);
        printf("[%.2lf] %lu us\n", percentiles[i], data_ptr[(int)ordinal_rank]);
    }

    free(data_ptr);
}

void collect_profile_info()
{
    printf("total num conns = %d\n", current_profiler_index);
    
    measure_period_percentile(PENDING_PERIOD_PERCENTILE, connections_profile_ptr, current_profiler_index);
    measure_period_percentile(ACCEPT_PERIOD_PERCENTILE, connections_profile_ptr, current_profiler_index);
    measure_period_percentile(ESTABLISHMENT_PERIOD_PERCENTILE, connections_profile_ptr, current_profiler_index);
}


void signal_handler(int s)
{
    switch(s)
    {
        case SIGUSR1:
            printf("received SIGUSR1 signal - to store profile information\n");
            collect_profile_info();
            printf("exiting\n");
            exit(0);
            break;
    }
}

void tcp_server_profiling(int signo)
{
    int diff;
    int start_pos, end_pos;
    if (profile_info_kernel_ptr == NULL)
        return;

    if (!profile_info_kernel_ptr->index)
        return;

    diff = profile_info_kernel_ptr->index - current_profiler_index;
    if (diff > NUM_PROFILE_CONNECTIONS)
        printf("overflow, should never happen\n");

    if (connections_profile_ptr == NULL)
    {
        allocated = NUM_PROFILE_CONNECTIONS * sizeof(struct tcp_socket_profile);
        connections_profile_ptr = (struct tcp_socket_profile*) malloc(allocated);
        slots_remaining = NUM_PROFILE_CONNECTIONS;
    }

    if (slots_remaining < diff)
    {
        allocated += (NUM_PROFILE_CONNECTIONS* sizeof(struct tcp_socket_profile));
        connections_profile_ptr = realloc(connections_profile_ptr, allocated);
        slots_remaining += NUM_PROFILE_CONNECTIONS;
    }

    start_pos = current_profiler_index % NUM_PROFILE_CONNECTIONS;
    end_pos = profile_info_kernel_ptr->index % NUM_PROFILE_CONNECTIONS;
    if (start_pos > end_pos)
    {

        /* start pos is where we start copying from, end_pos is where we stop copying */
        /* copy until the end of the buffer */
        int wr_bytes = (NUM_PROFILE_CONNECTIONS - start_pos) * sizeof(struct tcp_socket_profile);
        int c = (NUM_PROFILE_CONNECTIONS - start_pos);
        memcpy(connections_profile_ptr + current_profiler_index, profile_info_kernel_ptr->conns + start_pos, wr_bytes);
        slots_remaining -= c;
        current_profiler_index += c;

        /* copy from the beginning */
        wr_bytes = end_pos * sizeof(struct tcp_socket_profile);
        memcpy(connections_profile_ptr + current_profiler_index, &profile_info_kernel_ptr->conns, wr_bytes);
        slots_remaining -= end_pos;
        current_profiler_index += end_pos;
    }
    else
    {
        /* copy between start_pos and end_pos */
        int c = (end_pos - start_pos);
        int len1 = c * sizeof(struct tcp_socket_profile);
        memcpy(connections_profile_ptr + current_profiler_index, profile_info_kernel_ptr->conns + start_pos, len1);
        slots_remaining -= c;
        current_profiler_index += c;
    }

    diff = profile_info_kernel_ptr->index - current_profiler_index;
    if (diff > NUM_PROFILE_CONNECTIONS)
    {
        printf("overflow after copying, should not happen\n");
    }
}   


void init_timer(void)
{
    struct itimerval delay;
    /* register handler for SIG ALARM signal */
    printf("initing timer\n");
    signal(SIGALRM, tcp_server_profiling);
    signal(SIGUSR1, signal_handler);

    /* set timer which will fire every 100ms */
    delay.it_value.tv_usec = 100000;
    delay.it_value.tv_sec  = 0;
    delay.it_interval.tv_usec = 100000;
    delay.it_interval.tv_sec = 0;
    setitimer(ITIMER_REAL, &delay, NULL);
}


int main(int argc, char** argv)
{
    struct in_addr a;
    struct listen_socket_profile_info* pi_ptr;
    struct exasock_listen_endpoint lep;
    uint16_t port;
    int fd;
    char* port_string;


    /* name ip:port */
    port_string = strchr(argv[1], ':');
    if (!port_string)
    {
        printf("invalid address value. format is <ip>:<port>\n");
        return -1;
    }
    *port_string  = '\0';
    port_string++;
    port = strtol(port_string, NULL, 10);
    if(!port)
    {
        printf("invalid port value\n");
        return -1;
    }

    fd = open(EXASOCK_DEVICE, O_RDWR);
    if (fd == -1)
    {
        printf("could not open " EXASOCK_DEVICE ": %s",
                 strerror(errno));
        return -1;
    }

    /* inet_aton returns in network byte order no endianness conversion needed */
    if(!inet_aton(argv[1], &a))
    {
        printf("invalid ip provided\n");
        close(fd);
        return -1;
    }

    lep.local_addr = a.s_addr;
    lep.local_port = htons(port);
    if (ioctl(fd, EXASOCK_IOCTL_LISTEN_SOCKET_PROFILE, &lep) != 0)
    {
        perror("ioctl EXASOCK_IOCTL_LISTEN_SOCKET_PROFILE failed!\n");
        close(fd);
        return -1;
    }

    pi_ptr = mmap(NULL, sizeof(struct listen_socket_profile_info), PROT_READ | PROT_WRITE, 
                  MAP_SHARED, fd, EXASOCK_OFFSET_LISTEN_SOCK_PROFILE_INFO);
    if (pi_ptr == MAP_FAILED)
    {
        printf("could not mmap info page: %s", strerror(errno));
        close(fd);
        return -1;
    }
    profile_info_kernel_ptr = pi_ptr;
    init_timer();
    for(;;)
        pause();

    close(fd);
    return 0;
}
