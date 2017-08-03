/** 
 * Filtering demo showing how to grab traffic that matches an arbitrary rule
 * into a buffer.
 */
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include <exanic/fifo_rx.h>
#include <exanic/fifo_tx.h>
#include <exanic/filter.h>
#include <exanic/exanic.h>
#include <unistd.h>
#include "filter-common.h"
#include <time.h>

int main(int argc, char *argv[])
{
    exanic_t *exanic;
    exanic_rx_t *rx; 
    exanic_ip_filter_t filter;
    int my_filter;
    struct in_addr src_addr, dst_addr;
    int stop = 0;
    char device[16];
    int port_number;
    char buf[1550];
    int size;
    time_t cur_time, last_time;
    int matched_frames = 0, error_frames = 0;
    int verbose = 0;

    if (argc == 8 && !strcmp("--verbose", argv[1]) )
        verbose = 1;
    else if (argc == 7 && strcmp("--verbose", argv[1]))
        verbose = 0;
    else
        goto usage_error;
    
    if (parse_device_port(argv[1+verbose], device, &port_number) == -1)
    {
        fprintf(stderr, "Bad device/port.\n");
        goto usage_error;
    }

    if ((exanic = exanic_acquire_handle(device)) == NULL)
    {
        fprintf(stderr, "%s: %s\n", device, exanic_get_last_error());
        return -1;
    }

    /* Acquire an unused filter buffer.
     * Other applications can listen on this buffer by calling 
     * exanic_acquire_rx_buffer and passing in the rx->buffer_number
     */
    rx = exanic_acquire_unused_filter_buffer(exanic, port_number);
    if (rx == NULL)
    {
        fprintf(stderr, "%s: %s\n", device, exanic_get_last_error());
        fprintf(stderr, "%s: %s\n", device, "Couldn't allocate filter.");
        return -1;
    }

    if (inet_aton(argv[2+verbose], &src_addr) == 0)
    {
        printf("Invalid src_ip.\n");
        return -1;
    }

    if (inet_aton(argv[4+verbose], &dst_addr) == 0)
    {
        printf("Invalid dst_ip.\n");
        return -1;
    }

    filter.src_addr = src_addr.s_addr;
    filter.dst_addr = dst_addr.s_addr;
    filter.src_port = htons(atoi(argv[3+verbose]));
    filter.dst_port = htons(atoi(argv[5+verbose])); 
    filter.protocol = atoi(argv[6+verbose]);

    printf("Setting up RX filter with parameters:\n");
    printf("    device:     %s:%d\n", device, port_number);
    printf("    buffer id:  %d\n",  rx->buffer_number);
    printf("    src_ip:     %s\n", argv[2+verbose]);
    printf("    src_port:   %d\n", ntohs(filter.src_port));
    printf("    dst_ip:     %s\n", argv[4+verbose]);
    printf("    dst_port:   %d\n", ntohs(filter.dst_port));
    printf("    protocol:   %d\n", filter.protocol);

    /**
     * Bind the filter to the buffer we acquired earlier.
     * You can point an arbitrary number of filters to a specific buffer by 
     * calling this function many times.
     */
    my_filter = exanic_filter_add_ip(exanic, rx, &filter);

    if (my_filter == -1)
    {
        fprintf(stderr, "%s: %s\n", device, exanic_get_last_error());
        return -1;
    }
    printf("Inserted IP RX filter, ID number %d.\n", my_filter);

    last_time = time(NULL);

    while (!stop)
    {
        cur_time = time(NULL);
        size = exanic_receive_frame(rx, buf, sizeof(buf), NULL);
        if (size > 0)
        {
            if (verbose)
            {
                printf("Frame matched filter:\n");
                print_escape(stdout, buf, size);
            }
            matched_frames++;
        }
        else if (size < 0)
        {   
            if (verbose)
                printf("Receive error: %d.\n", size);
            error_frames++;
        }
    
        if (last_time != cur_time)
        {   
            last_time = cur_time;
            if (!verbose)
                printf("Matching frames %d, errors %d\n",
                                    matched_frames, error_frames);
        }
    }

    exanic_release_rx_buffer(rx);
    exanic_release_handle(exanic);
    return 0;

    usage_error:
    printf("Usage: %s [--verbose] <device:port> <src_ip> <src_port> <dst_ip> <dst_port> <protocol>\n", argv[0]);
    printf("        Eg (very specific):   %s --verbose exanic0:0 192.168.1.1 80 192.168.1.4 60 6\n", argv[0]);
    printf("        Eg (TCP, dest only):  %s --verbose exanic0:0 0 0 192.168.1.4 60 6\n", argv[0]);
    printf("        Eg (all UDP traffic): %s --verbose exanic0:0 0 0 0 0 17\n", argv[0]);
    printf("        Set field to 0 for wildcard match.\n");
    printf("        Common protocols:\n");
    printf("            6:  TCP\n");
    printf("            17: UDP\n");
    return -1;
}
