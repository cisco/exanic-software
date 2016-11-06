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

const char * vlan_match_method_to_str(int vlan_match_method)
{
    switch (vlan_match_method)
    {
        case EXANIC_VLAN_MATCH_METHOD_ALL:      
                    return "EXANIC_VLAN_MATCH_METHOD_ALL";
        case EXANIC_VLAN_MATCH_METHOD_SPECIFIC: 
                    return "EXANIC_VLAN_MATCH_METHOD_SPECIFIC";
        case EXANIC_VLAN_MATCH_METHOD_NOT_VLAN: 
                    return "EXANIC_VLAN_MATCH_METHOD_NOT_VLAN";
        case EXANIC_VLAN_MATCH_METHOD_ALL_VLAN: 
                    return "EXANIC_VLAN_MATCH_METHOD_ALL_VLAN";
        default: return "Invalid.";
    }
}

int main(int argc, char *argv[])
{
    exanic_t *exanic;
    exanic_rx_t *rx; 
    exanic_mac_filter_t filter;
    int my_filter;
    int stop = 0;
    char device[16];
    int port_number;
    char buf[1500];
    int size;
    time_t cur_time, last_time;
    int matched_frames = 0, error_frames = 0;
    int verbose = 0;

    if (argc == 7 && !strcmp("--verbose", argv[1]) )
        verbose = 1;
    else if (argc == 6 && strcmp("--verbose", argv[1]))
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
        fprintf(stderr, "%s: %s\n", device, "Couldn't alloc RX buffer.");
        return -1;
    }
    
    if (sscanf(argv[2+verbose], "%2hhx:%2hhx:%2hhx:%2hhx:%2hhx:%2hhx",
        &filter.dst_mac[0], &filter.dst_mac[1], &filter.dst_mac[2], 
        &filter.dst_mac[3], &filter.dst_mac[4], &filter.dst_mac[5])
        != 6)
        memset(filter.dst_mac, 0x00, sizeof(filter.dst_mac));

    sscanf(argv[3+verbose], "%hx", &filter.ethertype);
    filter.ethertype = htons(filter.ethertype);
    filter.vlan = strtoul(argv[4+verbose], NULL, 0);
    filter.vlan_match_method = strtoul(argv[5+verbose], NULL, 0);

    if (filter.vlan_match_method > EXANIC_VLAN_MATCH_METHOD_ALL_VLAN)
    {
        fprintf(stderr, "%s: %s\n", device, "Bad VLAN match method.");
        return -1;
    }

    printf("Setting up MAC RX filter with parameters:\n");
    printf("    device:             %s:%d\n", device, port_number);
    printf("    buffer id:          %d\n",  rx->buffer_number);
    printf("    dst_mac:            %02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx\n",
                 filter.dst_mac[0], filter.dst_mac[1], filter.dst_mac[2], 
                 filter.dst_mac[3], filter.dst_mac[4], filter.dst_mac[5]);
    printf("    ethertype:          0x%04x\n", ntohs(filter.ethertype));
    printf("    vlan:               %d\n", filter.vlan);
    printf("    vlan_match_method:  %s\n", 
                            vlan_match_method_to_str(filter.vlan_match_method));

    /**
     * Bind the filter to the buffer we acquired earlier.
     * You can point an arbitrary number of filters to a specific buffer by 
     * calling this function many times.
     */
    my_filter = exanic_filter_add_mac(exanic, rx, &filter);

    if (my_filter == -1)
    {
        fprintf(stderr, "%s: %s\n", device, exanic_get_last_error());
        return -1;
    }
    printf("Inserted MAC RX filter, ID number %d.\n", my_filter);

    last_time = time(NULL);

    while (!stop)
    {
        cur_time = time(NULL);
        size = exanic_receive_frame(rx, buf, sizeof(buf), NULL);
        if (size > 0)
        {
            matched_frames++;
            if (verbose)
            {
                printf("Frame matched filter:\n");
                print_escape(stdout, buf, size);
            }
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
    printf("Usage: %s [--verbose] <device:port> <dst_mac> <ethertype> <vlan> <vlan_match_method>\n", argv[0]);
    printf("        Eg (very specific):  %s --verbose exanic0:0 64:3f:5f:01:1a:b4 0800 15 1\n", argv[0]);
    printf("        Eg (disregard vlan): %s --verbose exanic0:0 64:3f:5f:01:1a:b4 0800 0 0\n", argv[0]);
    printf("        Eg (all IP traffic): %s --verbose exanic0:0 0 0800 0 0\n", argv[0]);
    printf("        VLAN Match Method:\n");
    printf("            0:  ALL - get all frames regardless of VLAN tagging (ignore tag).\n");
    printf("            1:  SPECIFIC - get only frames destined for specific VLAN.\n");
    printf("            2:  NOT_VLAN - get only frames that are not VLAN tagged.\n");
    printf("            3:  ALL_VLAN - get only frames that have a VLAN tag (ignore VLAN id).\n");
    return -1;
}
