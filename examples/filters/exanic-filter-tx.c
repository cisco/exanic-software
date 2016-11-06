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

/** 
 * Generate a frame that will match or not match a given filter.
 */
void generate_ip_filter_frame(char *buffer, exanic_ip_filter_t filter, int match, int sequence)
{
    struct __attribute__ ((__packed__)) my_ip_frame
    {
        uint8_t dst_mac[6];
        uint8_t src_mac[6];
        uint16_t ethertype;
        uint8_t  version;
        uint8_t  dscp;
        uint16_t  ip_len;
        uint16_t ident;
        uint16_t fragment;
        uint8_t ttl;
        uint8_t protocol;
        uint16_t ip_checksum;
        uint32_t src_ip;
        uint32_t dst_ip;
        uint16_t src_port;
        uint16_t dst_port;
        uint16_t prot_len;
        uint16_t prot_checksum;
        uint8_t  payload[18];
    } *ip_frame;

    ip_frame = (struct my_ip_frame *) buffer;

    memset(ip_frame, 0x00, sizeof(struct my_ip_frame));
    ip_frame->version = 0x54;
    ip_frame->ethertype = htons(0x0800);
    memset(ip_frame->dst_mac, 0xff, 6);

    if (filter.src_addr != 0) 
    {
        if (match)
            ip_frame->src_ip = filter.src_addr;
        else
            ip_frame->src_ip = 0;
    }
            
    if (filter.dst_addr != 0) 
    {
        if (match)
            ip_frame->dst_ip = filter.dst_addr;
        else
            ip_frame->dst_ip = 0;
    }

    if (filter.src_port != 0) 
    {
        if (match)
            ip_frame->src_port = filter.src_port;
        else
            ip_frame->src_port = 0;
    }

    if (filter.dst_port != 0) 
    {
        if (match)
            ip_frame->dst_port = filter.dst_port;
        else
            ip_frame->dst_port = 0;
    }

    if (filter.protocol != 0)
    {
        if (match)
            ip_frame->protocol = filter.protocol;
        else
            ip_frame->protocol = 0;
    }

    ip_frame->payload[3] = (sequence >> 24) & 0xFF;
    ip_frame->payload[2] = (sequence >> 16) & 0xFF;
    ip_frame->payload[1] = (sequence >>  8) & 0xFF;
    ip_frame->payload[0] = (sequence >>  0) & 0xFF;
}

int main(int argc, char *argv[])
{
    exanic_t *exanic;
    exanic_ip_filter_t filter;
    exanic_tx_t *tx;
    struct in_addr src_addr, dst_addr;
    int stop = 0;
    char device[16];
    int port_number;
    char buf[1500];
    int sequence = 0, last_sequence = 0;
    time_t cur_time, last_time;

    if (argc != 7)
        goto usage_error;

    if (parse_device_port(argv[1], device, &port_number) == -1)
    {
        fprintf(stderr, "Bad device/port.\n");
        goto usage_error;
    }

    if ((exanic = exanic_acquire_handle(device)) == NULL)
    {
        fprintf(stderr, "%s: %s\n", device, exanic_get_last_error());
        return -1;
    }

    tx = exanic_acquire_tx_buffer(exanic, port_number, 0x1000);

    if (tx == NULL)
    {
        fprintf(stderr, "%s: %s\n", device, exanic_get_last_error());
        fprintf(stderr, "%s: %s\n", device, "Couldn't allocate tx instance.");
        return -1;
    }

    if (inet_aton(argv[2], &src_addr) == 0)
    {
        printf("Invalid src_ip.\n");
        return -1;
    }

    if(inet_aton(argv[4], &dst_addr) == 0)
    {
        printf("Invalid dst_ip.\n");
        return -1;
    }

    filter.src_addr = src_addr.s_addr;
    filter.dst_addr = dst_addr.s_addr;
    filter.src_port = htons(atoi(argv[3]));
    filter.dst_port = htons(atoi(argv[5])); 
    filter.protocol = atoi(argv[6]);

    printf("Setting up TX frame with parameters:\n");
    printf("    device:     %s:%d\n", device, port_number);
    printf("    src_ip:     %s\n", argv[2]);
    printf("    src_port:   %d\n", ntohs(filter.src_port));
    printf("    dst_ip:     %s\n", argv[4]);
    printf("    dst_port:   %d\n", ntohs(filter.dst_port));
    printf("    protocol:   %d\n", filter.protocol);


    last_time = time(NULL);
    while (!stop)
    {
        generate_ip_filter_frame(buf, filter, 1, sequence);
        exanic_transmit_frame(tx, buf, 60);
        sequence++;
        cur_time = time(NULL);
        if (last_time != cur_time)
        {   
            last_time = cur_time;
            printf("Transmitted %d frames.\n",
                        sequence - last_sequence);
            last_sequence = sequence;
        }
    }

    exanic_release_tx_buffer(tx);
    exanic_release_handle(exanic);
    return 0;

    usage_error:
    printf("Usage: %s <device:port> <src_ip> <src_port> <dst_ip> <dst_port> <protocol>\n", argv[0]);
    printf("        Transmit IP frames that will match a given filter spec.\n");
    printf("        Common protocols:\n");
    printf("            6:  TCP\n");
    printf("            17: UDP\n");
    return -1;
}



