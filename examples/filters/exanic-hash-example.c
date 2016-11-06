/** Simple flow hashing demo, showing how to set up flow hashing and fork off 
 *  processes to handle RX on each. Connect port 0 to port 1 of exanic0 
 *  directly to run this. 
 */
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include <exanic/fifo_rx.h>
#include <exanic/fifo_tx.h>
#include <exanic/pcie_if.h>
#include <exanic/filter.h>
#include <exanic/exanic.h>
#include <unistd.h>
#include <sys/time.h>
#include "filter-common.h"

/* IP Header Length. UDP/TCP ports are at different frame
 * offset in the case IHL > 5.
 */
#define IHL 5 

int main(int argc, char *argv[])
{
    exanic_t *exanic_rx;
    exanic_t *exanic_tx;
    exanic_rx_t *rx = NULL;
    exanic_tx_t *tx;
    int tx_buffer_size = 0x1000;
    int port_rx = 1;
    int port_tx = 0;
    char device_rx[16];
    char device_tx[16];
    int num_buffers;
    int fork_buffer;
    int size;
    char buf[255];
    int count;
    int iter;
    int num_cores, num_packets;
    struct timeval start_time, cur_time;

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
#if IHL > 5 
        uint32_t ip_options[IHL-5];
#endif        
        uint16_t src_port;
        uint16_t dst_port;
        uint16_t prot_len;
        uint16_t prot_checksum;
        uint8_t  payload[22];
    } my_ip_frame;

    if (argc != 5)
        goto usage_error;

    if (parse_device_port(argv[1], device_tx, &port_tx) == -1)
    {
        fprintf(stderr, "Bad device/port.\n");
        goto usage_error;
    }

    if (parse_device_port(argv[2], device_rx, &port_rx) == -1)
    {
        fprintf(stderr, "Bad device/port.\n");
        goto usage_error;
    }
    
    num_cores = atoi(argv[3]);
    num_packets = atoi(argv[4]);
        
    if (sizeof(my_ip_frame) != 64 + (IHL-5) * 4)
    {
        fprintf(stderr, "Compiler didn't pack frame structure, aborting. Size is %d bytes.\n", 
                                (int) sizeof(my_ip_frame));
        return -1;
    }

    if ((exanic_rx = exanic_acquire_handle(device_rx)) == NULL)
    {
        fprintf(stderr, "%s: %s\n", device_rx, exanic_get_last_error());
        return -1;
    }

    if ((exanic_tx = exanic_acquire_handle(device_tx)) == NULL)
    {
        fprintf(stderr, "%s: %s\n", device_rx, exanic_get_last_error());
        return -1;
    }

    /* Enable flow hashing, choosing an appropriate hash function,
     * and number of hash buffers. 
     */
    num_buffers = exanic_enable_flow_hashing(exanic_rx, port_rx, num_cores, 
                                      EXANIC_RX_HASH_FUNCTION_PORT);
    if (num_buffers < 1)
    {
        fprintf(stderr, "%s: %s\n", device_rx, exanic_get_last_error());
        return -1;
    }

    printf("Got %d flow hashing buffers. Forking receive processes.\n", 
                                                                num_buffers);

    tx = exanic_acquire_tx_buffer(exanic_tx, port_tx, tx_buffer_size);  

    /* Construct a dummy ip frame. */ 
    memset(&my_ip_frame, 0xFF, sizeof(my_ip_frame));
    my_ip_frame.protocol = IPPROTO_UDP;
    my_ip_frame.ethertype = htons(0x0800);
    my_ip_frame.version =  (IHL << 4) & 4;

    /* Fork off hash buffer handler processes. */
    for (fork_buffer = 0; fork_buffer < num_buffers; fork_buffer++)
    {
        if (!fork())
        {
            /* RX Buffers > 0 will receive flow hashed data. */
            rx = exanic_acquire_rx_buffer(exanic_rx, port_rx, fork_buffer + 1);
            break; 
        }
    }

    if (fork_buffer == num_buffers)
        usleep(100000);

    count = 0;
    iter = num_packets; 
    gettimeofday(&start_time, NULL);
    gettimeofday(&cur_time, NULL);

    while(iter-- > 0 || 
            ((fork_buffer != num_buffers) && 
                (cur_time.tv_sec - start_time.tv_sec < 2))) 
    {
        /* Keep original PID as transmitter. */
        if (fork_buffer == num_buffers)
        {
            count++;
            my_ip_frame.src_port = rand() % 65536;
            my_ip_frame.dst_port = rand() % 65536;
            my_ip_frame.src_ip =  rand();
            my_ip_frame.dst_ip = rand();
            exanic_transmit_frame(tx, (void *) &my_ip_frame, 
                                        sizeof(my_ip_frame));
        }
        else
        {
            size = exanic_receive_frame(rx, buf, sizeof(buf), NULL);
            if (size > 0) 
            {
                count++;
                iter = 1000000;
            }
            else if (size < 0)
            {
                printf("Error on buffer %d, error: %d!\n", fork_buffer, size);
                if (size == -256)
                    printf("    Error type: RX buffer lapped.\n");
            }
        }
        gettimeofday(&cur_time, NULL);
    }

    if (fork_buffer != num_buffers)
        printf("Process %d: received %d frames on buffer %d.\n", getpid(), 
                                                        count, fork_buffer);
    else  
    {
        sleep(2);
        printf("Process %d: sent %d total frames.\n", getpid(), count);
    }

    exanic_release_handle(exanic_rx);
    exanic_release_handle(exanic_tx);
    return 0;

    usage_error:
    printf("Usage: %s if1 if2 num_cores num_packets\n", argv[0]);
    printf("    if1: transmit interface (eg. exanic0:0)\n");
    printf("    if2: receive interface (eg. exanic0:1)\n");
    printf("    num_cores: maximum number of cores to use (must be power of 2)\n");
    printf("    num_packets: total number of packets to transmit\n"); 
    return -1;
}
