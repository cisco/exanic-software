/*
 *
 * This application works with the stac_t0 FDK example. It performs the
 * STAC_T0 latency test as defined by the Securities Technology Analysis Center (STAC).
 * It generates UDP datagrams containing random indexes and expects
 * echoed indexes to come back in TCP segments from the stack under test,
 * in this case an ExaNIC.
 *
 * Hardware timestamps are taken to calculate the latency in the stack.
 *
 * To run this test, apply the stac_t0 firmware and establish an
 * ATE TCP connection from software (see examples/exasock/ate-connect.c),
 * then pass in the parameters detailed below. The application will
 * send a specified number of UDP datagrams and dump the RX and TX
 * packets to a file (stdout by default if no files are specified)
 *
 */

#include <stdio.h>
#include <string.h>
#include <time.h>
#include <getopt.h>
#include <pthread.h>
#include <unistd.h>
#include <signal.h>
#include <assert.h>

#include <exanic/exanic.h>
#include <exanic/fifo_tx.h>
#include <exanic/fifo_rx.h>
#include <exanic/register.h>
#include <exanic/time.h>
#include <exanic/util.h>

#include <linux/in.h>
#include <linux/ip.h>


#define RX_BUFFER_SIZE 2048

typedef struct {
    int64_t index;
    int64_t order;
    exanic_cycles_t tx_time;
    char packet[512]; //Could do this dynamically if we care
} tx_packet_t;

typedef struct {
    int64_t index;
    exanic_cycles_t rx_time;
} rx_packet_t;


exanic_t *nic   = NULL;
exanic_tx_t *tx = NULL;
exanic_rx_t *rx = NULL;

rx_packet_t* rx_packets = NULL;
tx_packet_t* tx_packets = NULL;
int64_t rx_packet_count;
int64_t tx_packet_count;

int64_t data_size = 0;
int64_t count = 1000;
char message_type = 0;
volatile int stop = 0;

/* manipulate the sent index to trigger every time */
int hammering = 0;

int compare_txpkts(const void * a, const void * b)
{
    tx_packet_t* A = (tx_packet_t*)a;
    tx_packet_t* B = (tx_packet_t*)b;
    return ( A->order - B->order );
}

static inline int little_endian(void)
{
    unsigned int x = 1;
    int lower_byte = (int)(((char *)&x)[0]);
    return lower_byte;
}

/* mask an index so that when interpreted
 * as big-endian, it triggers the SUT */
uint64_t make_hammer(uint64_t index)
{
    if (little_endian())
    {
        uint64_t result = index;
        char *bytes = (char *)&result;
        bytes[7] = 0;
        bytes[6] &= 0xfc;
        return result;
    }
    else
        return (index << 10);
}

void init_packets(tx_packet_t* packets, const int data_size, const int count,
                    char message_type)
{
    const uint64_t partition_size = UINT64_MAX / count;
    srand(time(NULL));   // should only be called once

    int64_t c = 0;
    for(c = 0; c < count; c++)
    {
        /* This code taken from STAC-T0 RFC */
        const int64_t base = c * partition_size;
        const int64_t addend = (int64_t)( ( (double)rand()/RAND_MAX) * partition_size);
        packets[c].index = base + addend;
        packets[c].order = rand();

        if (hammering)
            packets[c].index = make_hammer(packets[c].index);


        /* Init the packet with junk */
        char* packet = packets[c].packet;
        int i;
        for (i = 0; i < data_size; i++)
        {
            packet[i] = 0xFF;
        }

        /* Set the Ethernet parameters */
        /* dest addr = broadcast */
        memset(packet, 0xff, 6);
        memset(packet + 6, 0xaa, 6);
        memset(packet + 12, 0xCC, 2);

        /* Byte 44 is ATE session ID in the current firmware
         *
         * TODO:
         * put in 2-byte connection IDs and verify byte order
         * once a mult-port, 512 session per port firmware is
         * available */
        memset(packet + 44, 0, 1);

        /* Set the message type */
        packet[14 + 20 + 8] = message_type;

        /* Set the index value */
        switch (message_type)
        {
            case 'A':
                *(int64_t*)(packet + 14 + 20 + 8 + 233) = packets[c].index;
                break;
            case 'B':
                *(int64_t*)(packet + 14 + 20 + 8 + 6) = packets[c].index;
                break;
        }
    }

    //Sort packets in random order
    qsort(packets,count, sizeof(tx_packet_t),compare_txpkts);
}

void* rx_thread(void *data)
{
    rx_packets = calloc(count,sizeof(rx_packet_t));

    exanic_cycles32_t end;
    exanic_cycles_t end_expanded;

    char rx_buffer[RX_BUFFER_SIZE];
    int size = 0;

    int64_t i = 0;
    unsigned char pkt_type = 0;

    for(i = 0; !stop; i++ )
    {

        if(i && (i % 100000) == 0)
        {
            fprintf(stderr, "Received %li packets\n", i);
        }

        do
        {   /* Wait for RX frame to arrive at the NIC */
            size = exanic_receive_frame(rx, rx_buffer, sizeof(rx_buffer), &end);
        }
        while (size <= 0 && !stop);
        if(stop)
            break;

        pkt_type = *(rx_buffer + 14 + 9);

        /* ignore non-tcp packets */
        if (pkt_type != IPPROTO_TCP)
        {
            i--;
            continue;
        }

        end_expanded = exanic_expand_timestamp(nic, end);
        rx_packets[i].rx_time = end_expanded;

        rx_packets[i].index = *(int64_t*)(rx_buffer + 14 + 20 + 20 + 4);
    }

    fprintf(stderr,"RX thread stopped after %li iterations\n", i);

    rx_packet_count = i;

    return NULL;

}

void* tx_thread(void *data)
{

    tx_packets = calloc(count,sizeof(tx_packet_t));
    init_packets(tx_packets, data_size, count,message_type);

    exanic_cycles32_t old_start, start;
    exanic_cycles_t start_expanded;

    int64_t i = 0;
    for(i = 0; i < count && !stop; i++)
    {

        if(i && (i % 100000) == 0)
        {
            fprintf(stderr, "Sent %li packets\n", i);
        }

        old_start = exanic_get_tx_timestamp(tx);
        exanic_transmit_frame(tx, tx_packets[i].packet, data_size);

        do
        {
            /* Wait for TX frame to leave the NIC */
            start = exanic_get_tx_timestamp(tx);
        }
        while (old_start == start);

        start_expanded = exanic_expand_timestamp(nic, start);
        tx_packets[i].tx_time = start_expanded;

        //This should probably be a bit smarter....
        usleep(1);
    }


    fprintf(stderr, "TX thread stopped after %li iterations\n", i);
    tx_packet_count = i;

    fprintf(stderr, "Stop =1\n");
    stop = 1;

    return NULL;

}


void handler(int sig)
{
    printf("Stopping on signal %i\n", sig);
    stop = 1;
}


int main(int argc, char *argv[])
{

    signal(SIGINT, handler);
    signal(SIGSTOP, handler);
    signal(SIGKILL, handler);

    FILE *savefp = NULL;
    int c, err = 0;

    /* Configure sensible defaults */
    const char *device = NULL;
    const char *savefile = NULL;
    int tx_port = 0;
    int rx_port = 0;


    /* No args supplied */
    if (argc < 2)
        goto usage_error;

    while ((c = getopt(argc, argv, "d:w:p:P:M:c:H")) != -1)
    {
        switch (c)
        {
            case 'd':
                {
                    /*
                    device = strdup(optarg);
                    if (!device)
                        goto usage_error;
                        */
                    device = optarg;
                    break;
                }
            case 'w':
                savefile = optarg;
                break;
            case 'p':
                tx_port = atoi(optarg);
                break;
            case 'P':
                rx_port = atoi(optarg);
                break;
            case 'M':
                message_type = optarg[0];
                break;
            case 'c':
                count = atoi(optarg);
                break;
            case 'H':
                hammering = 1;
                break;
            default:
                goto usage_error;
        }
    }


    if (savefile != NULL)
    {
        if (strcmp (savefile, "-") == 0)
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

    if(message_type == 'A' || message_type == 'a')
    {
        message_type = 'A';
        data_size = 503 - 4;
    }
    else if(message_type == 'B' || message_type == 'b')
    {
        message_type = 'B';
        data_size = 64 - 4;
    }
    else
    {
        fprintf(stderr, "Message type must be A or B\n");
        goto usage_error;

    }


    nic = exanic_acquire_handle(device);
    if (!nic)
    {
        fprintf(stderr, "exanic_acquire_handle: %s\n",
                 exanic_get_last_error());
        err = 1;
        goto err_acquire_handle;
    }

    if (exanic_get_hw_type(nic) != EXANIC_HW_X10_HPT)
    {
        fprintf(stderr, "Warning: %s is not an ExaNIC-HPT with high-res "
                 "timestamping.\n",
                 device);
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

    pthread_t tx_thread_id = {0};
    pthread_t rx_thread_id = {0};

    if(pthread_create(&tx_thread_id, NULL, tx_thread, NULL))
    {
        fprintf(stderr, "Error creating tx thread\n");
        return 1;
    }

    if(pthread_create(&rx_thread_id, NULL, rx_thread, NULL))
    {
        fprintf(stderr, "Error creating rx thread\n");
        return 1;
    }

    fprintf(stderr, "Waiting for TX thread to stop\n");
    if(pthread_join(tx_thread_id, NULL))
    {
        fprintf(stderr, "Error joining tx thread\n");
        return 2;

    }
    fprintf(stderr, "TX thread stopped\n");

    fprintf(stderr, "Waiting for RX thread to stop\n");
    if(pthread_join(rx_thread_id, NULL))
    {
        fprintf(stderr, "Error joining rx thread\n");
        return 2;
    }
    fprintf(stderr, "RX thread stopped\n");


    if(!savefp)
        savefp = stderr;

    fprintf(savefp, "Dumping %li TX Packets\n", tx_packet_count);
    int i = 0;
    for(i = 0; i < tx_packet_count; i++)
    {
        uint64_t index          = tx_packets[i].index;
        int64_t order           = tx_packets[i].order;
        exanic_cycles_t tx_time = tx_packets[i].tx_time;
        printf("TX %016lx %016lx %li\n", order, index, tx_time);
    }

    fprintf(savefp, "Dumping %li RX Packets\n", rx_packet_count);
    for(i = 0; i < rx_packet_count; i++)
    {
        uint64_t index           = rx_packets[i].index;
        exanic_cycles_t rx_time = rx_packets[i].rx_time;
        printf("RX %016x %016lx %li\n", i, index, rx_time);
    }

    return 0;

    /* Fall through to cleanup code */

    exanic_release_tx_buffer(tx);
    err_acquire_tx: exanic_release_rx_buffer(rx);
    err_acquire_rx: exanic_release_handle(nic);
    err_acquire_handle: if (savefp != NULL) fclose(savefp);
    err_open_savefile: return err;

    usage_error: fprintf(stderr, "Usage: %s -d device\n", argv[0]);
    fprintf(stderr,
            "           [-p txport] [-P rxport] \n");
    fprintf(stderr,
            "           [-c count] [-h] \n\n");
    fprintf(stderr,
            "  -d: specify the ExaNIC device name (e.g. exanic0)\n");
    fprintf(stderr,
            "  -w: write results to given file (- for stdout)\n");
    fprintf(stderr,
            "  -c: number of packets to send (default 1000)\n");
    fprintf(stderr,
            "  -h: print this usage information\n\n");
    return 1;
}
