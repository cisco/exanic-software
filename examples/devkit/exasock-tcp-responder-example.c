/**
 * For use with the ExaNIC development kit example FPGA application.
 * Shows how to use a FPGA application together with Exasock TCP.
 *
 * To be used with "exanic_x4_trigger.fw" from the devkit examples.
 */
#include <poll.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <signal.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <exanic/exanic.h>
#include <exanic/util.h>
#include <exasock/extensions.h>

#define REG_FIRMWARE_ID         0x00
#define REG_FIRMWARE_VERSION    0x01
#define REG_ARM                 0x02
#define REG_TESTFIRE            0x03
#define REG_MATCH_LENGTH        0x04
#define REG_TRANSMIT_LENGTH     0x05
#define REG_TRIGGER_COUNT       0x06
#define REG_AUTORELOAD          0x07

#define FIRMWARE_ID             0xEB000001

#define PATTERN_RAM_OFFSET      0x2000
#define MASK_RAM_OFFSET         0x4000
#define TRANSMIT_RAM_OFFSET     0x6000

int running = 1;

void sig_handler(int sig)
{
    running = 0;
}

int main(int argc, char *argv[])
{
    struct sockaddr_in addr;
    char *p;
    int fd, exanic_port, udp_port;
    exanic_t* exanic;
    char dev[16], pkt[256], buf[4096];
    size_t hdrlen, datalen;
    volatile uint32_t *app_regs;
    char *app_mem;
    uint32_t trigger_count;
    ssize_t ret;
    unsigned count = 0;

    struct __attribute__ ((__packed__))
    {
        uint8_t dst_mac[6];
        uint8_t src_mac[6];
        uint16_t ethertype;
        uint8_t version;
        uint8_t dscp;
        uint16_t ip_len;
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
    } pattern_data, mask_data;

    /* Parse command line arguments */

    if (argc != 4)
        goto usage_error;

    udp_port = strtol(argv[1], &p, 10);
    if (*argv[1] == '\0' || *p != '\0')
        goto usage_error;
    addr.sin_family = AF_INET;
    if (inet_aton(argv[2], &addr.sin_addr) == 0)
        goto usage_error;
    addr.sin_port = htons(strtol(argv[3], &p, 10));
    if (*argv[3] == '\0' || *p != '\0')
        goto usage_error;

    /* Establish a TCP connection */

    fd = socket(AF_INET, SOCK_STREAM, 0);
    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) == -1)
    {
        fprintf(stderr, "connect: %s\n", strerror(errno));
        return 1;
    }

    printf("Connected to %s:%d\n", inet_ntoa(addr.sin_addr),
            ntohs(addr.sin_port));

    /* Get access to the FPGA application */

    if (exasock_tcp_get_device(fd, dev, sizeof(dev), &exanic_port) == -1)
    {
        fprintf(stderr, "exasock_tcp_get_device: %s\n", strerror(errno));
        return EXIT_FAILURE;
    }
    if (exanic_port != 0)
    {
        fprintf(stderr, "Error: TCP connection is on port %d, "
                "but the example application must use port 0\n", exanic_port);
        return EXIT_FAILURE;
    }
    exanic = exanic_acquire_handle(dev);
    if (exanic == NULL)
    {
        fprintf(stderr, "exanic_acquire_handle: %s\n", exanic_get_last_error());
        return EXIT_FAILURE;
    }
    app_regs = exanic_get_devkit_registers(exanic);
    if (app_regs == NULL)
    {
        fprintf(stderr, "exanic_get_devkit_registers: %s\n",
                exanic_get_last_error());
        return EXIT_FAILURE;
    }
    app_mem = exanic_get_devkit_memory(exanic);
    if (app_mem == NULL)
    {
        fprintf(stderr, "exanic_get_devkit_memory: %s\n",
                exanic_get_last_error());
        return EXIT_FAILURE;
    }

    if (app_regs[REG_FIRMWARE_ID] != FIRMWARE_ID)
    {
        fprintf(stderr, "Application ID register does not match expected (got %x, expected %x)\n",
                app_regs[REG_FIRMWARE_ID], FIRMWARE_ID);
        return -1;
    }

    /* Set up the pattern trigger for the FPGA application */

    memset(&pattern_data, 0, sizeof(pattern_data));
    memset(&mask_data, 0, sizeof(mask_data));

    /* IP ethertype */
    pattern_data.ethertype = htons(0x0800);
    mask_data.ethertype = 0xFFFF;
    /* UDP protocol */
    pattern_data.protocol = 0x11;
    mask_data.protocol = 0xFF;
    /* Destination port */
    pattern_data.dst_port = htons(udp_port);
    mask_data.dst_port = 0xFFFF;

    /* Copy to FPGA memory */
    memcpy(app_mem + PATTERN_RAM_OFFSET, &pattern_data, sizeof(pattern_data));
    memcpy(app_mem + MASK_RAM_OFFSET, &mask_data, sizeof(mask_data));
    app_regs[REG_MATCH_LENGTH] = sizeof(pattern_data);

    printf("Triggering on UDP port %d\n", udp_port);

    signal(SIGHUP, sig_handler);
    signal(SIGINT, sig_handler);
    signal(SIGPIPE, sig_handler);
    signal(SIGALRM, sig_handler);
    signal(SIGTERM, sig_handler);

    while (running)
    {
        trigger_count = app_regs[REG_TRIGGER_COUNT];

        /* Load the FPGA application with the TCP response packet */

        /* Construct response packet */
        hdrlen = exasock_tcp_build_header(fd, pkt, sizeof(pkt), 0, 0);
        if (hdrlen == -1)
        {
            if (errno == EAGAIN)
            {
                /* Unlikely case that the address fell out of the ARP table */
                usleep(1000);
                continue;
            }
            else
            {
                fprintf(stderr, "exasock_tcp_build_header: %s\n",
                        strerror(errno));
                goto exit_loop;
            }
        }
        datalen = sprintf(pkt + hdrlen, "hello world %d\n", ++count);
        exasock_tcp_set_length(pkt, hdrlen, datalen);
        exasock_tcp_calc_checksum(pkt, hdrlen, pkt + hdrlen, datalen);

        /* Copy to FPGA memory and arm trigger */
        memcpy(app_mem + TRANSMIT_RAM_OFFSET, &pkt, hdrlen + datalen);
        app_regs[REG_TRANSMIT_LENGTH] = hdrlen + datalen;
        app_regs[REG_ARM] = 1;

        /* Wait for response packet to be triggered */

        while (trigger_count == app_regs[REG_TRIGGER_COUNT])
        {
            /* Read from TCP connection and discard received data */
            ret = recv(fd, buf, sizeof(buf), MSG_DONTWAIT);
            if (ret == -1 && errno != EAGAIN)
            {
                fprintf(stderr, "recv: %s\n", strerror(errno));
                goto exit_loop;
            }
            else if (ret == 0 || !running)
                goto exit_loop;
        }

        /* Response was triggered */

        printf("Triggered\n");

        /* Update TCP state */
        if (exasock_tcp_send_advance(fd, pkt + hdrlen, datalen) == -1)
        {
            fprintf(stderr, "exasock_tcp_send_advance: %s\n",
                    strerror(errno));
            goto exit_loop;
        }
    }

exit_loop:
    /* Disarm the trigger */
    app_regs[REG_ARM] = 0;
    close(fd);

    return EXIT_SUCCESS;

usage_error:
    fprintf(stderr,
            "Usage: %s <udp-port> <tcp-addr> <tcp-port>\n\n"
            "Establishes a TCP connection to the specified address and port.\n"
            "A packet is sent on the TCP connection whenever there is an incoming packet\n"
            "on the specified UDP port.\n\n"
            "This example requires the example ExaNIC development kit application.\n",
            argv[0]);
    return EXIT_FAILURE;
}
