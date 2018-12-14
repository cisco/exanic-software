/*
 * This program demonstrates the use of ExaNIC Accelerated TCP Engine (ATE) for
 * exasock accelerated TCP connections. It creates a socket, enables Accelerated
 * TCP Engine for the socket and connects to a TCP server. Once the connection is
 * established, ATE is ready to send TCP segments directly from HW whenever
 * triggered. This program will keep on receiving any data sent from the server on
 * the connection and printing the data as it arrives.
 *
 * Example usage:
 *
 *   exasock ./ate-connect 192.168.1.10 11111
 *
 * Note that exasock is required to enable and control ExaNIC Accelerated TCP
 * Engine, so this program will fail if run without exasock.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <arpa/inet.h>

#include <exasock/socket.h>

#define BUF_LEN 2048

/* Enable if exasock_ate_connect() helper is to be used or disable in case
 * the standard connect() call preceded with setting of SO_EXA_ATE socket option
 * is preferred (both approaches equivalent). */
#define USE_EXASOCK_ATE_CONNECT_HELPER 1

static void dump_buf(char *buf, ssize_t len)
{
    int i;

    for (i = 0; i < len; i++)
    {
        if ((i % 16) == 0)
            fprintf(stderr, "\n  %04x ", i);
        fprintf(stderr, " %02x", (uint8_t)buf[i]);
    }
    fprintf(stderr, "\n");
}

int main (int argc, char *argv[])
{
    struct sockaddr_in sa;
    char *p;
    int fd;
    int ate_id;
    ssize_t len;
    char buf[BUF_LEN];
    int err = 0;

    /* Parse command line arguments */

    if (argc != 3)
        goto usage_error;

    sa.sin_family = AF_INET;
    if (inet_aton(argv[1], &sa.sin_addr) == 0)
        goto usage_error;
    sa.sin_port = htons(strtol(argv[2], &p, 10));
    if (*argv[2] == '\0' || *p != '\0')
        goto usage_error;

    fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0)
    {
        fprintf(stderr, "socket: %s\n", strerror(errno));
        err = EXIT_FAILURE;
        goto err_socket;
    }

    /* Enable ATE and connect with server */
    ate_id = 0;
#if USE_EXASOCK_ATE_CONNECT_HELPER
    err = exasock_ate_connect(fd, ate_id, (struct sockaddr *)&sa, sizeof(sa));
    sa.sin_port = htons(strtol(argv[2], &p, 10) + 1);
#else
    /* Enable ATE */
    err = setsockopt(fd, SOL_EXASOCK, SO_EXA_ATE, &ate_id, sizeof(ate_id));
    if (err)
    {
        fprintf(stderr, "Failed to enable ATE: %s\n", strerror(errno));
        err = EXIT_FAILURE;
        goto exit;
    }

    /* Connect with server */
    err = connect(fd, (struct sockaddr *)&sa, sizeof(sa));
#endif
    if (err)
    {
        fprintf(stderr, "connect: %s (%d)\n", strerror(errno), err);
        err = EXIT_FAILURE;
        goto exit;
    }

    fprintf(stderr, "Connected with %s:%u\n",
            inet_ntoa(sa.sin_addr), ntohs(sa.sin_port));

    /* Receive and dump any data arriving on the connection */
    fprintf(stderr, "Receiving data:\n");
    do
    {
        len = recv(fd, buf, BUF_LEN, 0);
        if (len > 0)
            dump_buf(buf, len);
    } while (len > 0);

exit:
    close(fd);
err_socket:
    return err;

usage_error:
    fprintf(stderr,
            "Usage: exasock %s <server-addr> <server-port>\n"
            "\n"
            "Establish TCP connection with <server-addr>:<server-port>\n"
            "using ExaNIC Accelerated TCP Engine (ATE).\n"
            "This application must be used with exasock.\n",
            argv[0]);

    return EXIT_FAILURE;
}
