/*
 * This program demonstrates the use of the Exasock extensions API. It retrieves a
 * raw TCP header from an accelerated socket, construct a TCP segment manually and
 * sends it via the raw API (libexanic).
 *
 * Example usage:
 *
 *   exasock ./tcp-raw-send 192.168.1.11 11111
 *
 * This will listen for TCP connections on the interface with address 192.168.1.11
 * and port 11111. After a connection is accepted, any received packets will be
 * echoed by manually constructing the next TCP segment and transmitting it via
 * the raw ethernet frame API (libexanic).
 *
 * The extensions API is useful for performing TCP transmission from outside of
 * standard sockets, for example, from the ExaNIC FPGA or by preloading the
 * transmit buffers on the card.
 *
 * Note that if run without Exasock this example will fail, as the Exasock
 * extensions API function stubs will not have been replaced with the versions
 * that are preloaded via the Exasock wrapper.
 */

#include <poll.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <exanic/exanic.h>
#include <exanic/fifo_tx.h>
#include <exasock/extensions.h>

int main(int argc, char *argv[])
{
    struct sockaddr_in servaddr, addr;
    socklen_t addrlen;
    int listenfd, fd, port;
    char *p, buf[1024], pktbuf[2048], dev[16];
    ssize_t len, hdrlen;
    exanic_t *exanic;
    exanic_tx_t *tx;
    const char *verstring;

    /* Parse command line arguments */

    if (argc != 3)
        goto usage_error;

    servaddr.sin_family = AF_INET;
    if (inet_aton(argv[1], &servaddr.sin_addr) == 0)
        goto usage_error;
    servaddr.sin_port = htons(strtol(argv[2], &p, 10));
    if (*argv[2] == '\0' || *p != '\0')
        goto usage_error;

    /* Check that exasock is loaded, otherwise extension functions will fail */

    if (!exasock_loaded())
    {
        fprintf(stderr, "This program should be run with exasock.\n");
        return EXIT_FAILURE;
    }

    verstring = exasock_version_text();
    if (verstring == NULL)
    {
        fprintf (stderr, "Failed to obtain Exasock version text.\n");
        return EXIT_FAILURE;
    }

    /* Will not happen, only to demonstrate usage */
    if (exasock_version_code() < EXASOCK_VERSION(2,2,0))
    {
        fprintf(stderr, "Please install Exasock library 2.2.0 or newer.\n");
        return EXIT_FAILURE;
    }
    printf("Exasock release %s\n", verstring);

    /* Listen for connection */

    listenfd = socket(AF_INET, SOCK_STREAM, 0);
    if (bind(listenfd, (struct sockaddr *)&servaddr, sizeof(servaddr)) == -1)
    {
        fprintf(stderr, "bind: %s\n", strerror(errno));
        return EXIT_FAILURE;
    }
    if (listen(listenfd, 1) == -1)
    {
        fprintf(stderr, "listen: %s\n", strerror(errno));
        return EXIT_FAILURE;
    }
    addrlen = sizeof(addr);
    fd = accept(listenfd, (struct sockaddr *)&addr, &addrlen);
    if (fd == -1)
    {
        fprintf(stderr, "accept: %s\n", strerror(errno));
        return EXIT_FAILURE;
    }
    close(listenfd);

    /* Get handle to ExaNIC device */

    if (exasock_tcp_get_device(fd, dev, sizeof(dev), &port) == -1)
    {
        fprintf(stderr, "exasock_tcp_get_device: %s\n", strerror(errno));
        return EXIT_FAILURE;
    }
    exanic = exanic_acquire_handle(dev);
    if (exanic == NULL)
    {
        fprintf(stderr, "exanic_acquire_handle: %s\n", exanic_get_last_error());
        return EXIT_FAILURE;
    }
    tx = exanic_acquire_tx_buffer(exanic, port, 0);
    if (tx == NULL)
    {
        fprintf(stderr, "exanic_acquire_tx_buffer: %s\n",
                exanic_get_last_error());
        return EXIT_FAILURE;
    }

    /* Echo received data on connection */

    while (1)
    {
        len = recv(fd, buf, sizeof(buf), 0);
        if (len == -1)
        {
            fprintf(stderr, "recv: %s\n", strerror(errno));
            return EXIT_FAILURE;
        }
        else if (len == 0)
            break;

        /* Use exasock extension API to construct raw TCP packet */

        do
            hdrlen = exasock_tcp_build_header(fd, pktbuf, sizeof(pktbuf), 0, 0);
        while (hdrlen == -1 && errno == EAGAIN);
        if (hdrlen == -1)
        {
            fprintf(stderr, "exasock_tcp_build_header: %s\n", strerror(errno));
            return EXIT_FAILURE;
        }
        memcpy(pktbuf + hdrlen, buf, len);
        exasock_tcp_set_length(pktbuf, hdrlen, len);
        exasock_tcp_calc_checksum(pktbuf, hdrlen, pktbuf + hdrlen, len);

        /* Send raw TCP packet using libexanic */

        if (exanic_transmit_frame(tx, pktbuf, hdrlen + len) == -1)
        {
            fprintf(stderr, "exanic_transmit_frame: %s\n",
                    exanic_get_last_error());
            return EXIT_FAILURE;
        }

        /* Update exasock TCP state for the packet we just transmitted */

        if (exasock_tcp_send_advance(fd, buf, len) == -1)
        {
            fprintf(stderr, "exasock_tcp_send_advance: %s\n", strerror(errno));
            return EXIT_FAILURE;
        }
    }

    exanic_release_tx_buffer(tx);
    exanic_release_handle(exanic);
    close(fd);

    return 0;

usage_error:
    fprintf(stderr, "Usage: %s <addr> <port>\n", argv[0]);
    return EXIT_FAILURE;
}
