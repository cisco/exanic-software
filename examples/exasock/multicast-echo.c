#include <time.h>
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

int main(int argc, char *argv[])
{
    struct sockaddr_in mcast_addr, send_addr;
    struct ip_mreq im;
    int recv_fd, send_fd;
    char *p, *q;

    /* Parse command line arguments */

    if (argc != 3)
        goto usage_error;

    mcast_addr.sin_family = AF_INET;
    send_addr.sin_family = AF_INET;

    if ((p = strtok(argv[1], ":")) == NULL ||
        inet_aton(p, &mcast_addr.sin_addr) == 0)
        goto usage_error;
    if ((p = strtok(NULL, ":")) == NULL ||
        inet_aton(p, &im.imr_interface) == 0)
        goto usage_error;
    if ((p = strtok(NULL, "")) == NULL)
        goto usage_error;
    mcast_addr.sin_port = htons(strtol(p, &q, 10));
    if (*p == '\0' || *q != '\0')
        goto usage_error;

    im.imr_multiaddr = mcast_addr.sin_addr;

    if ((p = strtok(argv[2], ":")) == NULL ||
        inet_aton(p, &send_addr.sin_addr) == 0)
        goto usage_error;
    if ((p = strtok(NULL, "")) == NULL)
        goto usage_error;
    send_addr.sin_port = htons(strtol(p, &q, 10));
    if (*p == '\0' || *q != '\0')
        goto usage_error;

    /* Create and bind sockets */

    recv_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (recv_fd == -1)
    {
        fprintf(stderr, "socket: %s\n", strerror(errno));
        return EXIT_FAILURE;
    }

    send_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (send_fd == -1)
    {
        fprintf(stderr, "socket: %s\n", strerror(errno));
        return EXIT_FAILURE;
    }

    if (setsockopt(recv_fd, IPPROTO_IP, IP_ADD_MEMBERSHIP, (char *)&im,
                   sizeof(im)) == -1)
    {
        fprintf(stderr, "setsockopt: IP_ADD_MEMBERSHIP failed: %s\n",
                strerror(errno));
        return EXIT_FAILURE;
    }

    if (bind(recv_fd, (struct sockaddr *)&mcast_addr, sizeof(mcast_addr)) == -1)
    {
        fprintf(stderr, "bind: %s\n", strerror(errno));
        return EXIT_FAILURE;
    }

    if (connect(send_fd, (struct sockaddr *)&send_addr, sizeof(send_addr)) == -1)
    {
        fprintf(stderr, "connect: %s\n", strerror(errno));
        return EXIT_FAILURE;
    }

    /* Echo packets */

    while (1)
    {
        char buf[65536];
        ssize_t len;

        len = recv(recv_fd, buf, sizeof(buf), 0);
        if (len == -1)
        {
            fprintf(stderr, "recv: %s\n", strerror(errno));
            return EXIT_FAILURE;
        }

        if (send(send_fd, buf, len, 0) == -1)
        {
            fprintf(stderr, "send: %s\n", strerror(errno));
            return EXIT_FAILURE;
        }
    }

    close(recv_fd);
    close(send_fd);

    return 0;

usage_error:
    fprintf(stderr,
            "Usage: %s <multicast-group>:<interface-addr>:<port> <send-addr>:<port>\n"
            "\n"
            "Receive multicast UDP packets on <interface-addr> addressed to\n"
            "multicast group <multicast-group> at port <port>, and echo a copy of\n"
            "each packets to <send-addr>:<port>.\n",
            argv[0]);

    return 0;
}
