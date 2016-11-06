#include <time.h>
#include <poll.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <linux/sockios.h>
#include <linux/net_tstamp.h>

int main(int argc, char *argv[])
{
    struct sockaddr_in addr;
    struct hwtstamp_config hwts_config;
    struct ifreq ifr;
    int val;
    char *p;
    int fd;

    if (argc != 3)
        goto usage_error;

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons(strtol(argv[2], &p, 10));
    if (*argv[2] == '\0' || *p != '\0')
        goto usage_error;

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd == -1)
    {
        fprintf(stderr, "socket: %s\n", strerror(errno));
        return EXIT_FAILURE;
    }

    /* Enable hardware timestamping on the interface */
    memset(&hwts_config, 0, sizeof(hwts_config));
    hwts_config.tx_type = HWTSTAMP_TX_OFF;
    hwts_config.rx_filter = HWTSTAMP_FILTER_ALL;
    memset(&ifr, 0, sizeof(ifr));
    snprintf(ifr.ifr_name, IFNAMSIZ, "%s", argv[1]);
    ifr.ifr_data = (void *)&hwts_config;
    if (ioctl(fd, SIOCSHWTSTAMP, &ifr) == -1)
    {
        fprintf(stderr, "ioctl(SIOCSHWTSTAMP): %s\n", strerror(errno));
        return EXIT_FAILURE;
    }

    /* Listen for UDP packets on the given port */
    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) == -1)
    {
        fprintf(stderr, "bind: %s\n", strerror(errno));
        return EXIT_FAILURE;
    }

    /* Enable reporting of hardware timestamps */
    val = SOF_TIMESTAMPING_RAW_HARDWARE;
    if (setsockopt(fd, SOL_SOCKET, SO_TIMESTAMPING, &val, sizeof(val)) == -1)
    {
        fprintf(stderr, "setsockopt(SO_TIMESTAMPING): %s\n", strerror(errno));
        return EXIT_FAILURE;
    }

    while (1)
    {
        char data[4096], ctrl[4096];
        struct msghdr msg;
        struct iovec iov;
        ssize_t len;
        struct cmsghdr *cmsg;

        memset(&msg, 0, sizeof(msg));
        msg.msg_iov = &iov;
        msg.msg_iovlen = 1;
        msg.msg_control = ctrl;
        msg.msg_controllen = sizeof(ctrl);
        iov.iov_base = data;
        iov.iov_len = sizeof(data);

        len = recvmsg(fd, &msg, 0);
        if (len == -1)
        {
            fprintf(stderr, "recvmsg: %s\n", strerror(errno));
            return EXIT_FAILURE;
        }

        printf("recvmsg returned %ld\n", len);

        for (cmsg = CMSG_FIRSTHDR(&msg); cmsg != NULL;
             cmsg = CMSG_NXTHDR(&msg, cmsg))
        {
            if (cmsg->cmsg_level == SOL_SOCKET &&
                cmsg->cmsg_type == SCM_TIMESTAMPING)
            {
                /* Timestamps are delivered in a SCM_TIMESTAMPING control
                 * message containing 3 timestamps
                 * Hardware timestamps are passed in ts[2] */
                struct timespec *ts =
                    (struct timespec *)CMSG_DATA(cmsg);
                printf("timestamp %ld.%09ld\n", ts[2].tv_sec, ts[2].tv_nsec);
            }
        }
    }

    return 0;

usage_error:
    fprintf(stderr,
            "Usage: %s <interface> <port>\n"
            "\n"
            "Enable hardware timestamping on the given network interface\n"
            "Receive UDP packets and output the hardware timestamp\n",
            argv[0]);

    return EXIT_FAILURE;
}
