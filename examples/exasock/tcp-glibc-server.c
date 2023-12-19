/*
 * This program is a normal TCP server listening on
 * IP address 1.1.1.2 and tcp port 31415. This program
 * is used along with tcp-preload-slot.c as a client
 * program which runs on exasock to send messages to
 * this TCP server.
 *
 * Example usage:
 *
 *   ./tcp-server
 */

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <stdbool.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>

#define SERVER_IP_ADDR      "1.1.1.2"
#define SERVER_TCP_PORT     31415
#define MESSAGE             "MESSAGE_FROM_SERVER"

int main()
{
    int fd, listenfd, ret = 0, one = 1;
    struct sockaddr_in sa;
    socklen_t slen;
    char buf[1024];
    char *fail;
    ssize_t len;

    listenfd = socket(AF_INET, SOCK_STREAM, 0);
    if (listenfd < 0) {
        fprintf(stderr, "socket listenfd : %s\n", strerror(errno));
        return EXIT_FAILURE;
    }

    ret = setsockopt(listenfd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    if (ret != 0) {
        ret = -1;
        fail = "setsockopt";
        goto err;
    }

    /* bind to a port and start listening */
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    inet_aton(SERVER_IP_ADDR, &sa.sin_addr);
    sa.sin_port = htons(SERVER_TCP_PORT);
    ret = bind(listenfd, (struct sockaddr *)&sa, sizeof(sa));
    if (ret != 0) {
        ret = -1;
        fail = "bind";
        goto err;
    }

    ret = listen(listenfd, 1);
    if (ret != 0) {
        ret = -1;
        fail = "listen";
        goto err;
    }

    while (true) {
        /* accept the connection */
        slen = sizeof(sa);
        memset(&sa, 0, sizeof(sa));
        fd = accept(listenfd, (struct sockaddr *)&sa, &slen);
        if (fd < 0) {
            ret = -1;
            fail = "accept";
            goto err;
        }

        while (true) {
            memset(buf, 0, sizeof(buf));
            len = read(fd, buf, sizeof(buf));
            if (len <= 0) {
                break;
            }
            fprintf(stdout, "%s\n", buf);
            len = write(fd, MESSAGE, strlen(MESSAGE));
        }
        close(fd);
    }

    close(listenfd);
    return EXIT_SUCCESS;

err:
    fprintf(stderr, "%s failed with error %s\n", fail, strerror(errno));
    close(listenfd);

    return ret;
}
