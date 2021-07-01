/*
 * exanic-xvcserver:
 * Provides access to the ExaNIC JTAG port over PCIe.  Vivado tools can connect
 * to this server via the XVC protocol.
 * (N.B. Requires an ExaNIC FDK built with JTAG access support.)
 *
 * This file, "exanic-xvcserver.c", is a derivative of "xvcServer.c"
 * (https://github.com/Xilinx/XilinxVirtualCable) which is in turn a derivative
 * of "xvcd.c" (https://github.com/tmbinc/xvcd).  These upstream sources are
 * used under the CC0 1.0 Universal license
 * (http://creativecommons.org/publicdomain/zero/1.0/), and you may also use
 * this code under the CC0 1.0 Universal license, or MIT license, at your
 * option.  This software is provided "as is" without warranty of any kind.
 */


#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <time.h>
#include <stdint.h>

#include <fcntl.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/tcp.h>
#include <netinet/in.h> 
#include <pthread.h>

#include <exanic/exanic.h>
#include <exanic/pcie_if.h>
#include <exanic/register.h>

typedef struct {
    uint32_t length_offset;
    uint32_t tms_offset;
    uint32_t tdi_offset;
    uint32_t tdo_offset;
    uint32_t ctrl_offset;
} jtag_t;

static int verbose = 0;

static int sread(int fd, void *target, int len)
{
    unsigned char * t = target;
    while (len)
    {
        int r = read(fd, t, len);
        if (r <= 0)
            return r;
        t += r;
        len -= r;
    }
    return 1;
}

int handle_data(int fd, volatile jtag_t *jtag_ptr)
{
    const char xvcInfo[] = "xvcServer_v1.0:2048\n";

    do
    {
        char cmd[16];
        unsigned char buffer[2048], result[1024];
        memset(cmd, 0, 16);

        if (sread(fd, cmd, 2) != 1)
            return 1;

        if (memcmp(cmd, "ge", 2) == 0)
        {
            if (sread(fd, cmd, 6) != 1)
                return 1;
            memcpy(result, xvcInfo, strlen(xvcInfo));
            if (write(fd, result, strlen(xvcInfo)) != strlen(xvcInfo))
            {
                perror("write");
                return 1;
            }
            if (verbose) {
                printf("%u : Received command: 'getinfo'\n", (int) time(NULL));
                printf("\t Replied with %s\n", xvcInfo);
            }
            break;
        } else if (memcmp(cmd, "se", 2) == 0)
        {
            if (sread(fd, cmd, 9) != 1)
                return 1;
            memcpy(result, cmd + 5, 4);
            if (write(fd, result, 4) != 4)
            {
                perror("write");
                return 1;
            }
            if (verbose)
            {
                printf("%u : Received command: 'settck'\n", (int) time(NULL));
                printf("\t Replied with '%.*s'\n\n", 4, cmd + 5);
            }
            break;
        } else if (memcmp(cmd, "sh", 2) == 0)
        {
            if (sread(fd, cmd, 4) != 1)
                return 1;
            if (verbose)
                printf("%u : Received command: 'shift'\n", (int) time(NULL));
        } else
        {

            fprintf(stderr, "invalid cmd '%s'\n", cmd);
            return 1;
        }

        int len;
        if (sread(fd, &len, 4) != 1)
        {
            fprintf(stderr, "reading length failed\n");
            return 1;
        }

        int nr_bytes = (len + 7) / 8;
        if (nr_bytes * 2 > sizeof(buffer))
        {
            fprintf(stderr, "buffer size exceeded\n");
            return 1;
        }

        if (sread(fd, buffer, nr_bytes * 2) != 1)
        {
            fprintf(stderr, "reading data failed\n");
            return 1;
        }
        memset(result, 0, nr_bytes);

        if (verbose) {
            printf("\tNumber of Bits  : %d\n", len);
            printf("\tNumber of Bytes : %d \n", nr_bytes);
            printf("\n");
        }

        int bytesLeft = nr_bytes;
        int bitsLeft = len;
        int byteIndex = 0;
        int tdi, tms, tdo;

        while (bytesLeft > 0)
        {
            tms = 0;
            tdi = 0;
            tdo = 0;
            if (bitsLeft >= 32) {
                memcpy( &tms, & buffer[byteIndex], 4);
                memcpy( &tdi, & buffer[byteIndex + nr_bytes], 4);

                jtag_ptr->length_offset = 32;
                jtag_ptr->tms_offset = tms;
                jtag_ptr->tdi_offset = tdi;
                jtag_ptr->ctrl_offset = 0x01;
                while (jtag_ptr->ctrl_offset & 0x1)
                    ;

                tdo = jtag_ptr->tdo_offset;
                memcpy( &result[byteIndex], &tdo, 4);

                bytesLeft -= 4;
                bitsLeft -= 32;
                byteIndex += 4;

                if (verbose)
                {
                    printf("LEN : 0x%08x\n", 32);
                    printf("TMS : 0x%08x\n", tms);
                    printf("TDI : 0x%08x\n", tdi);
                    printf("TDO : 0x%08x\n", tdo);
                }

            }
            else
            {
                memcpy( &tms, &buffer[byteIndex], bytesLeft);
                memcpy( &tdi, &buffer[byteIndex + nr_bytes], bytesLeft);

                jtag_ptr->length_offset = bitsLeft;
                jtag_ptr->tms_offset = tms;
                jtag_ptr->tdi_offset = tdi;
                jtag_ptr->ctrl_offset = 0x01;
                while (jtag_ptr->ctrl_offset & 0x1)
                    ;

                tdo = jtag_ptr->tdo_offset;
                tdo >>= 32 - bitsLeft;

                memcpy( & result[byteIndex], &tdo, bytesLeft);

                if (verbose)
                {
                    printf("LEN : 0x%08x\n", bitsLeft);
                    printf("TMS : 0x%08x\n", tms);
                    printf("TDI : 0x%08x\n", tdi);
                    printf("TDO : 0x%08x\n", tdo);
                }
                break;
            }
        }
        if (write(fd, result, nr_bytes) != nr_bytes)
        {
            perror("write");
            return 1;
        }

    } while (1);
    /* Note: Need to fix JTAG state updates, until then no exit is allowed */
    return 0;
}

int main(int argc, char * * argv)
{
    int i, s;
    struct sockaddr_in address;
    exanic_t *exanic;
    char *device=0;
    uint32_t caps;

    if (argc < 2)
    {
        fprintf(stderr, "usage: %s: <device> [-v (verbose)]\n\n", argv[0]);
        return 1;
    }
    else if (argc >= 2)
        device = argv[1];
    if (argc == 3)
    {
        if (strcmp(argv[2], "-v") == 0)
            verbose = 1;
    }

    exanic = exanic_acquire_handle(device);
    if (exanic == NULL)
    {
        fprintf(stderr, "%s: %s\n", device, exanic_get_last_error());
        return 1;
    }
    // Ensure this image supports JTAG over PCIe
    caps = exanic_register_read(exanic, REG_EXANIC_INDEX(REG_EXANIC_CAPS));
    if ((caps & EXANIC_CAP_JTAG_ACCESS) == 0)
    {
        fprintf(stderr, "JTAG over PCIe is not supported on this image, please refer to ExaNIC FDK documentation\n");
        return 1;
    }
    s = socket(AF_INET, SOCK_STREAM, 0);

    if (s < 0)
    {
        perror("socket");
        return 1;
    }

    volatile jtag_t *jtag_ptr = (void*)&(exanic->registers[REG_HW_INDEX(REG_HW_JTAG_LENGTH)]);
    i = 1;
    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &i, sizeof i);

    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(2542);
    address.sin_family = AF_INET;

    if (bind(s, (struct sockaddr*)&address, sizeof(address)) < 0)
    {
        perror("bind");
        return 1;
    }

    if (listen(s, 0) < 0)
    {
        perror("listen");
        return 1;
    }

    fd_set conn;
    int maxfd = 0;

    FD_ZERO( &conn);
    FD_SET(s, &conn);

    maxfd = s;

    printf("Waiting for connection on port 2542...\n");
    while (1)
    {
        fd_set read = conn, except = conn;
        int fd;

        if (select(maxfd + 1, &read, 0, &except, 0) < 0)
        {
            perror("select");
            break;
        }

        for (fd = 0; fd <= maxfd; ++fd)
        {
            if (FD_ISSET(fd, & read))
            {
                if (fd == s)
                {
                    int newfd;
                    socklen_t nsize = sizeof(address);

                    newfd = accept(s, (struct sockaddr*) &address, &nsize);

                    printf("connection accepted\n");
                    if (newfd < 0)
                        perror("accept");
                    else
                    {
                        if (verbose)
                            printf("setting TCP_NODELAY to 1\n");
                        int flag = 1;
                        int ojtag_ptresult = setsockopt(newfd,
                            IPPROTO_TCP,
                            TCP_NODELAY,
                            (char*)&flag,
                            sizeof(int));
                        if (ojtag_ptresult < 0)
                            perror("TCP_NODELAY error");
                        if (newfd > maxfd)
                            maxfd = newfd;
                        FD_SET(newfd, &conn);
                    }
                }
                else if (handle_data(fd, jtag_ptr))
                {

                    printf("connection closed\n");
                    close(fd);
                    FD_CLR(fd, &conn);
                }
            }
            else if (FD_ISSET(fd, &except))
            {
                if (verbose)
                    printf("connection aborted - fd %d\n", fd);
                close(fd);
                FD_CLR(fd, &conn);
                if (fd == s)
                    break;
            }
        }
    }
    return 0;
}
