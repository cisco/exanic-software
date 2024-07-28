#include <string.h>
#include <ctype.h>
#include <signal.h>
#include <unistd.h>
#include <stdio.h>
#include <errno.h>
#include <time.h>
#include <endian.h>
#include <net/if.h>
#include <sys/ioctl.h>

#include <exanic/exanic.h>
#include <exanic/config.h>
#include <exanic/port.h>
#include <exanic/fifo_rx.h>
#include <exanic/time.h>
#include <exanic/filter.h>

#include "pcap-structures.h"

typedef enum
{
    FORMAT_PCAP = 0,
    FORMAT_ERF = 1,
} file_format_type;


volatile int run = 1;

void signal_handler(int signum)
{
    run = 0;
}

/* Parses a string of the format "<device>:<port>" */
int parse_device_port(const char *str, char *device, int *port_number)
{
    char *p, *q;

    p = strchr(str, ':');
    if (p == NULL)
        return -1;

    if ((p-str) >= 16)
        return -1;
    strncpy(device, str, p - str);
    device[p - str] = '\0';
    *port_number = strtol(p + 1, &q, 10);
    if (*(p + 1) == '\0' || *q != '\0')
        /* strtol failed */
        return -1;
    return 0;
}

int parse_one_filter(char ***argv, int *argc, exanic_ip_filter_t *filter, int *bidir)
{
    struct in_addr ip_addr;
    char *endptr;
    int host_specified = 0, dst_specified = 0, src_specified = 0;
    int port_specified = 0, dport_specified = 0, sport_specified = 0;
    int proto_specified = 0;

    memset(filter, 0, sizeof(*filter));
    while (*argc)
    {
        if (strcmp((*argv)[0], "host") == 0)
        {
            if (host_specified)
                 return 0;
            if (dst_specified || src_specified || dport_specified || sport_specified)
                 return 0;
            (*argv)++; (*argc)--;
            if (!*argc || inet_aton((*argv)[0], &ip_addr) == 0)
                return 0;
            filter->dst_addr = ip_addr.s_addr;
            (*argv)++; (*argc)--;
            host_specified = 1;
        }
        else if (strcmp((*argv)[0], "dst") == 0)
        {
            if (dst_specified)
                return 0;
            if (host_specified || port_specified)
                return 0;
            (*argv)++; (*argc)--;
            if (!*argc || inet_aton((*argv)[0], &ip_addr) == 0)
                return 0;
            filter->dst_addr = ip_addr.s_addr;
            (*argv)++; (*argc)--;
            dst_specified = 1;
        }
        else if (strcmp((*argv)[0], "src") == 0)
        {
            if (src_specified)
                return 0;
            if (host_specified || port_specified)
                return 0;
            (*argv)++; (*argc)--;
            if (!*argc || inet_aton((*argv)[0], &ip_addr) == 0)
                return 0;
            filter->src_addr = ip_addr.s_addr;
            (*argv)++; (*argc)--;
            src_specified = 1;
        }
        else if (strcmp((*argv)[0], "port") == 0)
        {
            if (port_specified)
                return 0;
            if (dst_specified || src_specified || dport_specified || sport_specified)
                 return 0;
            (*argv)++; (*argc)--;
            if (!*argc)
                return 0;
            filter->dst_port = htons(strtoul((*argv)[0], &endptr, 0));
            if (*endptr != 0)
                return 0;
            (*argv)++; (*argc)--;
            port_specified = 1;
        }
        else if (strcmp((*argv)[0], "dport") == 0)
        {
            if (dport_specified)
                return 0;
            if (host_specified || port_specified)
                return 0;
            (*argv)++; (*argc)--;
            if (!*argc)
                return 0;
            filter->dst_port = htons(strtoul((*argv)[0], &endptr, 0));
            if (*endptr != 0)
                return 0;
            (*argv)++; (*argc)--;
            dport_specified = 1;
        }
        else if (strcmp((*argv)[0], "sport") == 0)
        {
            if (dport_specified)
                return 0;
            if (host_specified || port_specified)
                return 0;
            (*argv)++; (*argc)--;
            if (!*argc)
                return 0;
            filter->src_port = htons(strtoul((*argv)[0], &endptr, 0));
            if (*endptr != 0)
                return 0;
            (*argv)++; (*argc)--;
            sport_specified = 1;
        }
        else if (strcmp((*argv)[0], "tcp") == 0)
        {
            if (proto_specified)
                return 0;
            filter->protocol = 6;
            (*argv)++; (*argc)--;
            proto_specified = 1;
        }
        else if (strcmp((*argv)[0], "udp") == 0)
        {
            if (proto_specified)
                return 0;
            filter->protocol = 17;
            (*argv)++; (*argc)--;
            proto_specified = 1;
        }
        else if (strcmp((*argv)[0], "or") == 0)
        {
            (*argv)++; (*argc)--;
            *bidir = host_specified || port_specified;
            return 1;
        }
        else
           return 0;
    }

    *bidir = host_specified || port_specified;
    return (*argc == 0);
}

int apply_filters(exanic_t *exanic, exanic_rx_t *rx, char **argv, int argc)
{
    exanic_ip_filter_t filter;
    int bidir;

    while (argc && parse_one_filter(&argv, &argc, &filter, &bidir))
    {
        int ret = exanic_filter_add_ip(exanic, rx, &filter);
        if ((ret != -1) && bidir)
        {
            filter.src_addr = filter.dst_addr;
            filter.dst_addr = 0;
            filter.src_port = filter.dst_port;
            filter.dst_port = 0;
            ret = exanic_filter_add_ip(exanic, rx, &filter);
        }
        if (ret == -1)
        {
            fprintf(stderr, "error adding filter: %s\n", exanic_get_last_error());
            return 0;
        }
    }

    if (argc != 0)
    {
        fprintf(stderr, "parse error near %s\n", argv[0]);
        return 0;
    }

    return 1;
}

unsigned write_pcap_header(FILE *fp, int nsec_pcap, int snaplen)
{
    struct pcap_file_header hdr;
    hdr.magic = nsec_pcap ? NSEC_TCPDUMP_MAGIC : TCPDUMP_MAGIC;
    hdr.version_major = PCAP_VERSION_MAJOR;
    hdr.version_minor = PCAP_VERSION_MINOR;
    hdr.thiszone = 0;
    hdr.sigfigs = 0; /* 9? libpcap always writes 0 */
    hdr.snaplen = snaplen;
    hdr.linktype = DLT_EN10MB;
    fwrite(&hdr, sizeof(hdr), 1, fp);
    return sizeof(hdr);
}

unsigned write_pcap_packet(char *data, ssize_t len, struct exanic_timespecps *tsps,
                       int nsec_pcap, int snaplen, FILE *fp)
{
    struct pcap_pkthdr hdr;
    ssize_t caplen = (len > snaplen) ? snaplen : len;
    hdr.ts_sec = tsps->tv_sec;
    hdr.ts_usec = nsec_pcap ? (tsps->tv_psec / 1000) : (tsps->tv_psec/1000/1000);
    hdr.caplen = caplen;
    hdr.len = len;
    fwrite(&hdr, sizeof(hdr), 1, fp);
    fwrite(data, 1, caplen, fp);
    return sizeof(hdr) + caplen;
}

/* https://wiki.wireshark.org/ERF */
struct erf_record
{
    uint32_t ts_frac;
    uint32_t ts_sec;
    uint8_t type;
    uint8_t flags;
    uint16_t rlen;
    uint16_t lctr;
    uint16_t wlen;
    uint16_t eth_pad;
};

unsigned write_erf_packet(char *data, ssize_t len, struct exanic_timespecps *tsps,
                          int port, int snaplen, FILE *fp)
{
    struct erf_record hdr;
    const size_t size_hdr = 18;
    // times in little endian
    hdr.ts_sec = htole32(tsps->tv_sec);

    /* convert to 32 bit binary fraction of a second
     * The simplest way to think of this conversion is to convert picoseconds to
     * fractions of a second (ps / 10**12) and then to multiply by 0x100000000
     * (1 << 32), resulting in a 32bit binary fraction. Rearranging for integer
     * maths this becomes (ps << 32) / 10**12. This can potentially roll over
     * for large picosecond values. It can however be factored by observing that
     * 10**12 = 2**12 * 5**12. Thus:
     * (ps << ( 32 - 12) ) / (5**12)  = (ps << 20) / 244140625.
     * This does not roll over even for large picosecond values (e.g. 10**12-1)
     */
    const uint64_t ps = tsps->tv_psec;
    const uint32_t erfbinfrac = (ps << 20) / 244140625;
    hdr.ts_frac = htole32(erfbinfrac);

    hdr.type = 2; // type ETH with no extension header
    hdr.flags = 1 << 2; // variable length record
    hdr.flags |= (port & 0x3);
    ssize_t caplen = (len > snaplen) ? snaplen : len;
    hdr.rlen = htons(caplen + size_hdr);
    hdr.lctr = 0;
    hdr.wlen = htons(len);
    hdr.eth_pad = 0;
    fwrite(&hdr, size_hdr, 1, fp);
    fwrite(data, 1, caplen, fp);
    return size_hdr + caplen;
}

void print_time(struct exanic_timespecps *tsps)
{
    struct tm tm;
    localtime_r((time_t*)&tsps->tv_sec, &tm);

    printf("%04d%02d%02dT%02d%02d%02d.%012ld ",
           tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
           tm.tm_hour, tm.tm_min, tm.tm_sec,
           tsps->tv_psec);
}

void print_hexdump(char *data, int len)
{
    char ascii[16];
    int i, rem;

    for (i = 0; i < len; )
    {
        if ((i % 16) == 0)
            printf("%04x: ", i);

        printf("%02x", (unsigned char)data[i]);
        if (isprint(data[i]))
            ascii[i%16] = data[i];
        else
            ascii[i%16] = '.';
        i++;

        if ((i % 2) == 0)
            printf(" ");
        if ((i % 16) == 0)
            printf(" %.16s\n", ascii);
    }
    rem = i % 16;
    if (rem)
        printf("%*.*s\n", 2*(16-rem)+((16-rem+1)/2)+rem+1, rem, ascii);
}

/* TODO: Clean up interface of this function and put into libexanic */
ssize_t exanic_receive_frame_ex(exanic_rx_t *rx, char *rx_buf,
                                size_t rx_buf_size, uint32_t *timestamp,
                                int *frame_status)
{
    union {
        struct rx_chunk_info info;
        uint64_t data;
    } u;

    u.data = rx->buffer[rx->next_chunk].u.data;

    if (u.info.generation == rx->generation)
    {
        size_t size = 0;

        /* Next expected packet */
        while (1)
        {
            const char *payload = (char *)rx->buffer[rx->next_chunk].payload;

            /* Advance next_chunk to next chunk */
            rx->next_chunk++;
            if (rx->next_chunk == EXANIC_RX_NUM_CHUNKS)
            {
                rx->next_chunk = 0;
                rx->generation++;
            }

            /* Process current chunk */
            if (u.info.length != 0)
            {
                /* Last chunk */
                if (size + u.info.length > rx_buf_size)
                {
                    if (frame_status != NULL)
                        *frame_status = EXANIC_RX_FRAME_TRUNCATED;
                    return -1;
                }

                memcpy(rx_buf + size, payload, u.info.length);
                size += u.info.length;

                /* TODO: Recheck that we haven't been lapped */

                if (timestamp != NULL)
                    *timestamp = u.info.timestamp;

                if (frame_status != NULL)
                    *frame_status =
                        (u.info.frame_status & EXANIC_RX_FRAME_ERROR_MASK);

                return size;
            }
            else
            {
                /* More chunks to come */
                if (size + EXANIC_RX_CHUNK_PAYLOAD_SIZE <= rx_buf_size)
                    memcpy(rx_buf + size, payload,
                            EXANIC_RX_CHUNK_PAYLOAD_SIZE);
                size += EXANIC_RX_CHUNK_PAYLOAD_SIZE;

                /* Spin on next chunk */
                do
                    u.data = rx->buffer[rx->next_chunk].u.data;
                while (u.info.generation == (uint8_t)(rx->generation - 1));

                if (u.info.generation != rx->generation)
                {
                    /* Got lapped? */
                    __exanic_rx_catchup(rx);
                    if (frame_status != NULL)
                        *frame_status = EXANIC_RX_FRAME_SWOVFL;
                    return -1;
                }
            }
        }
    }
    else if (u.info.generation == (uint8_t)(rx->generation - 1))
    {
        /* No new packet */
        if (frame_status != NULL)
            *frame_status = 0;
        return -1;
    }
    else
    {
        /* Got lapped? */
        __exanic_rx_catchup(rx);
        if (frame_status != NULL)
            *frame_status = EXANIC_RX_FRAME_SWOVFL;
        return -1;
    }
}

static int set_promiscuous_mode(exanic_t *exanic, int port_number, int enable)
{
    struct ifreq ifr;
    int fd, ret;

    memset(&ifr, 0, sizeof(ifr));
    if (exanic_get_interface_name(exanic, port_number, ifr.ifr_name,
                                  sizeof(ifr.ifr_name)) == -1)
    {
        fprintf(stderr, "%s:%d: %s\n", exanic->name, port_number,
                exanic_get_last_error());
        return -1;
    }

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    ret = ioctl(fd, SIOCGIFFLAGS, &ifr);
    if (ret != -1)
    {
        if (enable)
            ifr.ifr_flags |= IFF_PROMISC;
        else
            ifr.ifr_flags &= ~IFF_PROMISC;

        ret = ioctl(fd, SIOCSIFFLAGS, &ifr);
    }
    close(fd);

    if (ret == -1)
    {
        fprintf(stderr, "failed to %s promiscuous mode (%s)%s\n",
                enable ? "enable" : "disable", strerror(errno),
                enable ? ", continuing anyway" : "");
        return -1;
    }

    return 0;
}

struct exanic_rx_context
{
    char device[16];
    int port_number;
    exanic_t *exanic;
    exanic_rx_t *rx;
    int set_promisc;
    exanic_cycles_t utc_offset_cycles;
};

#define EXA_MAX_IFACES 8

int main(int argc, char *argv[])
{
    const char *savefile = NULL;
    FILE *savefp = NULL;
    struct exanic_rx_context rx_ctxs[EXA_MAX_IFACES];
    int rx_ctxs_no = 0;
    int rx_ctx_idx = 0;
    char rx_buf[16384];
    ssize_t rx_size;
    int status;
    exanic_cycles32_t timestamp;
    int utc_offset_sec = 0;
    struct timespec ts;
    struct exanic_timespecps tsps;
    int hw_tstamp = 0, nsec_pcap = 0, snaplen = sizeof(rx_buf), flush = 0;
    int promisc = 1, filter;
    unsigned long rx_success = 0, rx_aborted = 0, rx_corrupt = 0,
                  rx_hwovfl = 0, rx_swovfl = 0, rx_other = 0;
    file_format_type file_format = FORMAT_PCAP;
    int file_no = 0, monitor_file_size = 0;
    unsigned long file_size = 0, file_size_limit = 0;
    char file_name_buf[4096];
    int c;

    memset(&rx_ctxs, 0, sizeof(rx_ctxs));

    while ((c = getopt(argc, argv, "i:w:s:C:F:U:pHNh?")) != -1)
    {
        switch (c)
        {
            case 'i':
                if (rx_ctxs_no >= EXA_MAX_IFACES)
                {
                    fprintf(stderr, "maximum interfaces supported: %d\n", EXA_MAX_IFACES);
                    return 1;
                }

                if (exanic_find_port_by_interface_name(
                    optarg, rx_ctxs[rx_ctxs_no].device, 16, &rx_ctxs[rx_ctxs_no].port_number) != 0
                    &&
                    parse_device_port(
                    optarg, rx_ctxs[rx_ctxs_no].device, &rx_ctxs[rx_ctxs_no].port_number) != 0)
                {
                    fprintf(stderr, "%s: no such interface or not an ExaNIC\n", optarg);
                    return 1;
                }

                ++rx_ctxs_no;
                break;
            case 'w':
                savefile = optarg;
                break;
            case 's':
                snaplen = atoi(optarg);
                break;
            case 'C':
                /* as per tcpdump */
                file_size_limit = 1000000L * atoi(optarg);
                break;
            case 'F':
                /* formats as per editcap */
                if (strcmp(optarg, "pcap") == 0)
                    file_format = FORMAT_PCAP;
                else if (strcmp(optarg, "erf") == 0)
                    file_format = FORMAT_ERF;
                else
                    goto usage_error;
                break;
            case 'U':
                utc_offset_sec = atoi(optarg);
                break;
            case 'p':
                promisc = 0;
                break;
            case 'H':
                hw_tstamp = 1;
                break;
            case 'N':
                nsec_pcap = 1;
                break;
            default:
                goto usage_error;
        }
    }

    if (rx_ctxs_no == 0)
        goto usage_error;

    if (savefile != NULL)
    {
        if (strcmp(savefile, "-") == 0)
        {
            savefp = stdout;
            flush = 1;
        }
        else
        {
            savefp = fopen(savefile, "w");
            if (!savefp)
            {
                perror(savefile);
                goto err_open_savefile;
            }
            /* monitor file size iff we have a name and a size */
            if (file_size_limit)
                monitor_file_size = 1;
        }
        if (file_format == FORMAT_PCAP)
            file_size = write_pcap_header(savefp, nsec_pcap, snaplen);
    }

    for (int i = 0; i < rx_ctxs_no; ++i)
    {
        /* Get the exanic handle */
        rx_ctxs[i].exanic = exanic_acquire_handle(rx_ctxs[i].device);
        if (rx_ctxs[i].exanic == NULL)
        {
            fprintf(stderr, "%s: %s\n", rx_ctxs[i].device, exanic_get_last_error());
            goto err_acquire_handle;
        }

        filter = optind < argc;
        if (filter)
            rx_ctxs[i].rx = exanic_acquire_unused_filter_buffer(rx_ctxs[i].exanic, rx_ctxs[i].port_number);
        else
            rx_ctxs[i].rx = exanic_acquire_rx_buffer(rx_ctxs[i].exanic, rx_ctxs[i].port_number, 0);

        if (rx_ctxs[i].rx == NULL)
        {
            fprintf(stderr, "%s:%d: %s\n", rx_ctxs[i].device, rx_ctxs[i].port_number,
                    exanic_get_last_error());
            goto err_acquire_rx;
        }

        if (filter && !apply_filters(rx_ctxs[i].exanic, rx_ctxs[i].rx, &argv[optind], argc-optind))
            goto err_apply_filters;

        rx_ctxs[i].set_promisc = promisc && !exanic_get_promiscuous_mode(rx_ctxs[i].exanic, rx_ctxs[i].port_number);

        if (rx_ctxs[i].set_promisc)
        {
            if (set_promiscuous_mode(rx_ctxs[i].exanic, rx_ctxs[i].port_number, 1) == -1)
                rx_ctxs[i].set_promisc = 0;
        }

        rx_ctxs[i].utc_offset_cycles = rx_ctxs[i].exanic->tick_hz * utc_offset_sec;
    }

    signal(SIGHUP, signal_handler);
    signal(SIGINT, signal_handler);
    signal(SIGPIPE, signal_handler);
    signal(SIGALRM, signal_handler);
    signal(SIGTERM, signal_handler);

    /* Start reading from the rx buffer */
    while (run)
    {
        rx_size = exanic_receive_frame_ex(rx_ctxs[rx_ctx_idx].rx, rx_buf, sizeof(rx_buf),
                &timestamp, &status);

        if (rx_size < 0 && status == EXANIC_RX_FRAME_OK)
        {
            rx_ctx_idx = (rx_ctx_idx + 1) % rx_ctxs_no;
            continue;
        }

        /* Get timestamp */
        if (rx_size > 0 && hw_tstamp)
        {
            const uint64_t timestamp64 = exanic_expand_timestamp(rx_ctxs[rx_ctx_idx].exanic, timestamp)
                + rx_ctxs[rx_ctx_idx].utc_offset_cycles; /* Add optional UTC offset in cycles */
            exanic_cycles_to_timespecps(rx_ctxs[rx_ctx_idx].exanic, timestamp64, &tsps);
        }
        else
        {
            clock_gettime(CLOCK_REALTIME, &ts);
            tsps.tv_sec = ts.tv_sec;
            tsps.tv_psec = ts.tv_nsec * 1000ULL;
        }

        if (savefp != NULL)
        {
            /* Log to pcap file */
            if (rx_size > 0)
            {
                /* as per tcpdump, create new file, if the current file exceeds the limit */
                if (monitor_file_size && file_size > file_size_limit)
                {
                    fclose(savefp);
                    savefp = NULL;
                    ++file_no;
                    if (snprintf(file_name_buf, 4096, "%s%d", savefile, file_no) == 4096)
                    {
                        fprintf(stderr, "%s%d: filename overflow\n", savefile, file_no);
                        goto err_open_next_file;
                    }
                    savefp = fopen(file_name_buf, "w");
                    if (!savefp)
                    {
                        perror(file_name_buf);
                        goto err_open_next_file;
                    }
                    if (file_format == FORMAT_PCAP)
                        file_size = write_pcap_header(savefp, nsec_pcap, snaplen);
                }
                if (file_format == FORMAT_PCAP)
                    file_size += write_pcap_packet(rx_buf, rx_size, &tsps, nsec_pcap,
                                                   snaplen, savefp);
                else if (file_format == FORMAT_ERF)
                    file_size += write_erf_packet(rx_buf, rx_size, &tsps,
                                                  rx_ctxs[rx_ctx_idx].port_number,
                                                  snaplen, savefp);
                if (flush)
                    fflush(savefp);
            }
        }
        else
        {
            /* Dump to stdout */
            print_time(&tsps);
            if (rx_size > 0)
            {
                if (status == EXANIC_RX_FRAME_OK)
                    printf("received %zd bytes\n", rx_size);
                else if (status == EXANIC_RX_FRAME_CORRUPT)
                    printf("received %zd bytes with bad CRC\n", rx_size);
                else
                    printf("received %zd bytes with unknown error id %d\n", rx_size, status);
                print_hexdump(rx_buf, (rx_size > snaplen) ? snaplen : rx_size);
            }
            else
            {
                if (status == EXANIC_RX_FRAME_ABORTED)
                    printf("sender aborted frame\n");
                else if (status == EXANIC_RX_FRAME_HWOVFL)
                    printf("frames lost due to insufficient PCIe/memory bandwidth\n");
                else if (status == EXANIC_RX_FRAME_SWOVFL)
                    printf("frames lost due to capture program too slow (usually a scheduling issue)\n");
                else if (status == EXANIC_RX_FRAME_TRUNCATED)
                    printf("unexpectedly long (>16KB) frame received\n");
                else
                    printf("unknown error\n");
            }
        }

        /* Update counters */
        if (status == EXANIC_RX_FRAME_OK)
            rx_success++;
        else if (status == EXANIC_RX_FRAME_CORRUPT)
            rx_corrupt++;
        else if (status == EXANIC_RX_FRAME_ABORTED)
            rx_aborted++;
        else if (status == EXANIC_RX_FRAME_HWOVFL)
            rx_hwovfl++;
        else if (status == EXANIC_RX_FRAME_SWOVFL)
            rx_swovfl++;
        else
            rx_other++;
    }

    fprintf(stderr, "%s: received=%lu corrupt=%lu aborted=%lu hw_lost=%lu sw_lost=%lu other=%lu\n",
                     argv[0], rx_success, rx_corrupt, rx_aborted, rx_hwovfl, rx_swovfl, rx_other);

    if (savefp != NULL)
        fclose(savefp);
    return 0;

err_open_next_file:
err_apply_filters:
err_acquire_rx:
    for (int i = 0; i < rx_ctxs_no; ++i)
    {
        if (rx_ctxs[i].set_promisc && rx_ctxs[i].exanic)
            set_promiscuous_mode(rx_ctxs[i].exanic, rx_ctxs[i].port_number, 0);

        if (rx_ctxs[i].rx)
            exanic_release_rx_buffer(rx_ctxs[i].rx);

        if (rx_ctxs[i].exanic)
            exanic_release_handle(rx_ctxs[i].exanic);
    }
err_acquire_handle:
    if (savefp != NULL)
        fclose(savefp);
err_open_savefile:
    return 1;

usage_error:
    fprintf(stderr, "Usage: %s -i interface...\n", argv[0]);
    fprintf(stderr, "           [-w savefile] [-s snaplen] [-C file_size]\n");
    fprintf(stderr, "           [-F file_format] [-p] [-H] [-N] [filter...]\n");
    fprintf(stderr, "  -i: specify Linux interface (e.g. eth0) or ExaNIC port name (e.g. exanic0:0)\n");
    fprintf(stderr, "  -w: dump frames to given file in specified format (- for stdout)\n");
    fprintf(stderr, "  -s: maximum data length to capture\n");
    fprintf(stderr, "  -C: file size at which to start a new save file (in millions of bytes)\n");
    fprintf(stderr, "  -F: file format [pcap|erf] (default is pcap)\n");
    fprintf(stderr, "  -U: UTC offset to add to hardware timestamp (in seconds)\n");
    fprintf(stderr, "  -p: do not attempt to put interface in promiscuous mode\n");
    fprintf(stderr, "  -H: use hardware timestamps (refer to documentation on how to sync clock)\n");
    fprintf(stderr, "  -N: write nanosecond-resolution pcap format\n\n");
    fprintf(stderr, "Filter examples:\n");
    fprintf(stderr, "  tcp port 80                   (to/from tcp port 80)\n");
    fprintf(stderr, "  host 192.168.0.1 tcp port 80  (to/from 192.168.0.1:80)\n");
    fprintf(stderr, "  dst 192.168.0.1 dport 53      (to 192.168.0.1:53, either tcp or udp)\n");
    fprintf(stderr, "  src 192.168.0.5 sport 80 or dst 192.168.0.1 (combine clauses with 'or')\n");
    return 1;
}
