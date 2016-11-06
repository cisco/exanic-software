/* copied from libpcap to avoid dependency */

#include <stdint.h>
#include <sys/time.h>

#define TCPDUMP_MAGIC      0xa1b2c3d4
#define NSEC_TCPDUMP_MAGIC 0xa1b23c4d
#define PCAP_VERSION_MAJOR 2
#define PCAP_VERSION_MINOR 4
#define DLT_EN10MB         1

struct pcap_file_header {
        uint32_t magic;
        uint16_t version_major;
        uint16_t version_minor;
        uint32_t thiszone;   /* gmt to local correction */
        uint32_t sigfigs;    /* accuracy of timestamps */
        uint32_t snaplen;    /* max length saved portion of each pkt */
        uint32_t linktype;   /* data link type (LINKTYPE_*) */
};

struct pcap_pkthdr {
        uint32_t ts_sec;     /* time stamp */
        uint32_t ts_usec;
        uint32_t caplen;     /* length of portion present */
        uint32_t len;        /* length this packet (off wire) */
};

