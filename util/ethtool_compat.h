/* Replacements for missing ethtool definitions in system headers */

#ifndef ETHTOOL_GET_TS_INFO
struct ethtool_ts_info {
        __u32   cmd;
        __u32   so_timestamping;
        __s32   phc_index;
        __u32   tx_types;
        __u32   tx_reserved[3];
        __u32   rx_filters;
        __u32   rx_reserved[3];
};

#define ETHTOOL_GET_TS_INFO     0x00000041 /* Get time stamping and PHC info */
#endif

#ifndef ETHTOOL_SFECPARAM
struct ethtool_fecparam {
        __u32   cmd;
        __u32   active_fec;
        __u32   fec;
        __u32   reserved;
};

enum ethtool_fec_config_bits {
        ETHTOOL_FEC_NONE_BIT,
        ETHTOOL_FEC_AUTO_BIT,
        ETHTOOL_FEC_OFF_BIT,
        ETHTOOL_FEC_RS_BIT,
        ETHTOOL_FEC_BASER_BIT,
};

#define ETHTOOL_FEC_NONE  (1 << ETHTOOL_FEC_NONE_BIT)
#define ETHTOOL_FEC_AUTO  (1 << ETHTOOL_FEC_AUTO_BIT)
#define ETHTOOL_FEC_OFF   (1 << ETHTOOL_FEC_OFF_BIT)
#define ETHTOOL_FEC_RS    (1 << ETHTOOL_FEC_RS_BIT)
#define ETHTOOL_FEC_BASER (1 << ETHTOOL_FEC_BASER_BIT)

#define ETHTOOL_SFECPARAM       0x00000051 /* Set FEC settings */
#endif
