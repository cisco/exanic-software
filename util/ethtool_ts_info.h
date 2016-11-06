/* replacement for missing ETHTOOL_GET_TS_INFO in system headers */

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

