/**
 * \file
 * \brief The ioctl interface provided by the ExaNIC kernel driver
 *
 * Socket ioctls which can be used on the ethernet interface:
 * - \ref EXAIOCGIFINFO
 * - \ref EXAIOCGHWTSTAMP
 *
 * Ioctls which can be used on /dev/exanic*:
 * - \ref EXANICCTL_INFO
 * - \ref EXANICCTL_TX_BUFFER_ALLOC
 * - \ref EXANICCTL_TX_BUFFER_FREE
 * - \ref EXANICCTL_TX_FEEDBACK_ALLOC
 * - \ref EXANICCTL_TX_FEEDBACK_FREE
 */
#ifndef EXANIC_IOCTL_H
#define EXANIC_IOCTL_H

#include "const.h"

/** \brief Socket ioctl for retrieving information about an ExaNIC interface */
#define EXAIOCGIFINFO   (SIOCDEVPRIVATE+0)

/** \brief Socket ioctl for retrieving ExaNIC HW timestamping configuration
 *
 * This is equivalent of SIOCGHWTSTAMP ioctl (returns the configuration in
 * hwtstamp_config structure). It allows getting the configuration regardless
 * of kernel's support for SIOCGHWTSTAMP ioctl.
 */
#define EXAIOCGHWTSTAMP (SIOCDEVPRIVATE+1)

/**
 * \brief Info struct populated by EXAIOCGIFINFO ioctl
 */
struct exaioc_ifinfo
{
    char dev_name[16];
    uint16_t port_num;
    char __reserved[14];
};

#define EXANICCTL_TYPE              'x'

/** \brief Retrieve information about an ExaNIC */
#define EXANICCTL_INFO                      _IOR(EXANICCTL_TYPE, 0xe0, \
                                         struct exanicctl_info)
/** \brief Retrieve information about an ExaNIC (extended) */
#define EXANICCTL_INFO_EX                   _IOR(EXANICCTL_TYPE, 0xe0, \
                                         struct exanicctl_info_ex)
/** \brief Retrieve information about an ExaNIC (extended version 2) */
#define EXANICCTL_INFO_EX2                  _IOR(EXANICCTL_TYPE, 0xe0, \
                                         struct exanicctl_info_ex2)
/** \brief Request a TX buffer allocation from the kernel driver */
#define EXANICCTL_TX_BUFFER_ALLOC           _IOWR(EXANICCTL_TYPE, 0xe2, \
                                          struct exanicctl_tx_buffer_alloc)
/** \brief Release a TX buffer allocation */
#define EXANICCTL_TX_BUFFER_FREE            _IOW(EXANICCTL_TYPE, 0xe3, \
                                         struct exanicctl_tx_buffer_free)
/** \brief Request a TX feedback slot allocation from the kernel driver */
#define EXANICCTL_TX_FEEDBACK_ALLOC         _IOWR(EXANICCTL_TYPE, 0xe4, \
                                          struct exanicctl_tx_feedback_alloc)
/** \brief Release a TX feedback slot allocation */
#define EXANICCTL_TX_FEEDBACK_FREE          _IOW(EXANICCTL_TYPE, 0xe5, \
                                         struct exanicctl_tx_feedback_free)
/** \brief Allocate and set up an RX filter slot for an IP rule. */
#define EXANICCTL_RX_FILTER_ADD_IP          _IOWR(EXANICCTL_TYPE, 0xe6, \
                                          struct exanicctl_rx_filter_add_ip)
/** \brief Allocate and set up an RX filter slot for a MAC rule. */
#define EXANICCTL_RX_FILTER_ADD_MAC         _IOWR(EXANICCTL_TYPE, 0xe7, \
                                          struct exanicctl_rx_filter_add_mac)
/** \brief Disable and free a RX IP filter slot */
#define EXANICCTL_RX_FILTER_REMOVE_IP       _IOW(EXANICCTL_TYPE, 0xe8, \
                                         struct exanicctl_rx_filter_remove_ip)
/** \brief Disable and free a RX MAC filter slot */
#define EXANICCTL_RX_FILTER_REMOVE_MAC       _IOW(EXANICCTL_TYPE, 0xe9, \
                                         struct exanicctl_rx_filter_remove_mac)
/** \brief Allocate a RX filter buffer region. */
#define EXANICCTL_RX_FILTER_BUFFER_ALLOC    _IOW(EXANICCTL_TYPE, 0xea, \
                                        struct exanicctl_rx_filter_buffer_alloc)
/** \brief Allocate a RX filter buffer region (extended). */
#define EXANICCTL_RX_FILTER_BUFFER_ALLOC_EX _IOWR(EXANICCTL_TYPE, 0xea, \
                                        struct exanicctl_rx_filter_buffer_alloc)
/** \brief Free an RX filter buffer region. */
#define EXANICCTL_RX_FILTER_BUFFER_FREE     _IOW(EXANICCTL_TYPE, 0xeb, \
                                        struct exanicctl_rx_filter_buffer_free)
/** \brief Configure flow hashing for a port. */
#define EXANICCTL_RX_HASH_CONFIGURE         _IOW(EXANICCTL_TYPE, 0xec, \
                                          struct exanicctl_rx_hash_configure)
/** \brief Retrieve information about an ExaNIC devkit */
#define EXANICCTL_DEVKIT_INFO               _IOR(EXANICCTL_TYPE, 0xed, \
                                         struct exanicctl_devkit_info)
/** \brief Retrieve usage information about an Exanic */
#define EXANICCTL_DEVICE_USAGE              _IOR(EXANICCTL_TYPE, 0xee, \
                                         struct exanicctl_usage_info)
/** \brief Retrieve information about an ExaNIC devkit's extended regions */
#define EXANICCTL_DEVKIT_INFO_EX            _IOR(EXANICCTL_TYPE, 0xef, \
                                         struct exanicctl_devkit_info)

/**
 * \brief Arguments for EXANICCTL_INFO
 */
struct exanicctl_info
{
    size_t tx_buffer_size;            /* output */
    size_t filters_size;              /* output */
    int if_index[4];                  /* output */
};

/**
 * \brief Arguments for EXANICCTL_INFO_EX
 */
struct exanicctl_info_ex
{
    size_t tx_buffer_size;            /* output */
    size_t filters_size;              /* output */
    int if_index[4];                  /* output */
    int    max_buffers;               /* output */
};

/**
 * \brief Arguments for EXANICCTL_INFO_EX2
 */
struct exanicctl_info_ex2
{
    size_t tx_buffer_size;            /* output */
    size_t filters_size;              /* output */
    unsigned int max_buffers;         /* output */
    unsigned int num_ports;           /* output */
    unsigned int reserved[2];         /* output */
    int if_index[32];                 /* output */
};

/**
 * \brief Arguments for EXANICCTL_TX_BUFFER_ALLOC
 */
struct exanicctl_tx_buffer_alloc
{
    unsigned port_number;   /* input */
    size_t size;            /* input */
    size_t offset;          /* output */
};

/**
 * \brief Arguments for EXANICCTL_TX_BUFFER_FREE
 */
struct exanicctl_tx_buffer_free
{
    unsigned port_number;   /* input */
    size_t size;            /* input */
    size_t offset;          /* input */
};

/**
 * \brief Arguments for EXANICCTL_TX_FEEDBACK_ALLOC
 */
struct exanicctl_tx_feedback_alloc
{
    unsigned port_number;   /* input */
    unsigned feedback_slot; /* output */
};

/**
 * \brief Arguments for EXANICCTL_TX_FEEDBACK_FREE
 */
struct exanicctl_tx_feedback_free
{
    unsigned port_number;   /* input */
    unsigned feedback_slot; /* input */
};

/**
 * \brief Arguments for EXANICCTL_RX_FILTER_ADD_IP
 */
struct exanicctl_rx_filter_add_ip
{
    unsigned port_number;   /* input */
    unsigned filter_id;     /* output */
    unsigned buffer_number; /* input */
    uint32_t src_addr;      /* input */
    uint32_t dst_addr;      /* input */
    uint16_t src_port;      /* input */
    uint16_t dst_port;      /* input */
    uint8_t protocol;       /* input */
};

/**
 * \brief Arguments for EXANICCTL_RX_FILTER_ADD_MAC.
 */
struct exanicctl_rx_filter_add_mac
{
    unsigned port_number;       /* input */
    unsigned filter_id;         /* output */
    unsigned buffer_number;     /* input */
    uint8_t dst_mac[6];         /* input */
    uint16_t ethertype;         /* input */
    uint16_t vlan;              /* input */
    uint16_t vlan_match_method; /* input */
};

/**
 * \brief Arguments for EXANICCTL_RX_FILTER_BUFFER_ALLOC
 */
struct exanicctl_rx_filter_buffer_alloc
{
    unsigned port_number;   /* input */
    unsigned buffer_number; /* input/output */
};

/**
 * \brief Arguments for EXANICCTL_RX_FILTER_BUFFER_FREE
 */
struct exanicctl_rx_filter_buffer_free
{
    unsigned port_number;   /* input */
    unsigned buffer_number; /* input */
};

/**
 * \brief Arguments for EXANICCTL_IP_FILTER_REMOVE_IP
 */
struct exanicctl_rx_filter_remove_ip
{
    unsigned port_number;   /* input */
    unsigned filter_id;     /* input */
};

/**
 * \brief Arguments for EXANICCTL_IP_FILTER_REMOVE_MAC
 */
struct exanicctl_rx_filter_remove_mac
{
    unsigned port_number;   /* input */
    unsigned filter_id;     /* input */
};

/**
 * \brief Arguments for EXANICCTL_RX_HASH_CONFIGURE
 */
struct exanicctl_rx_hash_configure
{
    unsigned port_number;   /* input */
    unsigned enable;        /* input */
    unsigned mask;          /* input */
    unsigned function;      /* input */
};

/**
 * \brief Arguments for EXANICCTL_DEVKIT_INFO
 */
struct exanicctl_devkit_info
{
    unsigned regs_size;     /* output */
    unsigned mem_size;      /* output */
};

/**
 * \brief Arguments for EXANICCTL_DEVICE_USAGE
 */
struct exanicctl_usage_info
{
    int users;              /* output */
};

/**
 * \brief ExaNIC info page
 *
 * This defines the layout of the shared memory region that the
 * ExaNIC kernel module uses to pass information to userspace.
 */
struct exanic_info_page
{
    /**
     * \brief Current hardware time (upper 33 bits).
     */
    uint64_t hw_time;
};

#endif /* EXANIC_IOCTL_H */
