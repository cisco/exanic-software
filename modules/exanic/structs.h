/**
 * ExaNIC driver
 * Copyright (C) 2011-2013 Exablaze Pty Ltd and its licensors
 */

#if defined(CONFIG_PTP_1588_CLOCK) || defined(CONFIG_PTP_1588_CLOCK_MODULE)
#include <linux/ptp_clock_kernel.h>
#endif

/**
 * A context is allocated for each open file descriptor and for each
 * in-kernel user of the driver.
 */
struct exanic_ctx
{
    struct exanic *exanic;
    int check_numa_node;
    unsigned long tx_region_bitmap[
        BITS_TO_LONGS(EXANIC_TX_REGION_MAX_NUM_PAGES)];
    unsigned long tx_feedback_bitmap[
        BITS_TO_LONGS(EXANIC_TX_FEEDBACK_NUM_SLOTS)];
    unsigned int rx_refcount[EXANIC_MAX_PORTS];
    struct list_head filter_buffer_ref_list;
};

struct exanic_port
{
    void *rx_region_virt;
    dma_addr_t rx_region_dma;
    unsigned int rx_refcount; /* Only counts in-kernel users. */
    unsigned numa_node;
    size_t tx_region_usable_offset;
    size_t tx_region_usable_size;

    bool enabled;
    bool power;
    bool flow_hashing_enabled;

    unsigned int max_ip_filter_slots;
    unsigned int max_mac_filter_slots;
    unsigned int num_hash_functions;

    struct exanic_filter_buffer *filter_buffers;
    struct exanic_ip_filter_slot *ip_filter_slots;
    struct exanic_mac_filter_slot *mac_filter_slots;
    spinlock_t filter_lock;

    /* MAC address before any user changes */
    unsigned char orig_mac_addr[ETH_ALEN];
};

#if defined(CONFIG_PTP_1588_CLOCK) || defined(CONFIG_PTP_1588_CLOCK_MODULE)
enum per_out_mode
{
    PER_OUT_NONE,
    PER_OUT_1PPS,
    PER_OUT_10M,
};
#endif

struct exanic
{
    struct miscdevice misc_dev;
    struct pci_dev *pci_dev;

    struct timer_list link_timer;
    struct mutex mutex;

    void *regs_virt;
    void *tx_feedback_virt;
    void *tx_region_virt;
    void *devkit_regs_virt;
    void *devkit_mem_virt;
    struct exanic_info_page *info_page;
    phys_addr_t regs_phys;
    phys_addr_t filters_phys;
    phys_addr_t tx_region_phys;
    phys_addr_t devkit_regs_phys;
    phys_addr_t devkit_mem_phys;
    dma_addr_t tx_feedback_dma;

    unsigned int dma_addr_bits;
    size_t regs_size;
    size_t filters_size;
    size_t tx_region_size;

    struct exanic_port port[EXANIC_MAX_PORTS];
    unsigned int max_filter_buffers;

    unsigned long tx_region_bitmap[
        BITS_TO_LONGS(EXANIC_TX_REGION_MAX_NUM_PAGES)];
    unsigned long tx_feedback_bitmap[
        BITS_TO_LONGS(EXANIC_TX_FEEDBACK_NUM_SLOTS)];

    unsigned int pcie_if_ver;
    unsigned int hw_id;
    unsigned int function_id;
    unsigned int id;
    unsigned int devkit_regs_offset;
    unsigned int devkit_mem_offset;
    unsigned int num_ports;
    uint32_t caps;

    char name[8];

    struct net_device *ndev[EXANIC_MAX_PORTS];

#if defined(CONFIG_PTP_1588_CLOCK) || defined(CONFIG_PTP_1588_CLOCK_MODULE)
    struct ptp_clock *ptp_clock;
    struct ptp_clock_info ptp_clock_info;
    struct hrtimer ptp_clock_hrtimer;
    spinlock_t ptp_clock_lock;

    uint32_t tick_hz;
    uint64_t tick_rollover_counter;

    struct hrtimer phc_pps_hrtimer;
    bool phc_pps_enabled;
    time_t last_phc_pps;

    enum per_out_mode per_out_mode;
    ktime_t per_out_start;
#endif
};

/* Each context holds a reference to buffers it
 * wants to use. */
struct exanic_filter_buffer_ref
{
    struct list_head list;
    int port;
    int buffer;
};

struct exanic_filter_buffer 
{
    void *region_virt;
    dma_addr_t region_dma;
    unsigned numa_node;
    int refcount;
};

struct exanic_ip_filter_slot
{
    unsigned enable;
    unsigned buffer;

    uint32_t src_addr;
    uint32_t dst_addr;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t protocol;
};

struct exanic_mac_filter_slot
{
    unsigned enable;
    unsigned buffer;

    uint8_t dst_mac[6];
    uint16_t ethertype;
    uint16_t vlan;
    uint16_t vlan_match_method;
};

/* Accessor functions */
static inline struct device *exanic_dev(struct exanic *exanic)
{
    return &exanic->pci_dev->dev;
}

static inline struct mutex *exanic_mutex(struct exanic *exanic)
{
    return &exanic->mutex;
}

static inline volatile uint32_t *exanic_registers(struct exanic *exanic)
{
    return exanic->regs_virt;
}

static inline volatile uint16_t *exanic_tx_feedback(struct exanic *exanic)
{
    return exanic->tx_feedback_virt;
}

static inline char *exanic_tx_region(struct exanic *exanic)
{
    return exanic->tx_region_virt;
}

static inline void *exanic_rx_region(struct exanic *exanic, unsigned port_num)
{
    return exanic->port[port_num].rx_region_virt;
}
