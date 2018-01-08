/**
 * ExaNIC driver
 * Copyright (C) 2011-2013 Exablaze Pty Ltd and its licensors
 */

#ifndef _EXANIC_H_
#define _EXANIC_H_

#define DRV_VERSION "2.0.1-git"
#define DRV_NAME    "exanic"

#define PCI_DEVICE_ID_EXANIC_OLD        0x2B00

#define PCI_VENDOR_ID_EXABLAZE          0x1CE4
#define PCI_DEVICE_ID_EXANIC_X4         0x0001
#define PCI_DEVICE_ID_EXANIC_X2         0x0002
#define PCI_DEVICE_ID_EXANIC_X10        0x0003
#define PCI_DEVICE_ID_EXANIC_X10_GM     0x0004
#define PCI_DEVICE_ID_EXANIC_X40        0x0005
#define PCI_DEVICE_ID_EXANIC_X10_HPT    0x0006
#define PCI_DEVICE_ID_EXANIC_X40_40G    0x0007
#define PCI_DEVICE_ID_EXANIC_V5P        0x0008

/* Interface to exanic_(get|set)_feature_cfg */
enum exanic_feature
{
    EXANIC_MIRROR_RX,
    EXANIC_MIRROR_TX,
    EXANIC_BRIDGE,
};

/* exanic.c */
struct exanic;

struct exanic *exanic_find_by_minor(unsigned minor);

/* These functions are called with exanic mutex held. */
void exanic_configure_port_hash(struct exanic *exanic, unsigned port,
                                bool enable, unsigned mask, 
                                unsigned function);
int exanic_alloc_rx_dma(struct exanic *exanic, unsigned port_num,
                        int numa_node);
int exanic_alloc_filter_dma(struct exanic *exanic, unsigned port_num,
                            unsigned buffer_num, int numa_node);
int exanic_free_rx_dma(struct exanic *exanic, unsigned port_num);
int exanic_free_filter_dma(struct exanic *exanic, unsigned port_num, 
                       unsigned buffer_num);
bool exanic_rx_in_use(struct exanic *exanic, unsigned port_num);
int exanic_enable_port(struct exanic *exanic, unsigned port_num);
int exanic_disable_port(struct exanic *exanic, unsigned port_num);
int exanic_get_mac_addr_regs(struct exanic *exanic, unsigned port_num,
                             unsigned char mac_addr[ETH_ALEN]);
int exanic_set_mac_addr_regs(struct exanic *exanic, unsigned port_num,
                             const unsigned char mac_addr[ETH_ALEN]);
int exanic_get_feature_cfg(struct exanic *exanic, unsigned port_num,
                           enum exanic_feature feature, bool *state);
int exanic_set_feature_cfg(struct exanic *exanic, unsigned port_num,
                           enum exanic_feature feature, bool state);
bool exanic_port_enabled(struct exanic *exanic, unsigned port_num);

/* exanic-filter.c */
struct exanic_ip_filter_slot;
struct exanic_mac_filter_slot;

int exanic_insert_ip_filter(struct exanic *exanic, unsigned port_num,
                            struct exanic_ip_filter_slot *filter);
int exanic_insert_mac_filter(struct exanic *exanic, unsigned port_num,
                            struct exanic_mac_filter_slot *filter);
int exanic_remove_ip_filter(struct exanic *exanic,
                            unsigned port_num,
                            unsigned filter_id);
int exanic_remove_mac_filter(struct exanic *exanic,
                            unsigned port_num,
                            unsigned filter_id);
int exanic_remove_rx_filter_assoc(struct exanic *exanic,
                                  unsigned port_num,
                                  unsigned buffer_num);
int exanic_get_free_filter_buffer(struct exanic *exanic, 
                                    unsigned port_num);

/* exanic-ctx.c */
struct exanic_ctx;

struct exanic_ctx *exanic_alloc_ctx(struct exanic *exanic);
void exanic_free_ctx(struct exanic_ctx *ctx);
void exanic_rx_get(struct exanic_ctx *ctx, unsigned port_num);
void exanic_rx_put(struct exanic_ctx *ctx, unsigned port_num);
int exanic_alloc_tx_region(struct exanic_ctx *ctx, unsigned port_num,
                           size_t size, size_t *offset_ptr);
int exanic_free_tx_region(struct exanic_ctx *ctx, unsigned port_num,
                          size_t size, size_t offset);
int exanic_alloc_tx_feedback(struct exanic_ctx *ctx, unsigned port_num,
                             unsigned *feedback_slot_ptr);
int exanic_free_tx_feedback(struct exanic_ctx *ctx, unsigned port_num,
                            unsigned feedback_slot);
int exanic_has_filter_buffer_ref(struct exanic_ctx *ctx, unsigned port_num,
                                    unsigned buffer_num);
int exanic_add_filter_buffer_ref(struct exanic_ctx *ctx, unsigned port_num,
                                    unsigned buffer_num);
int exanic_remove_filter_buffer_ref(struct exanic_ctx *ctx, unsigned port_num,
                                        unsigned buffer_num);

/* exanic-dev.c */
extern struct file_operations exanic_fops;

/* exanic-netdev.c */
typedef bool (*exanic_netdev_intercept_func)(struct sk_buff *skb);
int exanic_netdev_alloc(struct exanic *exanic, unsigned port,
                        struct net_device **ndev_ret);
void exanic_netdev_free(struct net_device *ndev);
int exanic_transmit_frame(struct net_device *ndev, struct sk_buff *skb);
void exanic_netdev_rx_irq_handler(struct net_device *ndev);
int exanic_netdev_intercept_add(exanic_netdev_intercept_func func);
void exanic_netdev_intercept_remove(exanic_netdev_intercept_func func);
void exanic_netdev_check_link(struct net_device *ndev);

/* exanic-ptp.c */
void exanic_ptp_init(struct exanic *exanic);
void exanic_ptp_remove(struct exanic *exanic);
ktime_t exanic_ptp_time_to_ktime(struct exanic *exanic, uint32_t hw_time);

/* exanic-x4.c */
int exanic_x4_x2_get_serial(struct exanic *exanic, unsigned char serial[ETH_ALEN]);
int exanic_x4_x2_poweron_port(struct exanic *exanic, unsigned port_num);
int exanic_x4_x2_poweroff_port(struct exanic *exanic, unsigned port_num);
int exanic_x4_x2_save_feature_cfg(struct exanic *exanic);
int exanic_x4_x2_save_speed(struct exanic *exanic, unsigned port_number,
                            unsigned speed);
int exanic_x4_x2_save_autoneg(struct exanic *exanic, unsigned port_number,
                              bool autoneg);
int exanic_x4_x2_set_speed(struct exanic *exanic, unsigned port_number,
                           unsigned old_speed, unsigned speed);

/* exanic-z10.c */
int exanic_z10_poweron_port(struct exanic *exanic, unsigned port_num);
int exanic_z10_poweroff_port(struct exanic *exanic, unsigned port_num);

#endif /* _EXANIC_H_ */
