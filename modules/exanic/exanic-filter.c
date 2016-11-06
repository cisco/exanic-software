/**
 * ExaNIC driver
 * Copyright (C) 2011-2013 Exablaze Pty Ltd and its licensors
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt
#include <linux/version.h>
#include <linux/pci.h>
#include <linux/module.h>
#include <linux/kobject.h>
#include <linux/netdevice.h>
#include <linux/miscdevice.h>
#include <linux/etherdevice.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/tcp.h>

#include "../../libs/exanic/pcie_if.h"
#include "../../libs/exanic/ioctl.h"
#include "exanic.h"
#include "structs.h"

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 9, 0)
#define __HAS_OLD_HLIST_ITERATOR
#endif

/**
 * Determine whether a byte in the {protocol, src_addr, dst_addr, src_port, 
 * dst_port} concatenation maps to a wildcard field (i.e. the field is set to
 * zero).
 */
unsigned exanic_ip_filter_is_wildcard_field(struct exanic_ip_filter_slot *filter,
                                            int byte)
{
    switch (byte)
    {
        case 0:
        case 1:
            return (filter->dst_port == 0);
        case 2:
        case 3:
            return (filter->src_port == 0);
        case 4:
        case 5:
        case 6:
        case 7:
            return (filter->dst_addr == 0);
        case 8:
        case 9:
        case 10:
        case 11:
            return (filter->src_addr == 0);
        case 12:
            return (filter->protocol == 0);
        default:
            return 0;
    }
}

/**
 * Determine whether a byte in the {is_vlan, vlan, ethertype, dst_mac}
 * concatenation maps to a wildcard field (i.e. the field is set to
 * zero).
 */
unsigned exanic_mac_filter_is_wildcard_field(struct exanic_mac_filter_slot *filter,
                                            int byte)
{
    int i;
    switch (byte)
    {
        case 0:
        case 1:
        case 2:
        case 3:
        case 4:
        case 5:
            for (i = 0; i < 6; i++)
                if (filter->dst_mac[i] != 0)
                    return 0;
            return 1;
        case 6:
        case 7:
            return (filter->ethertype == 0);
        case 8:
            if (filter->vlan_match_method == EXANIC_VLAN_MATCH_METHOD_ALL ||
                filter->vlan_match_method == EXANIC_VLAN_MATCH_METHOD_ALL_VLAN)
                return 1;
            return 0;
        case 9:
            return (filter->vlan_match_method == EXANIC_VLAN_MATCH_METHOD_ALL); 
        default:
          return 0;
    }
}

/**
 * Map a byte offset in the {protocol, src_addr, dst_addr, src_port, dst_port}
 * 13 byte concatenation to the value of that byte.
 */
int exanic_ip_filter_byte_val_check(struct exanic_ip_filter_slot *filter,
                                  int byte_number, int byte_value)
{
    uint8_t prog_value;
    switch (byte_number)
    {
        case 0:
            prog_value = (uint8_t) ((filter->dst_port)       & 0xFF);
            break;
        case 1:
            prog_value = (uint8_t) ((filter->dst_port >> 8)  & 0xFF);
            break;
        case 2:
            prog_value = (uint8_t) ((filter->src_port)       & 0xFF);
            break;
        case 3:
            prog_value = (uint8_t) ((filter->src_port >> 8)  & 0xFF);
            break;
        case 4:
            prog_value = (uint8_t) (filter->dst_addr         & 0xFF);
            break;
        case 5:
            prog_value = (uint8_t) ((filter->dst_addr >> 8)  & 0xFF);
            break;
        case 6:
            prog_value = (uint8_t) ((filter->dst_addr >> 16) & 0xFF);
            break;
        case 7:
            prog_value = (uint8_t) ((filter->dst_addr >> 24) & 0xFF);
            break;
        case 8:
            prog_value = (uint8_t) (filter->src_addr         & 0xFF);
            break;
        case 9:
            prog_value = (uint8_t) ((filter->src_addr >> 8)  & 0xFF);
            break;
        case 10:
            prog_value = (uint8_t) ((filter->src_addr >> 16) & 0xFF);
            break;
        case 11:
            prog_value = (uint8_t) ((filter->src_addr >> 24) & 0xFF);
            break;
        case 12:
            prog_value = (uint8_t) (filter->protocol);
            break;
        default:
            return (uint8_t) 0;
    }
    
    return prog_value == byte_value;
}

/*
 * Map a byte offset in the {is_vlan, vlan, ethertype, dst_mac}
 * 10 byte concatenation to the value of that byte.
 */
int exanic_mac_filter_byte_val_check(struct exanic_mac_filter_slot *filter,
                                  int byte_number, uint8_t byte_value)
{
    uint8_t prog_value;
    switch (byte_number)
    {
        case 0:
            prog_value =  filter->dst_mac[0];
            break;
        case 1:
            prog_value =  filter->dst_mac[1];
            break;
        case 2:
            prog_value =  filter->dst_mac[2];
            break;
        case 3:
            prog_value =  filter->dst_mac[3];
            break;
        case 4:
            prog_value =  filter->dst_mac[4];
            break;
        case 5:
            prog_value =  filter->dst_mac[5];
            break;
        case 6:
            prog_value =  (uint8_t) filter->ethertype & 0xFF;
            break;
        case 7:
            prog_value =  (uint8_t) (filter->ethertype >> 8) & 0xFF;
            break;
        case 8:
            if (filter->vlan_match_method == EXANIC_VLAN_MATCH_METHOD_NOT_VLAN)
                prog_value = 0;
            else
                prog_value = (uint8_t) filter->vlan & 0xFF;
            break;
        case 9:
            if (filter->vlan_match_method == EXANIC_VLAN_MATCH_METHOD_SPECIFIC)
                return ((0x10 | (filter->vlan >> 8)) & 0xFF) == byte_value;
            else if (filter->vlan_match_method == EXANIC_VLAN_MATCH_METHOD_ALL)
                return 1;
            else if (filter->vlan_match_method == EXANIC_VLAN_MATCH_METHOD_ALL_VLAN)
                return (byte_value & 0x10) != 0;
            else 
                return (byte_value & 0x10) == 0;
        default:
            return (uint8_t) 0;
    }
    
    return (prog_value == byte_value);
}

/**
 * Force consistency between the driver IP filter list and the filters in
 * hardware. Necessary because hardware filters are write-only. 
 *
 * Called with the exanic mutex held.                   
 */
void exanic_update_hardware_ip_filter_bank(struct exanic *exanic, unsigned port_num,
                                            unsigned bank)
{
    int byte_number, byte_value, filter_number;
    unsigned address_offset;
    uint32_t filter_val;
    struct exanic_port *port = &exanic->port[port_num];

    for (byte_number = 0; byte_number < 13; byte_number++)
    {
        for (byte_value = 0; byte_value < 256; byte_value++)
        {
            filter_val = 0;
            for (filter_number = bank*EXANIC_NUM_FILTERS_PER_BANK; 
                    filter_number < bank*EXANIC_NUM_FILTERS_PER_BANK 
                                    + EXANIC_NUM_FILTERS_PER_BANK; 
                    filter_number++)
            {
                if (port->ip_filter_slots[filter_number].enable &&
                       (exanic_ip_filter_is_wildcard_field(
                            &port->ip_filter_slots[filter_number], byte_number) ||
                       (exanic_ip_filter_byte_val_check(
                            &port->ip_filter_slots[filter_number], byte_number,
                            byte_value))))
                    filter_val |= 1 << (filter_number - 
                                    bank* EXANIC_NUM_FILTERS_PER_BANK);
            }
            address_offset = (byte_number << 11) | 
                             (byte_value << 3) |
                             (bank & 0x7);
            writel(filter_val, exanic->regs_virt + 
                REG_FILTERS_OFFSET(port_num, REG_FILTER_IP_RULES) +
                address_offset*sizeof(uint32_t));
        }
    }
}

/**
 * Force consistency between the driver MAC filter list and the filters in
 * hardware. Necessary because hardware filters are write-only. 
 *
 * Called with the exanic mutex held.                   
 */
void exanic_update_hardware_mac_filter_bank(struct exanic *exanic, 
                                            unsigned port_num, unsigned bank)
{
    int byte_number, byte_value, filter_number;
    unsigned address_offset;
    uint32_t filter_val;
    struct exanic_port *port = &exanic->port[port_num];

    for (byte_number = 0; byte_number < 10; byte_number++)
    {
        for (byte_value = 0; byte_value < 256; byte_value++)
        {
            filter_val = 0;
            for (filter_number = bank*EXANIC_NUM_FILTERS_PER_BANK; 
                    filter_number < bank*EXANIC_NUM_FILTERS_PER_BANK + 
                                        EXANIC_NUM_FILTERS_PER_BANK; 
                    filter_number++)
            {
                if (port->mac_filter_slots[filter_number].enable &&
                       (exanic_mac_filter_is_wildcard_field(
                            &port->mac_filter_slots[filter_number], byte_number) ||
                       (exanic_mac_filter_byte_val_check(
                            &port->mac_filter_slots[filter_number], byte_number, 
                            byte_value))))
                    filter_val |= 1 << (filter_number - 
                                            bank*EXANIC_NUM_FILTERS_PER_BANK);
            }
            address_offset = (byte_number << 11) | 
                             (byte_value << 3) |
                             (bank & 0x7);
            writel(filter_val, exanic->regs_virt + 
                REG_FILTERS_OFFSET(port_num, REG_FILTER_MAC_RULES) +
                address_offset*sizeof(uint32_t));
        }
    }
}

/** 
 * Set the filter to memory buffer mapping.
 *
 * Called with the exanic mutex held.
 */
int exanic_set_filter_buffer(struct exanic *exanic, unsigned port_num,
                              int buffer_num, int region,
                              int filter_id)
{
    struct exanic_port *port = &exanic->port[port_num];
    if (port->filter_buffers[buffer_num].region_virt == NULL)
        return -EFAULT;
    
    writel(buffer_num, exanic->regs_virt + 
        REG_FILTERS_OFFSET(port_num, REG_RULE_TO_BUFFER) +
        (region*EXANIC_NUM_FILTERS_PER_REGION+filter_id)*sizeof(uint32_t));
    dev_dbg(&exanic->pci_dev->dev, DRV_NAME
        "%u: Port %u, filter id %d mapped to buffer %u\n", exanic->id, port_num,
          filter_id, buffer_num);
    return 0;
}

/**
 * Insert MAC filter into the filter list for the port.
 *
 * Called with the exanic mutex held.
 */
int exanic_insert_mac_filter(struct exanic *exanic, unsigned port_num,
                            struct exanic_mac_filter_slot *filter)
{
    struct exanic_port *port = &exanic->port[port_num];
    unsigned filter_id;
    int ret;

    for (filter_id = 0; filter_id < exanic->port[port_num].max_mac_filter_slots;
                    filter_id++)
        if (port->mac_filter_slots[filter_id].enable == 0)
            break;
  
    if (filter_id == exanic->port[port_num].max_mac_filter_slots)
        return -ENOMEM;

    filter->enable = 1;
    
    ret = exanic_set_filter_buffer(exanic, port_num, filter->buffer,
                                    EXANIC_FILTER_REGION_MAC, filter_id);
    if (ret < 0)
        return ret;

    spin_lock(&port->filter_lock);
    port->mac_filter_slots[filter_id] = *filter;
    spin_unlock(&port->filter_lock);

    exanic_update_hardware_mac_filter_bank(exanic, port_num, 
                            filter_id / EXANIC_NUM_FILTERS_PER_BANK);     
    
    return filter_id;
}
  
/**
 * Insert an IP filter into the filter list for the port.
 *
 * Called with the exanic mutex held.
 */
int exanic_insert_ip_filter(struct exanic *exanic, unsigned port_num,
                            struct exanic_ip_filter_slot *filter)
{
    struct exanic_port *port = &exanic->port[port_num];
    unsigned filter_id;
    int ret;

    for (filter_id = 0; filter_id < exanic->port[port_num].max_ip_filter_slots;
            filter_id++)
        if (port->ip_filter_slots[filter_id].enable == 0)
            break;
  
    if (filter_id == exanic->port[port_num].max_ip_filter_slots)
        return -ENOMEM;

    filter->enable = 1;
    
    ret = exanic_set_filter_buffer(exanic, port_num, filter->buffer, 
                                    EXANIC_FILTER_REGION_IP, filter_id);
    if (ret < 0)
        return ret;

    spin_lock(&port->filter_lock);
    port->ip_filter_slots[filter_id] = *filter;
    spin_unlock(&port->filter_lock);

    exanic_update_hardware_ip_filter_bank(exanic, port_num, 
                                filter_id / EXANIC_NUM_FILTERS_PER_BANK);     
    
    return filter_id;
}

/**
 * Remove an IP filter from the filter list for the port.
 *
 * Called with the exanic mutex held.
 */
int exanic_remove_ip_filter(struct exanic *exanic,
                            unsigned port_num,
                            unsigned filter_id)
{
    struct exanic_port *port = &exanic->port[port_num];

    if (filter_id > exanic->port[port_num].max_ip_filter_slots) 
        return -1;

    spin_lock(&port->filter_lock);
    port->ip_filter_slots[filter_id].enable = 0;
    spin_unlock(&port->filter_lock);

    exanic_update_hardware_ip_filter_bank(exanic, port_num, 
                                    filter_id / EXANIC_NUM_FILTERS_PER_BANK);
    return 0;
}

/**
 * Remove a MAC filter from the filter list for the port.
 *
 * Called with the exanic mutex held.
 */
int exanic_remove_mac_filter(struct exanic *exanic,
                            unsigned port_num,
                            unsigned filter_id)
{
    struct exanic_port *port = &exanic->port[port_num];

    if (filter_id > exanic->port[port_num].max_mac_filter_slots) 
        return -1;

    spin_lock(&port->filter_lock);
    port->mac_filter_slots[filter_id].enable = 0;
    spin_unlock(&port->filter_lock);

    exanic_update_hardware_mac_filter_bank(exanic, port_num, 
                                   filter_id / EXANIC_NUM_FILTERS_PER_BANK);
    return 0;
}

/**
 * Remove all rules assocated with a given buffer. 
 */
int exanic_remove_rx_filter_assoc(struct exanic *exanic,
                                  unsigned port_num,
                                  unsigned buffer_num)
{
    struct exanic_port *port = &exanic->port[port_num];
    int i;
    
    for (i = 0; i < exanic->port[port_num].max_ip_filter_slots; i++)
    {
        spin_lock(&port->filter_lock);
        if(port->ip_filter_slots[i].buffer == buffer_num)
            port->ip_filter_slots[i].enable = 0; 
        spin_unlock(&port->filter_lock);
    }

    /* Update all banks of EXANIC_NUM_FILTERS_PER_BANK filters. */
    for (i = 0; 
            i < exanic->port[port_num].max_ip_filter_slots/EXANIC_NUM_FILTERS_PER_BANK;
            i++)
        exanic_update_hardware_ip_filter_bank(exanic, port_num, i);

    for (i = 0; i < exanic->port[port_num].max_mac_filter_slots; i++)
    {
        spin_lock(&port->filter_lock);
        if(port->mac_filter_slots[i].buffer == buffer_num)
            port->mac_filter_slots[i].enable = 0; 
        spin_unlock(&port->filter_lock);
    }

    for (i = 0; i < exanic->port[port_num].max_mac_filter_slots/ EXANIC_NUM_FILTERS_PER_BANK; i++)
        exanic_update_hardware_mac_filter_bank(exanic, port_num, i);

    return 0;
}

/**
 * Find an unused (unallocated) filter buffer on a given port.
 * Returns -1 if it can't find one.
 */
int exanic_get_free_filter_buffer(struct exanic *exanic, unsigned port_num)
{
    int i;
    for (i = 0; i < exanic->max_filter_buffers; i++)
        if (exanic->port[port_num].filter_buffers[i].region_virt == NULL)
            return i;

    return -1;
}
