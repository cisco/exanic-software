#include <sys/ioctl.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>

#include "exanic.h"
#include "fifo_rx.h"
#include "pcie_if.h"
#include "ioctl.h"
#include "filter.h"

int exanic_filter_add_ip(exanic_t *exanic,
                         const exanic_rx_t *buffer,
                         const exanic_ip_filter_t *filter)
{
    struct exanicctl_rx_filter_add_ip arg;

    /* Can't steer to default buffer. */
    if (buffer->buffer_number == 0)
        return -1;

    arg.port_number = buffer->port_number;
    arg.buffer_number = buffer->buffer_number - 1;
    arg.src_addr = filter->src_addr;
    arg.dst_addr = filter->dst_addr;
    arg.src_port = filter->src_port;
    arg.dst_port = filter->dst_port;
    arg.protocol = filter->protocol;

    if (ioctl(exanic->fd, EXANICCTL_RX_FILTER_ADD_IP, &arg) != 0)
    {
        exanic_err_printf("EXANICCTL_RX_FILTER_ADD_IP failed: %s",
                strerror(errno));
        return -1;
    }

    return arg.filter_id;
}

int exanic_filter_add_mac(exanic_t *exanic,
                         const exanic_rx_t *buffer,
                         const exanic_mac_filter_t *filter)
{
    struct exanicctl_rx_filter_add_mac arg;
    int i;
    /* Can't steer to default buffer. */
    if (buffer->buffer_number == 0)
        return -1;

    arg.port_number = buffer->port_number;
    arg.buffer_number = buffer->buffer_number - 1;

    for (i = 0; i < 6; i++)
        arg.dst_mac[i] = filter->dst_mac[i];

    arg.ethertype = filter->ethertype;
    arg.vlan = filter->vlan;
    arg.vlan_match_method = filter->vlan_match_method;

    if (ioctl(exanic->fd, EXANICCTL_RX_FILTER_ADD_MAC, &arg) != 0)
    {
        exanic_err_printf("EXANICCTL_RX_FILTER_ADD_MAC failed: %s",
                strerror(errno));
        return -1;
    }

    return arg.filter_id;
}

int exanic_filter_remove_ip(exanic_t *exanic, int port_number,
                          int filter_id)
{
    struct exanicctl_rx_filter_remove_ip arg;

    arg.port_number = port_number;
    arg.filter_id = filter_id;

    if (ioctl(exanic->fd, EXANICCTL_RX_FILTER_REMOVE_IP, &arg) != 0)
    {
        exanic_err_printf("EXANICCTL_RX_FILTER_REMOVE_IP failed: %s",
                strerror(errno));
        return -1;
    }

    return 0;
}

int exanic_filter_remove_mac(exanic_t *exanic, int port_number,
                          int filter_id)
{
    struct exanicctl_rx_filter_remove_mac arg;

    arg.port_number = port_number;
    arg.filter_id = filter_id;

    if (ioctl(exanic->fd, EXANICCTL_RX_FILTER_REMOVE_MAC, &arg) != 0)
    {
        exanic_err_printf("EXANICCTL_RX_FILTER_REMOVE_MAC failed: %s",
                strerror(errno));
        return -1;
    }

    return 0;
}
