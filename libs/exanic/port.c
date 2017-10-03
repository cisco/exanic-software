#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <sys/ioctl.h>

#include "exanic.h"
#include "pcie_if.h"
#include "ioctl.h"
#include "port.h"
#include "util.h"
#include "z1/port.h"

static int check_network_interface(exanic_t *exanic)
{
    if (exanic_get_function_id(exanic) != EXANIC_FUNCTION_NIC &&
            exanic_get_function_id(exanic) != EXANIC_FUNCTION_DEVKIT &&
                exanic_get_function_id(exanic) != EXANIC_FUNCTION_PTP_GM)
    {
        exanic_err_printf("not a network interface");
        return -1;
    }
    return 0;
}

static int check_port_rx_usable(exanic_t *exanic, int port_number)
{
    if (port_number < 0 || port_number >= exanic->num_ports)
    {
        exanic_err_printf("invalid port number");
        return -1;
    }
    if ((exanic->registers[REG_PORT_INDEX(port_number, REG_PORT_STATUS)]
            & (EXANIC_PORT_NOT_IMPLEMENTED | EXANIC_PORT_RX_UNSUPPORTED)) != 0)
    {
        exanic_err_printf("port not supported by hardware");
        return -1;
    }
    return 0;
}

static int check_port_tx_usable(exanic_t *exanic, int port_number)
{
    if (port_number < 0 || port_number >= exanic->num_ports)
    {
        exanic_err_printf("invalid port number");
        return -1;
    }
    if ((exanic->registers[REG_PORT_INDEX(port_number, REG_PORT_STATUS)]
            & (EXANIC_PORT_NOT_IMPLEMENTED | EXANIC_PORT_TX_UNSUPPORTED)) != 0)
    {
        exanic_err_printf("port not supported by hardware");
        return -1;
    }
    return 0;
}

static int check_port_configurable(exanic_t *exanic, int port_number)
{
    if (port_number < 0 || port_number >= exanic->num_ports)
    {
        exanic_err_printf("invalid port number");
        return -1;
    }
    if ((exanic->registers[REG_PORT_INDEX(port_number, REG_PORT_STATUS)]
            & EXANIC_PORT_NOT_IMPLEMENTED) != 0)
    {
        exanic_err_printf("port not supported by hardware");
        return -1;
    }
    return 0;
}

int exanic_port_mirror_supported(exanic_t *exanic, int port_number)
{
    uint32_t caps = exanic_get_caps(exanic);
    exanic_hardware_id_t hw_type = exanic_get_hw_type(exanic);

    /*
     * Check if firmware has mirroring support for a given port.
     * Always available on legacy 4-port cards regardless of capability bit.
     */
    return (((hw_type == EXANIC_HW_X4 ||
              hw_type == EXANIC_HW_Z10 ||
              hw_type == EXANIC_HW_Z1) && (port_number < 3)) ||
            ((hw_type == EXANIC_HW_X10) && (caps & EXANIC_CAP_MIRRORING) &&
             (port_number < 1)));
}

int exanic_port_rx_usable(exanic_t *exanic, int port_number)
{
    return port_number >= 0 && port_number < exanic->num_ports &&
        (exanic->registers[REG_PORT_INDEX(port_number, REG_PORT_STATUS)]
         & (EXANIC_PORT_NOT_IMPLEMENTED | EXANIC_PORT_RX_UNSUPPORTED)) == 0;
}

int exanic_port_tx_usable(exanic_t *exanic, int port_number)
{
    return port_number >= 0 && port_number < exanic->num_ports &&
        (exanic->registers[REG_PORT_INDEX(port_number, REG_PORT_STATUS)]
         & (EXANIC_PORT_NOT_IMPLEMENTED | EXANIC_PORT_TX_UNSUPPORTED)) == 0;
}

int exanic_port_configurable(exanic_t *exanic, int port_number)
{
    if (port_number < 0 || port_number >= exanic->num_ports ||
            (exanic->registers[REG_PORT_INDEX(port_number, REG_PORT_STATUS)]
            & EXANIC_PORT_NOT_IMPLEMENTED) != 0)
        return 0;
    else
        return 1;
}

int exanic_get_num_ports(exanic_t *exanic)
{
    return exanic->num_ports;
}

int exanic_get_port_status(exanic_t *exanic, int port_number)
{
    if (check_port_configurable(exanic, port_number) == -1)
        return 0;
    return exanic->registers[REG_PORT_INDEX(port_number, REG_PORT_STATUS)];
}

int exanic_port_enabled(exanic_t *exanic, int port_number)
{
    if (check_port_configurable(exanic, port_number) == -1)
        return 0;
    return exanic->registers[REG_PORT_INDEX(port_number, REG_PORT_ENABLED)];
}

int exanic_get_promiscuous_mode(exanic_t *exanic, int port_number)
{
    uint32_t flags;

    if (check_network_interface(exanic) == -1)
        return -1;
    if (check_port_rx_usable(exanic, port_number) == -1)
        return -1;

    flags = exanic->registers[REG_PORT_INDEX(port_number, REG_PORT_FLAGS)];
    if (flags & EXANIC_PORT_FLAG_PROMISCUOUS)
        return 1;
    else
        return 0;
}

int exanic_set_port_speed(exanic_t *exanic, int port_number, unsigned speed)
{
    if (check_network_interface(exanic) == -1)
        return -1;
    if (check_port_rx_usable(exanic, port_number) == -1)
        return -1;
    if (exanic->registers[REG_PORT_INDEX(port_number, REG_PORT_ENABLED)])
    {
        exanic_err_printf("cannot change speed when port is enabled");
        return -1;
    }

    switch (exanic_get_hw_type(exanic))
    {
        case EXANIC_HW_Z1:
            return z1_set_port_speed(exanic, port_number, speed);
        default:
            exanic_err_printf("port speed configuration not supported");
            return -1;
    }
}

unsigned exanic_get_port_speed(exanic_t *exanic, int port_number)
{
    if (check_port_configurable(exanic, port_number) == -1)
        return -1;
    return exanic->registers[REG_PORT_INDEX(port_number, REG_PORT_SPEED)];
}

int exanic_fake_auto_neg(exanic_t *exanic, unsigned int port_number)
{
    uint32_t flags;

    if (port_number < 0 || port_number >= exanic->num_ports)
    {
        exanic_err_printf("invalid port number");
        return -1;
    }

    if (exanic_get_hw_type(exanic) != EXANIC_HW_Z1)
    {
        exanic_err_printf("only valid for Z1");
        return -1;
    }

    flags = exanic->registers[REG_PORT_INDEX(port_number, REG_PORT_FLAGS)];
    /* do a bit transition to trigger fake auto-neg control chars to be sent */
    flags |= EXANIC_PORT_FLAG_AUTONEG_TX;
    exanic->registers[REG_PORT_INDEX(port_number, REG_PORT_FLAGS)] = flags;
    flags &= ~EXANIC_PORT_FLAG_AUTONEG_TX;
    exanic->registers[REG_PORT_INDEX(port_number, REG_PORT_FLAGS)] = flags;
    return 0;
}

int exanic_get_mac_addr(exanic_t *exanic, int port_number, uint8_t *mac_addr)
{
    if (check_network_interface(exanic) == -1)
        return -1;
    if (check_port_rx_usable(exanic, port_number) == -1)
        return -1;
    uint32_t addr;
    if (exanic_get_hw_type(exanic) == EXANIC_HW_Z1 ||
            exanic_get_hw_type(exanic) == EXANIC_HW_Z10)
        addr = exanic->registers[REG_EXANIC_INDEX(REG_EXANIC_MAC_ADDR_OUI)];
    else
        addr = exanic->registers[REG_PORT_INDEX(port_number, REG_PORT_MAC_ADDR_OUI)];
    memcpy(mac_addr, &addr, 3);
    addr = exanic->registers[REG_PORT_INDEX(port_number, REG_PORT_MAC_ADDR_NIC)];
    memcpy(mac_addr + 3, &addr, 3);
    return 0;
}

int exanic_get_supported_tx_types(exanic_t *exanic, int port_number)
{
    if (check_network_interface(exanic) == -1)
        return -1;
    if (check_port_tx_usable(exanic, port_number) == -1)
        return -1;
    return exanic->registers[
        REG_PORT_INDEX(port_number, REG_PORT_TX_SUPPORTED_TYPES)];
}

uint32_t exanic_get_bridging_config(exanic_t *exanic)
{
    if (check_network_interface(exanic) == -1)
        return -1;
    return exanic->registers[REG_EXANIC_INDEX(REG_EXANIC_FEATURE_CFG)]
        & EXANIC_FEATURE_BRIDGE_MIRROR_MASK;
}

int exanic_get_port_stats(exanic_t *exanic, int port_number,
                          exanic_port_stats_t *port_stats)
{
    if (check_port_configurable(exanic, port_number) == -1)
        return -1;
    port_stats->tx_count = exanic->registers[
        REG_PORT_STAT_INDEX(port_number, REG_PORT_STAT_TX)];
    port_stats->rx_count = exanic->registers[
        REG_PORT_STAT_INDEX(port_number, REG_PORT_STAT_RX)];
    port_stats->rx_ignored_count = exanic->registers[
        REG_PORT_STAT_INDEX(port_number, REG_PORT_STAT_RX_IGNORED)];
    port_stats->rx_error_count = exanic->registers[
        REG_PORT_STAT_INDEX(port_number, REG_PORT_STAT_RX_ERROR)];
    port_stats->rx_dropped_count = exanic->registers[
        REG_PORT_STAT_INDEX(port_number, REG_PORT_STAT_RX_DROPPED)];
    return 0;
}
