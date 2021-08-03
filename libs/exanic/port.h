/**
 * \file
 * \brief ExaNIC port configuration functions.
 */
#ifndef EXANIC_PORT_H
#define EXANIC_PORT_H

#include "exanic.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief Get the number of ports
 *
 * \return The number of ports on the ExaNIC
 */
int exanic_get_num_ports(exanic_t *exanic);

/**
 * \brief Return whether RX is supported on a port
 *
 * \return 1 if RX is supported, 0 if not supported
 */
int exanic_port_rx_usable(exanic_t *exanic, int port_number);

/**
 * \brief Return whether TX is supported on a port
 *
 * \return 1 if TX is supported, 0 if not supported
 */
int exanic_port_tx_usable(exanic_t *exanic, int port_number);

/**
 * \brief Return whether a port is configurable.
 *
 * Ports may be configurable but not usable
 *
 * \return 1 if port is configurable, 0 if not configurable
 */
int exanic_port_configurable(exanic_t *exanic, int port_number);

/**
 * \brief Get the port status
 *
 * \return A bitfield containing port status information
 *      (see \ref exanic_port_status_t)
 */
int exanic_get_port_status(exanic_t *exanic, int port_number);

/**
 * \brief Return whether a port is enabled
 *
 * \return 0 if disabled, or non-zero if enabled
 */
int exanic_port_enabled(exanic_t *exanic, int port_number);



/**
 * \brief Return whether a port autonegotiation is enabled
 *
 * \return 0 if disabled, or non-zero if enabled, -1 if an error occurred
 *
 */
int exanic_port_autoneg_enabled(exanic_t* exanic, int port_number);

/**
 * \brief Return whether promiscuous mode is enabled or disabled
 *
 * \param[in]   exanic
 *      A valid ExaNIC handle
 * \param[in]   port_number
 *      The port number
 *
 * \return 1 if promiscuous mode is on, 0 if promiscuous mode is off
 */
int exanic_get_promiscuous_mode(exanic_t *exanic, int port_number);

/**
 * \brief Set the speed of a port on the ExaNIC
 *
 * \deprecated This config option will be moved into the kernel driver,
 * and will be made configurable via the ethtool command.
 *
 * \param[in]   exanic
 *      A valid ExaNIC handle
 * \param[in]   port_number
 *      The port number
 * \param[in]   speed
 *      The desired port speed in Mbps
 *
 * \return 0 on success, or -1 if an error occurred
 */
int exanic_set_port_speed(exanic_t *exanic, int port_number, unsigned speed);

/**
 * \brief Get the speed of a port on the ExaNIC
 *
 * \param[in]   exanic
 *      A valid ExaNIC handle
 * \param[in]   port_number
 *      The port number
 *
 * \return The speed of the port in Mbps
 */
unsigned exanic_get_port_speed(exanic_t *exanic, int port_number);


/**
 * \brief Get the MAC address of a port on the ExaNIC
 *
 * \param[in]   exanic
 *      A valid ExaNIC handle
 * \param[in]   port_number
 *      The port number
 * \param[out]  mac_addr
 *      A pointer to a 6 byte buffer that will be populated with the MAC address
 *
 * \return 0 on success, or -1 if an error occurred
 */
int exanic_get_mac_addr(exanic_t *exanic, int port_number, uint8_t *mac_addr);

/**
 * \brief Disable a filter on a ExaNIC port
 *
 * \param[in]   exanic
 *      A valid ExaNIC handle
 * \param[in]   port_number
 *      The port number
 * \param[in]   filter_slot
 *      The filter slot number
 *
 * \return 0 on success, or -1 if an error occurred
 */
int exanic_remove_filter(exanic_t *exanic, int port_number, int filter_slot);

/**
 * \brief Get the set of supported TX types on a ExaNIC port
 *
 * \param[in]   exanic
 *      A valid ExaNIC handle
 * \param[in]   port_number
 *      The port number
 *
 * \return A bitmask of the supported TX types (see \ref exanic_tx_type_id_t).
 */
int exanic_get_supported_tx_types(exanic_t *exanic, int port_number);

typedef struct exanic_port_stats
{
    uint32_t    tx_count;
    uint32_t    rx_count;
    uint32_t    rx_ignored_count;
    uint32_t    rx_error_count;
    uint32_t    rx_dropped_count;
} exanic_port_stats_t;

/**
 * \brief Get port packet statistics
 *
 * \param[in]   exanic
 *      A valid ExaNIC handle
 * \param[in]   port_number
 *      The port number
 * \param[out]   port_stats
 *      A pointer to the struct which will be filled out with the stats
 *
 * \return 0 on success, or -1 if an error occurred
 */
int exanic_get_port_stats(exanic_t *exanic, int port_number,
                          exanic_port_stats_t *port_stats);

#ifdef __cplusplus
}
#endif

#endif /* EXANIC_PORT_H */
