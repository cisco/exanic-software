/**
 * \file
 * \brief Functions for retrieving network configuration for ExaNIC interfaces
 */
#ifndef EXANIC_CONFIG_H
#define EXANIC_CONFIG_H

#include <unistd.h> /* for ssize_t */
#include <arpa/inet.h> /* for in_addr_t */

#include "exanic.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief Address info for an interface
 */
typedef struct exanic_if_addr
{
    in_addr_t address;
    in_addr_t netmask;
    in_addr_t broadcast;
} exanic_if_addr_t;

/**
 * \brief Get the address info for an interface
 *
 * \param[in]   exanic
 *      A valid ExaNIC handle
 * \param[in]   port_number
 *      The port number
 * \param[out]  ifaddr
 *      A pointer to \ref exanic_if_addr_t which will be populated
 *      with the address information.
 *
 * \return 0 on success, -1 on error
 */
int exanic_get_interface_addr(exanic_t *exanic, int port_number,
                              exanic_if_addr_t *ifaddr);

/**
 * \brief Get the interface name for the ExaNIC port
 *
 * \param[in]   exanic
 *      A valid ExaNIC handle
 * \param[in]   port_number
 *      The port number
 * \param[out]  name
 *      A buffer which will be populated with the interface name
 * \param[in]   name_len
 *      The size of the buffer
 *
 * \return 0 on success, -1 on error
 */
int exanic_get_interface_name(exanic_t *exanic, int port_number, char *name,
                              size_t name_len);

/**
 * \brief Get the interface index for the ExaNIC port
 *
 * \param[in]   exanic
 *      A valid ExaNIC handle
 * \param[in]   port_number
 *      The port number
 *
 * \return Interface index on success, -1 on error
 */
int exanic_get_interface_index(exanic_t *exanic, int port_number);

/**
 * \brief Look up a ExaNIC device and port number by IP address
 *
 * \param[in]   addr
 *      IP address of the interface
 * \param[out]  device
 *      A buffer for the device name
 * \param[in]   device_len
 *      Size of the device buffer
 * \param[out]  port_number
 *      A pointer to an int which will be populated with the port number
 *
 * \return 0 on success, -1 on error or IP address not found
 */
int exanic_find_port_by_ip_addr(in_addr_t addr, char *device,
                                size_t device_len, int *port_number);

/**
 * \brief Look up a ExaNIC device and port number by interface name
 *
 * \param[in]   name
 *      Name of the Linux network interface
 * \param[out]  device
 *      A buffer for the device name
 * \param[in]   device_len
 *      Size of the device buffer
 * \param[out]  port_number
 *      A pointer to an int which will be populated with the port number
 *
 * \return 0 on success, -1 on error or IP address not found
 */
int exanic_find_port_by_interface_name(const char *name, char *device,
                                       size_t device_len, int *port_number);

/**
 * \brief A struct for returning data from exanic_get_all_ports()
 */
typedef struct exanic_port_info
{
    char device[16];
    int port_number;
} exanic_port_info_t;

/**
 * \brief Get a list of all ExaNIC ports on this host
 *
 * \param[out]  table
 *      An array to be populated with the device name and port numbers
 * \param[in]   table_size
 *      The size of the array in bytes
 *
 * \return The number of ports, or -1 on error
 */
ssize_t exanic_get_all_ports(exanic_port_info_t *table, size_t table_size);

/**
 * \brief A route for a single destination subnet
 */
typedef struct exanic_ip_route
{
    in_addr_t destination;
    in_addr_t netmask;
    in_addr_t gateway;
} exanic_ip_route_t;

enum
{
    EXANIC_MAX_ROUTES = 16,
};

/**
 * \brief Get the table of all configured routes
 *
 * \param[in]   exanic
 *      A valid ExaNIC handle
 * \param[in]   port_number
 *      The port number
 * \param[out]  table
 *      An array which will be populated with the routing table
 * \param[in]   table_size
 *      The size of the array in bytes
 *
 * \return The number of routes, or -1 on error
 */
ssize_t exanic_get_ip_routes(exanic_t *exanic, int port_number,
                             exanic_ip_route_t *table, size_t table_size);

#ifdef __cplusplus
}
#endif

#endif /* EXANIC_CONFIG_H */
