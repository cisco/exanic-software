/**
 * \file
 * \brief Functions for manipulating filters on an ExaNIC.
 */
#ifndef EXANIC_FILTER_H
#define EXANIC_FILTER_H

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief Description of an IP filter
 *
 * The filter can match on (protocol, src_addr, dst_addr, src_port, dst_port).
 *
 * To wildcard match on any field, simply set it to zero.
 *
 */
typedef struct exanic_ip_filter
{
    uint32_t    src_addr;   /**< Source IP address of packet */
    uint32_t    dst_addr;   /**< Destination IP address of packet */
    uint16_t    src_port;   /**< Source port of packet */
    uint16_t    dst_port;   /**< Destination port of packet */
    uint8_t     protocol;   /**< IPPROTO_UDP or IPPROTO_TCP */
} exanic_ip_filter_t;


/**
 * \brief Description of a MAC filter.
 *
 * The filter can match on {vlan, ethertype, dst_mac}.
 *
 * To wildcard match on any field, set it to zero.
 *
 * VLAN matching is available in modes defined by \ref vlan_match_method
 *
 */
typedef struct exanic_mac_filter
{
    uint8_t     dst_mac[6];
    uint16_t    ethertype;
    uint16_t    vlan;
    int         vlan_match_method;
} exanic_mac_filter_t;

/**
 * \brief Add an IP filter to the RX filter set.
 * This will also cause the kernel to filter matching packets from the
 * kernel IP stack.
 *
 * \param[in]   exanic
 *      A valid ExaNIC handle
 * \param[in]   buffer
 *      A \ref exanic_rx_t obtained using exanic_acquire_rx_buffer
 * \param[in]   filter
 *      A \ref exanic_ip_filter_t containing the filter description
 *
 * \return An identifier for the new filter, or -1 on error
 */
int exanic_filter_add_ip(exanic_t *exanic,
                         const exanic_rx_t *buffer,
                         const exanic_ip_filter_t *filter);

/**
 * \brief Add a MAC filter to the RX filter set.
 * This will also cause the kernel to filter matching packets from the
 * kernel IP stack.
 *
 * \param[in]   exanic
 *      A valid ExaNIC handle
 * \param[in]   buffer
 *      A \ref exanic_rx_t obtained using exanic_acquire_rx_buffer
 * \param[in]   filter
 *      A \ref exanic_mac_filter_t containing the filter description
 *
 * \return An identifier for the new filter, or -1 on error
 */
int exanic_filter_add_mac(exanic_t *exanic,
                          const exanic_rx_t *buffer,
                          const exanic_mac_filter_t *filter);

/**
 * \brief Remove a filter from the IP filter set
 *
 * \param[in]   exanic
 *      A valid ExaNIC handle
 * \param[in]   port_number
 *      The port number
 * \param[in]   filter_id
 *      The identifier that was returned by \ref exanic_filter_add_ip
 *
 * \return 0 on success, or -1 if an error occurred
 */
int exanic_filter_remove_ip(exanic_t *exanic,
                         int port_number,
                         int filter_id);

/**
 * \brief Remove a filter from the MAC filter set
 *
 * \param[in]   exanic
 *      A valid ExaNIC handle
 * \param[in]   port_number
 *      The port number
 * \param[in]   filter_id
 *      The identifier that was returned by \ref exanic_filter_add_mac
 *
 * \return 0 on success, or -1 if an error occurred
 */
int exanic_filter_remove_mac(exanic_t *exanic,
                         int port_number,
                         int filter_id);

#ifdef __cplusplus
}
#endif

#endif /* EXANIC_FILTER_H */
