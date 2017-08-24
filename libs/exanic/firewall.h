/**
 * \file
 * \author Ka-Shu Wong (kswong@zomojo.com)
 * \brief exanic firewall API
 *
 * Firewall configuration functions.
 */
#ifndef EXANIC_FIREWALL_H
#define EXANIC_FIREWALL_H

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief Return the current state of a firewall
 *
 * \param[in]   exanic
 *      A valid exanic handle
 *
 * \return The current state of the firewall
 */
exanic_firewall_state_t exanic_get_firewall_state(exanic_t *exanic);

/**
 * \brief Set the state of the firewall
 *
 * \param[in]   exanic
 *      A valid exanic handle
 *
 * \return 0 on success, or -1 if an error occurred
 */
int exanic_set_firewall_state(exanic_t *exanic, exanic_firewall_state_t state);

/**
 * \brief Get the number of supported filters on the firewall
 *
 * \param[in]   exanic
 *      A valid exanic handle
 *
 * \return The number of filters available
 */
int exanic_get_num_firewall_filters(exanic_t *exanic);

/**
 * \brief Configure a firewall filter rule
 *
 * \param[in]   exanic
 *      A valid exanic handle
 * \param[in]   slot
 *      The filter slot number
 * \param[in]   filter
 *      A pointer to a string in BPF-like syntax describing the filter
 *
 * \return 0 on success, or -1 if an error occurred
 */
int exanic_set_firewall_filter(exanic_t *exanic, int slot, const char *filter);

/**
 * \brief Retrieve a firewall filter rule
 *
 * \param[in]   exanic
 *      A valid exanic handle
 * \param[in]   slot
 *      The filter slot number
 * \param[out]  filter
 *      Pointer to a buffer for the filter string
 * \param[in]   filter_len
 *      The size of the filter buffer
 *
 * \return 0 on success, or -1 if an error occurred
 */
int exanic_get_firewall_filter(exanic_t *exanic, int slot, char *filter,
                               size_t filter_len);

/**
 * \brief Remove a firewall filter rule
 *
 * \param[in]   exanic
 *      A valid exanic handle
 * \param[in]   slot
 *      The filter slot number
 *
 * \return 0 on success, or -1 if an error occurred
 */
int exanic_clear_firewall_filter(exanic_t *exanic, int slot);

/**
 * \brief Remove all firewall filter rules
 *
 * \param[in]   exanic
 *      A valid exanic handle
 *
 * \return 0 on success, or -1 if an error occurred
 */
int exanic_clear_all_firewall_filters(exanic_t *exanic);

/**
 * \brief Get physical hardware firewall capability.
 *
 * \param[in]   exanic
 *      A valid exanic handle
 *
 * \return 1 if hardware supports firewall, 0 otherwise.
 */
int exanic_get_firewall_capability(exanic_t *exanic);

#ifdef __cplusplus
}
#endif

#endif /* EXANIC_FIREWALL_H */
