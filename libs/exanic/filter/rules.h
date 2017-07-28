/**
 * \file
 * \author Ka-Shu Wong (kswong@zomojo.com)
 * \brief Filter rules management
 *
 * Functions for storing and retrieving a set of filter rules
 */
#ifndef EXANIC_FILTER_RULES_H
#define EXANIC_FILTER_RULES_H

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief Store a filter string in the shared memory
 *
 * \param[in]   ruleset
 *      Identification string for the set of rules
 * \param[in]   slot
 *      The filter slot number
 * \param[in]   filter
 *      A pointer to a string in BPF-like syntax describing the filter
 *
 * \return 0 on success, or -1 if an error occurred
 */
int exanic_set_filter_string(const char *ruleset, int slot, const char *filter);

/**
 * \brief Retrieve a filter string from the shared memory
 *
 * \param[in]   ruleset
 *      Identification string for the set of rules
 * \param[in]   slot
 *      The filter slot number
 * \param[out]  filter
 *      Pointer to a buffer for the filter string
 * \param[in]   filter_len
 *      The size of the filter buffer
 *
 * \return 0 on success, or -1 if an error occurred
 */
int exanic_get_filter_string(const char *ruleset, int slot, char *filter,
                             int filter_len);

/**
 * \brief Remove a filter string
 *
 * \param[in]   ruleset
 *      Identification string for the set of rules
 * \param[in]   slot
 *      The filter slot number
 *
 * \return 0 on success, or -1 if an error occurred
 */
int exanic_clear_filter_string(const char *ruleset, int slot);

/**
 * \brief Remove all filter strings
 *
 * \param[in]   ruleset
 *      Identification string for the set of rules
 */
int exanic_clear_all_filter_strings(const char *ruleset);

#ifdef __cplusplus
}
#endif

#endif /* EXANIC_FILTER_RULES_H */
