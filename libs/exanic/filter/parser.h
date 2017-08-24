/**
 * \file
 * \author Ka-Shu Wong (kswong@zomojo.com)
 * \brief Filter parser
 *
 * Functions for parsing a filter description
 */
#ifndef EXANIC_FILTER_PARSER_H
#define EXANIC_FILTER_PARSER_H

#ifdef __cplusplus
extern "C" {
#endif

enum
{
    EXANIC_FILTER_STRING_MAX_LEN = 256,
    EXANIC_FILTER_SIZE           = 44,
};

/**
 * \brief Parse a string in BPF-like syntax
 *
 * \param[in]   filter
 *      A pointer to a string in BPF-linke syntax
 * \param[out]  pattern
 *      The filter pattern
 * \param[out]  mask
 *      The filter mask
 * \param[out]  drop_rule
 *      The type of rule: 0 for allow, 1 for drop
 *
 * \return 0 on success, or -1 if an error occurred
 */
int exanic_parse_filter_string(const char *filter, char *pattern, char *mask,
                               int *drop_rule);

#ifdef __cplusplus
}
#endif

#endif /* EXANIC_FILTER_PARSER_H */
