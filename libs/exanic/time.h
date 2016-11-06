/**
 * \file
 * \brief ExaNIC time functions
 */
#ifndef TIME_H_0630DBEBB2AB5AB62A5FDF88CAECEC39
#define TIME_H_0630DBEBB2AB5AB62A5FDF88CAECEC39

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief Convert ExaNIC timestamp to nanoseconds since epoch
 *
 * \param[in]   exanic
 *      A valid ExaNIC handle
 * \param[in]   timestamp
 *      A timestamp obtained from the ExaNIC
 *
 * \return Time in nanoseconds since epoch
 *
 * \warning This function must be called within a few seconds of the
 * timestamped time, otherwise the output time will be incorrect.
 */
uint64_t exanic_timestamp_to_counter(exanic_t *exanic, uint32_t timestamp);

/**
 * \brief Convert nanoseconds since epoch to ExaNIC timestamp
 *
 * \param[in]   exanic
 *      A valid ExaNIC handle
 * \param[in]   counter
 *      A time in nanoseconds since epoch
 *
 * \return Timestamp value for the provided time
 */
uint32_t exanic_counter_to_timestamp(exanic_t *exanic, uint64_t counter);

#ifdef __cplusplus
}
#endif

#endif /* TIME_H_0630DBEBB2AB5AB62A5FDF88CAECEC39 */
