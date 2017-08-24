/**
 * \file
 * \brief ExaNIC time functions
 */
#ifndef EXANIC_TIME_H
#define EXANIC_TIME_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stdbool.h>
#include <sys/time.h>

/**
 * A time structure to keep picosecond values.
 */
struct exanic_timespecps
{
    int64_t tv_sec; /**< seconds since UNIX epoch */
    int64_t tv_psec; /**< picosecond portion */
};

/**
 * A full 64 bit ExaNIC timestamp counter. The value represents the number
 * of cycles (ticks) of the ExaNIC timestamp counter since the UNIX epoch.
 */
typedef int64_t exanic_cycles_t;

/**
 * This type keeps the lower 32 bits of the ExaNIC timestamp counter.
 */
typedef uint32_t exanic_cycles32_t;

/**
 * \brief Expand the lower 32 bits of an ExaNIC timestamp into a full 64 bit
 * timestamp since since the epoch (in cycles)
 *
 * \param[in]   exanic
 *      A valid ExaNIC handle
 * \param[in]   timestamp
 *      The lower 32 bits of a timestamp as obtained from the ExaNIC
 *
 * \return A 64 bit ExaNIC timestamp since the epoch (in cycles)
 *
 * \warning This function must be called within a few seconds of the
 * timestamped time, otherwise the output time will be incorrect.
 */
exanic_cycles_t exanic_expand_timestamp(exanic_t *exanic,
        exanic_cycles32_t timestamp);

/**
 * \brief Convert a cycles value into a standard Linux timespec structure.
 *
 * \param[in]   exanic
 *      A valid ExaNIC handle
 * \param[in]   cycles
 *      A cycles value
 * \param[out]  ts
 *      A timespec structure which holds seconds and nanoseconds components.
 *
 */
void exanic_cycles_to_timespec(exanic_t *exanic, exanic_cycles_t cycles,
        struct timespec *ts);

/**
 * \brief Convert a cycles value into a timespec with picosecond support.
 *
 * \param[in]   exanic
 *      A valid ExaNIC handle
 * \param[in]   cycles
 *      A cycles value
 * \param[out]  tsps
 *      A timespecps structure which holds seconds and picoseconds components.
 *
 */
void exanic_cycles_to_timespecps(exanic_t *exanic, exanic_cycles_t cycles,
        struct exanic_timespecps *tsps);


/**
 * \brief Convert a cycles value into nanoseconds
 *
 * \param[in]   exanic
 *      A valid ExaNIC handle
 * \param[in]   cycles
 *      A cycles value
 * \return A value in nanoseconds
 */
int64_t exanic_cycles_to_ns(exanic_t *exanic, exanic_cycles_t cycles);

/**
 * \brief Convert a cycles value into picoseconds
 *
 * \param[in]   exanic
 *      A valid ExaNIC handle
 * \param[in]   cycles
 *      A cycles value
 * \param[out]  overflow
 *      If a non-NULL pointer is provided, then this output indicates
 *      whether a the result was larger than 64 bits
 *
 * \return A value in picoseconds
 */
int64_t exanic_cycles_to_ps(exanic_t *exanic, exanic_cycles_t cycles,
        bool *overflow);



/**
 * \deprecated Convert ExaNIC timestamp to nanoseconds since epoch
 * This interface is now deprecated.
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
 * \deprecated Convert nanoseconds since epoch to ExaNIC timestamp.
 * This interface is now deprecated.
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

#endif /* EXANIC_TIME_H */
