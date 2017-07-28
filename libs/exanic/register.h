/**
 * \file
 * \brief Registers API
 *
 * \note
 * <b>These functions must not be used in any latency-critical code.</b>\n
 * Most users should \b NOT include this header.  It's only necessary for
 * ExaNIC configuration, debugging and/or hacking.
 */
#ifndef EXANIC_REGISTER_H
#define EXANIC_REGISTER_H

#include "pcie_if.h"

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief Read from a ExaNIC register
 *
 * \param[in]   exanic
 *      A valid ExaNIC handle
 * \param[in]   reg
 *      The ExaNIC register to read
 *
 * \return The value of the register
 */
static inline uint32_t exanic_register_read(exanic_t *exanic, int reg)
{
    return exanic->registers[reg];
}

/**
 * \brief Write to a ExaNIC register
 *
 * \param[in]   exanic
 *      A valid ExaNIC handle
 * \param[in]   reg
 *      The ExaNIC register to write to
 * \param[in]   val
 *      The value to write
 */
static inline void exanic_register_write(exanic_t *exanic, int reg, uint32_t val)
{
    exanic->registers[reg] = val;
}

#ifdef __cplusplus
}
#endif

#endif /* EXANIC_REGISTER_H */
