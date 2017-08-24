/**
 * \file
 * \brief Miscellaneous exanic utility functions.
 */
#ifndef EXANIC_UTIL_H
#define EXANIC_UTIL_H

#include "pcie_if.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief Return an error if the ExaNIC is not supported by this libexanic
 *
 * Unsupported ExaNICs are still allowed basic functionality, such as
 * register read and write.
 *
 * \param[in]   exanic
 *      A valid ExaNIC handle
 *
 * \return 0 on success, or -1 if the ExaNIC is not supported
 */
int exanic_check_supported(exanic_t *exanic);

/**
 * \brief Return the hardware ID of a ExaNIC.
 *
 * \param[in]   exanic
 *      A valid ExaNIC handle
 *
 * \return The hardware ID of the ExaNIC.
 */
exanic_hardware_id_t exanic_get_hw_type(exanic_t *exanic);

/**
 * \brief Return the function ID of a ExaNIC.
 *
 * \param[in]   exanic
 *      A valid ExaNIC handle
 *
 * \return The function ID of the ExaNIC.
 */
exanic_function_id_t exanic_get_function_id(exanic_t *exanic);

/**
 * \brief Get the date stamp of the firmware on the ExaNIC.
 *
 * \param[in]   exanic
 *      A valid ExaNIC handle
 *
 * \return Firmware date stamp in unix time (seconds since epoch).
 */
time_t exanic_get_hw_rev_date(exanic_t *exanic);

/**
 * \brief Get the devkit user registers region.
 *
 * \param[in]   exanic
 *      A valid ExaNIC handle
 *
 * \return A pointer to the user registers on a devkit card.
 */
volatile uint32_t *exanic_get_devkit_registers(exanic_t *exanic);

/**
 * \brief Get the devkit user memory region.
 *
 * \param[in]   exanic
 *      A valid ExaNIC handle
 *
 * \return A pointer to the user memory region on a devkit card.
 */
char *exanic_get_devkit_memory(exanic_t *exanic);

/**
 * \brief Check if a devkit image is a time limited demo version.
 *
 * \param[in]   exanic
 *      A valid ExaNIC handle
 *
 * \return 1 if image is a demo version, 0 otherwise.
 */
int exanic_is_devkit_demo(exanic_t *exanic);

#ifdef __cplusplus
}
#endif

#endif /* EXANIC_UTIL_H */
