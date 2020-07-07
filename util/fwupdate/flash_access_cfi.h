#ifndef _EXANIC_FWUPDATE_FLASH_ACCESS_CFI_H
#define _EXANIC_FWUPDATE_FLASH_ACCESS_CFI_H

struct flash_device *flash_open_cfi(exanic_t *exanic, bool recovery_partition,
        flash_size_t *partition_size);

#endif /*_EXANIC_FWUPDATE_FLASH_ACCESS_CFI_H */
