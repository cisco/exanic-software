#ifndef _EXANIC_FWUPDATE_FILE_ACCESS_H
#define _EXANIC_FWUPDATE_FILE_ACCESS_H

#include "flash_access.h"

flash_word_t *read_firmware(const char *filename, flash_size_t partition_size,
                            flash_size_t *data_size, const char **firmware_id);

#endif /* _EXANIC_FWUPDATE_FILE_ACCESS_H */
