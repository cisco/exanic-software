#ifndef _EXANIC_FWUPDATE_BITSTREAM_CONFIG_H
#define _EXANIC_FWUPDATE_BITSTREAM_CONFIG_H

#include "flash_access.h"

bool check_bitstream_config(struct flash_device *flash, flash_word_t *data, flash_size_t size);

#endif /* _EXANIC_FWUPDATE_BITSTREAM_CONFIG_H */
