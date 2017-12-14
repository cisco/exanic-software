#ifndef _EXANIC_FWUPDATE_HOT_RELOAD_H
#define _EXANIC_FWUPDATE_HOT_RELOAD_H

#include <stdbool.h>
#include <exanic/exanic.h>

bool check_firmware_can_hot_reload(exanic_t *exanic, bool silent);
bool check_can_hot_reload(exanic_t *exanic, bool silent);
exanic_t *reload_firmware(exanic_t *exanic, void (*report_progress)());

#endif /* _EXANIC_FWUPDATE_HOT_RELOAD_H */
