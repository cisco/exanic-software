/**
 * ExaNIC PHY level operations for CMIS rev 3.0 compliant modules
 * Copyright (C) 2011-2019 Exablaze Pty Ltd and its licensors
 */

#ifndef _EXANIC_PHYOPS_CMIS_H_
#define _EXANIC_PHYOPS_CMIS_H_

/* CMIS config functions, called with the ExaNIC mutex held */
int exanic_phyops_cmis_init(struct exanic *exanic, int port);
void exanic_phyops_cmis_powerdown(struct exanic *exanic, int port);
int exanic_phyops_cmis_set_speed(struct exanic *exanic, int port,
                                 uint32_t old_speed, uint32_t speed);

#endif /* _EXANIC_PHYOPS_CMIS_H_ */
