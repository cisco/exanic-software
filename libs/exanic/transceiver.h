/**
 * \file
 * \brief Functions for communicating with pluggable transceivers
 */
#ifndef EXANIC_XCVR_H
#define EXANIC_XCVR_H

typedef struct
{
    char        vendor_name[65];
    char        vendor_pn[65];
    char        vendor_rev[65];
    char        vendor_sn[65];
    char        date_code[9];
    int         wavelength;
    int         bit_rate;
} exanic_xcvr_info_t;

/* port_number: ethernet interface number */
int exanic_get_xcvr_info(exanic_t *exanic, int port_number,
                         exanic_xcvr_info_t *info);

struct exanic_port_xcvr_diag
{
    double       rx_power;   /* uW */
    double       tx_power;   /* uW */
    double       tx_bias;    /* uA */
};

typedef struct
{
    double                       temp;      /* degrees C */
    unsigned                     num_lanes;
    struct exanic_port_xcvr_diag lanes[0];  /* per lane diagnostics */
} exanic_xcvr_diag_info_t;

/* port_number: ethernet interface number */
int exanic_get_xcvr_diag_info(exanic_t *exanic, int port_number,
                              exanic_xcvr_diag_info_t **info);

#endif /* EXANIC_XCVR_H */
