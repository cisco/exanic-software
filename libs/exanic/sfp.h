/**
 * \file
 * \brief Functions for communicating with SFPs
 */
#ifndef EXANIC_SFP_H
#define EXANIC_SFP_H

typedef struct exanic_sfp_info
{
    char        vendor_name[17];
    char        vendor_pn[17];
    char        vendor_rev[5];
    char        vendor_sn[17];
    char        date_code[9];
    int         wavelength;
    int         bit_rate;
} exanic_sfp_info_t;

typedef struct exanic_qsfp_info
{
    char        vendor_name[17];
    char        vendor_pn[17];
    char        vendor_rev[3];
    char        vendor_sn[17];
    char        date_code[9];
    int         wavelength;
    int         bit_rate;
} exanic_qsfp_info_t;

int exanic_get_sfp_info(exanic_t *exanic, int port_number,
                        exanic_sfp_info_t *info);

int exanic_get_qsfp_info(exanic_t *exanic, int port_number,
                        exanic_qsfp_info_t *info);

typedef struct exanic_sfp_diag_info
{
    float       temp;       /* degrees C */
    float       rx_power;   /* mW */
    float       tx_power;   /* mW */
} exanic_sfp_diag_info_t;

typedef struct exanic_qsfp_diag_info
{
    float       temp;          /* degrees C */
    float       rx_power[4];   /* mW */
    float       tx_bias[4];    /* mA */
} exanic_qsfp_diag_info_t;

int exanic_get_sfp_diag_info(exanic_t *exanic, int port_number,
                             exanic_sfp_diag_info_t *info);

int exanic_get_qsfp_diag_info(exanic_t *exanic, int port_number,
                             exanic_qsfp_diag_info_t *info);


#endif /* EXANIC_SFP_H */
