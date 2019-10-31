#ifndef EXANIC_X4_I2C_H
#define EXANIC_X4_I2C_H

int exanic_x4_i2c_phy_read(exanic_t *exanic, int phy_number, uint8_t regaddr,
                    char *buffer, size_t size);

int exanic_x2_i2c_phy_read(exanic_t *exanic, int phy_number, uint8_t regaddr,
                    char *buffer, size_t size);

int exanic_x4_i2c_phy_write(exanic_t *exanic, int phy_number, uint8_t regaddr,
                    char *buffer, size_t size);

int exanic_x2_i2c_phy_write(exanic_t *exanic, int phy_number, uint8_t regaddr,
                    char *buffer, size_t size);

int exanic_x4_x2_i2c_sfp_read(exanic_t *exanic, int sfp_number, uint8_t devaddr,
                    uint8_t regaddr, char *buffer, size_t size);

int exanic_x40_i2c_sfp_read(exanic_t *exanic, int sfp_number, uint8_t devaddr,
                    uint8_t regaddr, char *buffer, size_t size);

int exanic_v9p_i2c_sfp_read(exanic_t *exanic, int sfp_number, uint8_t devaddr,
                    uint8_t regaddr, char *buffer, size_t size);

int exanic_x4_x2_i2c_sfp_write(exanic_t *exanic, int sfp_number, uint8_t devaddr,
                    uint8_t regaddr, char *buffer, size_t size);

int exanic_x40_i2c_sfp_write(exanic_t *exanic, int sfp_number, uint8_t devaddr,
                    uint8_t regaddr, char *buffer, size_t size);

int exanic_v9p_i2c_sfp_write(exanic_t *exanic, int sfp_number, uint8_t devaddr,
                    uint8_t regaddr, char *buffer, size_t size);

int exanic_x4_i2c_eeprom_read(exanic_t *exanic, uint8_t regaddr, char *buffer,
                    size_t size);

int exanic_x2_i2c_eeprom_read(exanic_t *exanic, uint8_t regaddr, char *buffer,
                    size_t size);

int exanic_x4_i2c_eeprom_write(exanic_t *exanic, uint8_t regaddr, char *buffer,
                    size_t size);

int exanic_x2_i2c_eeprom_write(exanic_t *exanic, uint8_t regaddr, char *buffer,
                    size_t size);

#endif /* EXANIC_X4_I2C_H */
