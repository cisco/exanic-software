#include <arpa/inet.h>

#include "../exanic.h"
#include "../pcie_if.h"
#include "i2c.h"
#include "port.h"

/* Check for Marvell 88E1111 chip (used in Finisar FCLF-8520-3 copper SFPs) */
static int marvell_88e1111_check(exanic_t *exanic, int port_number)
{
    uint16_t id0, id1;
    int r1, r2;

    r1 = z1_i2c_sfp_read(exanic, port_number, 0xAC, 0x02, (char *)&id0, 2);
    r2 = z1_i2c_sfp_read(exanic, port_number, 0xAC, 0x03, (char *)&id1, 2);

    return r1 == 0 && r2 == 0 &&
        ntohs(id0) == 0x0141 &&
        (ntohs(id1) & 0xFFF0) == 0x0CC0;
}

/* Set port speed on Marvell 88E1111 PHY chip.
 * See "88E1111 Datasheet" (Marvell document no. MV-S100649-00) */
static void marvell_88e1111_set_port_speed(exanic_t *exanic, int port_number,
                                           unsigned speed)
{
    uint16_t data;

    if (speed == 1000)
    {
        /* Switch to copper register bank */
        data = htons(0x0000);
        z1_i2c_sfp_write(exanic, port_number, 0xAC, 0x16, (char *)&data, 2);

        /* Extended PHY Specific Status Register */
        z1_i2c_sfp_read(exanic, port_number, 0xAC, 0x1B, (char *)&data, 2);
        /* "1000BASE-X without clock without 100BASE-X auto-neg to copper" */
        data = (data & ~htons(0x000F)) | htons(0x000C);
        z1_i2c_sfp_write(exanic, port_number, 0xAC, 0x1B, (char *)&data, 2);

        /* Control Register (Copper) */
        z1_i2c_sfp_read(exanic, port_number, 0xAC, 0x00, (char *)&data, 2);
        /* Reset bit */
        data |= htons(0x8000);
        z1_i2c_sfp_write(exanic, port_number, 0xAC, 0x00, (char *)&data, 2);

        /* 1000BASE-T Control Register */
        z1_i2c_sfp_read(exanic, port_number, 0xAC, 0x09, (char *)&data, 2);
        /* Advertise 1000BASE-T Full-Duplex only */
        data = (data & ~htons(0x0300)) | htons(0x0200);
        z1_i2c_sfp_write(exanic, port_number, 0xAC, 0x09, (char *)&data, 2);

        /* Auto-Negotiation Advertisement Register (Copper) */
        z1_i2c_sfp_read(exanic, port_number, 0xAC, 0x04, (char *)&data, 2);
        /* Do not advertise 100BASE-T or 10BASE-T */
        data = (data & ~htons(0x03E0)) | htons(0x0000);
        z1_i2c_sfp_write(exanic, port_number, 0xAC, 0x04, (char *)&data, 2);

        /* Control Register (Copper) */
        z1_i2c_sfp_read(exanic, port_number, 0xAC, 0x00, (char *)&data, 2);
        /* 1000Mbps */
        data = (data & ~htons(0x2040)) | htons(0x0040);
        /* Reset bit */
        data |= htons(0x8000);
        /* Full-duplex */
        data |= htons(0x0100);
        /* Enable autonegotiation */
        data |= htons(0x1000);
        z1_i2c_sfp_write(exanic, port_number, 0xAC, 0x00, (char *)&data, 2);

        /* LED Control Register */
        z1_i2c_sfp_read(exanic, port_number, 0xAC, 0x18, (char *)&data, 2);
        /* LED_Link = 000 (Direct LED mode) */
        data = (data & htons(0x0038)) | htons(0x0000);
        z1_i2c_sfp_write(exanic, port_number, 0xAC, 0x18, (char *)&data, 2);
    }
    else if (speed == 100)
    {
        /* Switch to copper register bank */
        data = htons(0x0000);
        z1_i2c_sfp_write(exanic, port_number, 0xAC, 0x16, (char *)&data, 2);

        /* Extended PHY Specific Status Register */
        z1_i2c_sfp_read(exanic, port_number, 0xAC, 0x1B, (char *)&data, 2);
        /* "SGMII without clock with SGMII auto-neg to copper" */
        data = (data & ~htons(0x000F)) | htons(0x0004);
        z1_i2c_sfp_write(exanic, port_number, 0xAC, 0x1B, (char *)&data, 2);

        /* Control Register (Copper) */
        z1_i2c_sfp_read(exanic, port_number, 0xAC, 0x00, (char *)&data, 2);
        /* Reset bit */
        data |= htons(0x8000);
        z1_i2c_sfp_write(exanic, port_number, 0xAC, 0x00, (char *)&data, 2);

        /* 1000BASE-T Control Register */
        z1_i2c_sfp_read(exanic, port_number, 0xAC, 0x09, (char *)&data, 2);
        /* Do not advertise 1000BASE-T */
        data &= ~htons(0x0300);
        z1_i2c_sfp_write(exanic, port_number, 0xAC, 0x09, (char *)&data, 2);

        /* Auto-Negotiation Advertisement Register (Copper) */
        z1_i2c_sfp_read(exanic, port_number, 0xAC, 0x04, (char *)&data, 2);
        /* Advertise 100BASE-TX Full-Duplex and Half-Duplex */
        data = (data & ~htons(0x03E0)) | htons(0x0180);
        z1_i2c_sfp_write(exanic, port_number, 0xAC, 0x04, (char *)&data, 2);

        /* Control Register (Copper) */
        z1_i2c_sfp_read(exanic, port_number, 0xAC, 0x00, (char *)&data, 2);
        /* 100Mbps */
        data = (data & ~htons(0x2040)) | htons(0x2000);
        /* Reset bit */
        data |= htons(0x8000);
        /* Full-duplex */
        data |= htons(0x0100);
        /* Enable autonegotiation */
        data |= htons(0x1000);
        z1_i2c_sfp_write(exanic, port_number, 0xAC, 0x00, (char *)&data, 2);

        /* LED Control Register */
        z1_i2c_sfp_read(exanic, port_number, 0xAC, 0x18, (char *)&data, 2);
        /* LED_Link = 001 (use LED_LINK1000 pin as global link indicator) */
        data = (data & htons(0x0038)) | htons(0x0008);
        z1_i2c_sfp_write(exanic, port_number, 0xAC, 0x18, (char *)&data, 2);
    }
}

int z1_set_port_speed(exanic_t *exanic, int port_number, unsigned speed)
{
    if (speed != 1000 && speed != 100)
    {
        exanic_err_printf("unsupported port speed: %u Mbps", speed);
        return -1;
    }

    int marvell_88e1111 = marvell_88e1111_check(exanic, port_number);

    /* Check for supported SFP */
    if (speed != 1000 && !marvell_88e1111)
    {
        exanic_err_printf("unsupported SFP");
        return -1;
    }

    /* Set port speed on FPGA */
    uint32_t bit_100mb = 1 << (8 * port_number);
    if (speed == 1000)
        exanic->registers[REG_HW_INDEX(REG_HW_100MB_MODE)] &= ~bit_100mb;
    else if (speed == 100)
        exanic->registers[REG_HW_INDEX(REG_HW_100MB_MODE)] |= bit_100mb;

    if (exanic->registers[REG_PORT_INDEX(port_number, REG_PORT_SPEED)] != speed)
    {
        exanic_err_printf("port speed configuration failed");
        return -1;
    }

    /* Set port speed on SFP if needed */
    if (marvell_88e1111)
        marvell_88e1111_set_port_speed(exanic, port_number, speed);

    return 0;
}
