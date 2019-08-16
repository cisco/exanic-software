#include "exanic.h"
#include "pcie_if.h"
#include "port.h"
#include "util.h"

int exanic_check_supported(exanic_t *exanic)
{
    uint32_t pcie_if_ver;
    exanic_hardware_id_t hw_id;
    exanic_function_id_t func_id;

    pcie_if_ver = exanic->registers[REG_EXANIC_INDEX(REG_EXANIC_PCIE_IF_VER)];
    hw_id = exanic->registers[REG_EXANIC_INDEX(REG_EXANIC_HW_ID)];
    func_id = exanic->registers[REG_EXANIC_INDEX(REG_EXANIC_FUNCTION_ID)];

    if (pcie_if_ver != 1)
    {
        exanic_err_printf("unknown exanic interface version: %u", pcie_if_ver);
        return -1;
    }

    if (exanic_hardware_id_str(hw_id) == NULL)
    {
        exanic_err_printf("unknown hardware ID: %u", hw_id);
        return -1;
    }

    if (exanic_function_id_str(func_id) == NULL)
    {
        exanic_err_printf("unknown exanic function ID: %u", func_id);
        return -1;
    }

    return 0;
}

exanic_hardware_id_t exanic_get_hw_type(exanic_t *exanic)
{
    return exanic->registers[REG_EXANIC_INDEX(REG_EXANIC_HW_ID)];
}

exanic_function_id_t exanic_get_function_id(exanic_t *exanic)
{
    return exanic->registers[REG_EXANIC_INDEX(REG_EXANIC_FUNCTION_ID)];
}

uint32_t exanic_get_caps(exanic_t *exanic)
{
    return exanic->registers[REG_EXANIC_INDEX(REG_EXANIC_CAPS)];
}

time_t exanic_get_hw_rev_date(exanic_t *exanic)
{
    return exanic->registers[REG_EXANIC_INDEX(REG_EXANIC_HW_REV_DATE)];
}

volatile uint32_t *exanic_get_devkit_registers(exanic_t *exanic)
{
    return exanic->devkit_regs_region;
}

char *exanic_get_devkit_memory(exanic_t *exanic)
{
    return exanic->devkit_mem_region;
}

volatile uint32_t *exanic_get_extended_devkit_registers(exanic_t *exanic)
{
    return exanic->devkit_regs_ex_region;
}

char *exanic_get_extended_devkit_memory(exanic_t *exanic)
{
    return exanic->devkit_mem_ex_region;
}

int exanic_is_devkit_demo(exanic_t *exanic)
{
    return exanic->registers[REG_EXANIC_INDEX(REG_EXANIC_DEVKIT_DEMO_IMAGE)] == 1;
}
