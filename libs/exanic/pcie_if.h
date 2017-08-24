/**
 * \file
 * \brief ExaNIC PCIe Interface
 *
 * This file defines the PCIe interface between the host and the ExaNIC.  Any
 * changes to this interface should bump up the value of \ref
 * REG_EXANIC_PCIE_IF_VER.
 *
 * This documentation describes \ref REG_EXANIC_PCIE_IF_VER = 1.
 */
#ifndef EXANIC_PCIE_IF_H
#define EXANIC_PCIE_IF_H

#ifndef PAGE_SIZE
#define PAGE_SIZE 4096UL
#endif

/**
 * \brief ExaNIC constants
 */
enum
{
    /** Maximum number of ExaNICs that can be utilised in a machine. */
    EXANIC_MAX_NUM_DEVICES          = 4,

    /** Registers are at this BAR */
    EXANIC_REGS_BAR                 = 0,

    /** TX region is at this BAR */
    EXANIC_TX_REGION_BAR            = 2,

    /** The number of 4K pages for mapping the ExaNIC registers */
    EXANIC_REGS_NUM_PAGES           = 2,

    /** The number of 4K pages for the ExaNIC info region */
    EXANIC_INFO_NUM_PAGES           = 1,

    /** The number of 4K pages for a TX feedback region */
    EXANIC_TX_FEEDBACK_NUM_PAGES    = 1,

    /** The number of TX feedback slots per ExaNIC */
    EXANIC_TX_FEEDBACK_NUM_SLOTS    = 256,

    /** TX region size divided by the number of TX command FIFO entries */
    EXANIC_TX_CMD_FIFO_SIZE_DIVISOR = 512,

    /** The maximum number of 4K pages for a ExaNIC TX region. */
    EXANIC_TX_REGION_MAX_NUM_PAGES  = 512,  /* 2M */

    /** Number of DWORDs for a filter component. */
    EXANIC_FILTER_NUM_DWORDS        = 11,   /* 44 bytes */

    /** The size of an RX chunk including the metadata (in bytes) */
    EXANIC_RX_CHUNK_SIZE            = 128,

    /** The size of an RX chunk without the metadata (in bytes) */
    EXANIC_RX_CHUNK_PAYLOAD_SIZE    = 120,

    /** The number of 4K pages for an RX DMA region */
    EXANIC_RX_DMA_NUM_PAGES         = 512,  /* 2M */

    /** The number of RX chunks in a RX DMA region. Must be a power of 2. */
    EXANIC_RX_NUM_CHUNKS            = EXANIC_RX_DMA_NUM_PAGES * PAGE_SIZE /
                                      EXANIC_RX_CHUNK_SIZE,

    /** Number of filters in each bank. */
    EXANIC_NUM_FILTERS_PER_BANK     = 32,

    /** Number of filters in each filter region. */
    EXANIC_NUM_FILTERS_PER_REGION   = 256,

    /** Devkit memory region is at this BAR. */
    EXANIC_DEVKIT_MEMORY_REGION_BAR = 2,
};

/**
 * \brief 0x0000-0x00FF: Common ExaNIC registers
 *
 * These registers appear in the same spot across multiple ExaNICs.
 */
enum
{
    REG_EXANIC_BASE                     = 0x0000,

    /**
     * [RO] PCIe interface version.  Each version defines a particular
     * register map, address mappings, and PCIe functionality.
     */
    REG_EXANIC_PCIE_IF_VER              = 0,

    /**
     * [RO] Hardware ID (see \ref exanic_hardware_id_t).
     */
    REG_EXANIC_HW_ID                    = 1,

    /**
     * [RW] Configures various ExaNIC features. Also contains some status bits.
     * (see \ref exanic_feature_cfg_t)
     * Availability: NIC only
     * Bitmap:
     * [17]   - [RO] HW startup in progress
     * [16]   - [RW] Set to 0 to permanently clear the auxiliary enable signals
     * [15]   - reserved
     * [14:8] - [RO] Auxiliary bridging & mirroring configuration bits
     * [7]    - reserved
     * [6:0]  - Bridging & mirroring configuration bits
     */
    REG_EXANIC_FEATURE_CFG              = 2,

    /**
     * [RO] Hardware revision date.
     */
    REG_EXANIC_HW_REV_DATE              = 3,

    /**
     * [RO] Maximum supported DMA address width in bits (32 or 64).
     * Availability: NIC only
     */
    REG_EXANIC_DMA_ADDR_WIDTH           = 4,

    /**
     * [RW] Base address of the region used for TX feedback (upper 32 bits).
     * Availability: NIC only
     *
     * \warning This register must be set to 0 if a 32 bit address is in use.
     */
    REG_EXANIC_TX_FEEDBACK_BASE_ADDR_HI = 5,

    /**
     * [RW] Base address of the region used for TX feedback (low 32 bits).
     * Bit 0 is set to 1 for a 32 bit address and 0 for a 64 bit address
     * (see \ref exanic_dma_addr_cfg_t).
     * Availability: NIC only
     *
     * \warning The region must be page aligned.
     */
    REG_EXANIC_TX_FEEDBACK_BASE_ADDR_LO = 6,

    /**
     * [RO] The first 3 octets (OUI) of the MAC address.
     * 0x563412 in this register results in the OUI 12:34:56.
     * Availability: NIC only
     */
    REG_EXANIC_MAC_ADDR_OUI             = 7,

    /**
     * [RO] Function ID (see \ref exanic_function_id_t).
     */
    REG_EXANIC_FUNCTION_ID              = 8,

    /**
     * [RO] Current time according to the ExaNIC clock.
     */
    REG_EXANIC_HW_TIME                  = 9,

    /**
     * [WO] Set the ExaNIC clock to the value written into this register.
     */
    REG_EXANIC_CLK_SET                  = 10,

    /**
     * [RW] Clock correction factor.  The clock will be incremented or
     * decremented once every n ticks.  Bits 0:23 contains n and
     * bit 24 controls the direction of the adjustment.
     * (see \ref exanic_clk_adj_t)
     */
    REG_EXANIC_CLK_ADJ                  = 11,

    /**
     * [RO] Value of ExaNIC clock counter at last PPS pulse.
     */
    REG_EXANIC_PPS_TIMESTAMP            = 12,

    /**
     * [RO] Nominal frequency of ExaNIC clock (Hz).
     */
    REG_EXANIC_CLK_HZ                   = 13,

    /**
     * [RO] Capabilities flags (see \ref exanic_caps_t).
     */
    REG_EXANIC_CAPS                     = 14,

    /**
     * [RO] Upper bits of the ExaNIC clock.
     * Availability: PTP grandmaster
     */
    REG_EXANIC_HW_TIME_HI               = 15,

    /**
     * [WO] Set the upper bits of the ExaNIC clock.
     * Availability: PTP grandmaster
     */
    REG_EXANIC_CLK_SET_HI               = 16,

    /**
     * [RW] Extended clock correction factor.  This is a signed 32 bit
     * value in units of parts per 2^40.
     */
    REG_EXANIC_CLK_ADJ_EXT              = 17,

    /**
     * [RW] Bi-color LED control
     * Bit 0 - Green LED on
     * Bit 1 - Red LED on
     */
    REG_EXANIC_PPS_LED_CTRL             = 32,

    /**
     * [RO] The number of DMA buffers supported per port when using
     * flow hashing or flow steering.
     * Availability: X4, X2
     */
    REG_EXANIC_NUM_FILTER_BUFFERS       = 33,

    /**
     * [RO] The offset of the devkit region when using the ExaNIC devkit.
     * Availability: ExaNIC Development Kits
     */
    REG_EXANIC_DEVKIT_REGISTERS_OFFSET  = 34,

    /**
     * [RO] The offset of the devkit region when using the ExaNIC devkit.
     * Availability: ExaNIC Development Kits
     */
    REG_EXANIC_DEVKIT_MEMORY_OFFSET     = 35,

    /**
     * [RO] Reads 1 if this is a time-limited demo devkit image.
     * Availability: ExaNIC Development Kits
     */
    REG_EXANIC_DEVKIT_DEMO_IMAGE        = 36,

    /**
     * [RO] For devkit images, this is the user version provided in at compile
     * time to the ExaNIC netlist.
     * Availability: ExaNIC Development Kits
     */
    REG_EXANIC_DEVKIT_USER_VERSION      = 37,
};
#define REG_EXANIC_OFFSET(reg) (REG_EXANIC_BASE + (reg) * sizeof(uint32_t))
#define REG_EXANIC_INDEX(reg) (REG_EXANIC_OFFSET(reg) / sizeof(uint32_t))

/**
 * \brief 0x0100-0x01FF: Hardware-specific Registers
 *
 * These are the hardware-specific registers that are defined only for the
 * particular type of ExaNIC.
 */
enum
{
    REG_HW_BASE                         = 0x0100,

    /**
     * [WO] ExaNIC X4/X2 reload/reinitialise
     * Availability: X4, X2
     * Writing a '1' to either register causes:
     * Bit 1 [WO] - Re-initialise/reset FPGA
     * Bit 0 [WO] - Reload FPGA image from flash
     * Writing both bits simultaneously results in undefined behaviour
     */
    REG_HW_RELOAD_RESET_FPGA            = 0,

    /**
     * [RW] Registers for JTAG programming.
     * Availability: Z1 only
     */
    REG_HW_JTAG_TMS                     = 0,

    REG_HW_JTAG_TDIO                    = 1,

    REG_HW_JTAG_SHIFT_COUNT             = 2,

    /**
     * [RO] On-die FPGA temperature representation.
     * Availability: Z1, Z10, X4, X2
     */
    REG_HW_TEMPERATURE                  = 3,

    /**
     * [RO] Board version ID
     * Availability: Z1, Z10, X4, X2
     */
    REG_HW_BOARD_ID                     = 4,

    /**
     * [RO] FPGA core voltage VCCint
     * Availability: Z1, Z10, X4, X2
     */
    REG_HW_VCCINT                       = 5,

    /**
     * [RO] FPGA aux voltage VCCaux
     * Availability: Z1, Z10, X4, X2
     */
    REG_HW_VCCAUX                       = 6,

    /**
     * [RO] Power detect status bits
     * Availability: Z10 only
     */
    REG_HW_POWERDETECT                  = 7,

    /**
     * [RO] Used for detecting CPLD ACK
     * Availability: Z10 only
     */
    REG_HW_CPLD_ACK                     = 8,

    /**
     * [RW] Used to transfer data to/from CPLD
     * Availability: Z10 only
     */
    REG_HW_CPLD_DATA                    = 9,

    /**
     * [RW] Used to signal a new data transfer to/from CPLD
     * Availability: Z10 only
     */
    REG_HW_CPLD_CMD                     = 10,

    /**
     * [RW] GPIO register for use with I2C
     * Availability: Z1 only
     */
    REG_HW_I2C_GPIO                     = 11,

    /**
     * [RW] Z1 100Mb mode enable
     * Availability: Z1 only
     */
    REG_HW_100MB_MODE                   = 12,

    /**
     * [RW] Bitmask of PHYs to power down and SFP TX DIS
     * Availability: X4, X2
     */
    REG_HW_POWERDOWN                    = 14,

    /**
     * [RW] PRBS control (BER testing only)
     * Availability: X4, X2
     * [6:5] Select port for REG_HW_PRBS_ERR_CNT
     * [4:1] Select lane for REG_HW_PRBS_ERR_CNT
     * 0     PRBS Enable (applies to all ports in NIC!)
     */
    REG_HW_PRBS_CTRL                    = 19,

    /**
     * [RO] PRBS error count for a given port/lane
     * Availability: X4, X2
     * [31:0] Number of bits in error
     */
    REG_HW_PRBS_ERR_CNT                 = 20,

    /**
     * PPS connector signals
     * Bit 9 [RW] - PPS input edge select [0: falling, 1: rising]
     * Bit 8 [RW] - PPS output value (X10/X10-GM/X40 only)
     * Bit 7 [RW] - PPS output enable (X10/X10-GM/X40 only)
     * Bit 6 [RW] - PPS 50ohm Termination  enable (X10/X10-GM/X40 only)
     * Bit 5 [RW] - PPS source select [0: diff, 1: single-ended] (X2/X4 only)
     * Bit 4 [RO] - Single ended PPS input
     * Bit 3 [RO] - Differential PPS input (X2/X4 only)
     * Bit 2 [RO] - RS-485 Rx data pin (X2/X4 only)
     * Bit 1 [RW] - RX-485 Tx data pin (X2/X4 only)
     * Bit 0 [RW] - RX-485 Tx ctrl pin (X2/X4 only)
     * (see \ref exanic_hw_serial_t)
     */
    REG_HW_SERIAL_PPS                   = 21,

    /**
     * [RO] A count of the number of fan pulses seen before the expiry of a
     * timer. The duration of the measurement window is determined by dividing
     * the value in REG_EXANIC_CLK_HZ by 2^N, where N is the upper 8 bits of
     * this register.
     * [31:24] - N, where 2^N is used to divide the incoming reference clock
     * [23: 0] - number of fan pulses seen during measurement interval
     */
    REG_HW_FAN_REV_COUNTER              = 22,

    /**
     * [WO] Set the REG_EXANIC_HW_TIME value the card should output a pulse on
     * Availability: X10, X40
     */
    REG_HW_NEXT_PER_OUT                 = 23,

    /**
     * [RW] Set the length of the output pulse the card should generate in
     * units of 1/REG_EXANIC_CLK_HZ
     * Availability: X10, X40, X10-GM
     */
    REG_HW_PER_OUT_WIDTH                = 24,

    /**
     * [RW] Configuration bits for periodic timing output
     * Availability: X10, X40, X10-GM
     * Bit 0 [RW] - 1PPS generator
     * Bit 1 [RW] - 10MHz generator (X10-GM only)
     */
    REG_HW_PER_OUT_CONFIG               = 25,
};
#define REG_HW_OFFSET(reg) (REG_HW_BASE + (reg) * sizeof(uint32_t))
#define REG_HW_INDEX(reg) (REG_HW_OFFSET(reg) / sizeof(uint32_t))

/**
 * \brief 0x0200-0x02FF: Port-specific Registers
 *
 * These registers provide information about each ExaNIC port, and configures
 * the RX/TX engines associated with each port.
 */
enum
{
    REG_PORT_BASE                       = 0x0200,

    /**
     * [RW] Whether a port is enabled or not.
     */
    REG_PORT_ENABLED                    = 0,

    /**
     * [RO] Port speed (in Mbps)
     */
    REG_PORT_SPEED                      = 1,

    /**
     * [RO] Port status (see \ref exanic_port_status_t).
     */
    REG_PORT_STATUS                     = 2,

    /**
     * [RW] The last three octets (NIC) of the MAC address.
     * 0x563412 in this register results in the address 12:34:56.
     * Availability: NIC only
     */
    REG_PORT_MAC_ADDR_NIC               = 3,

    /**
     * [RW] Sets various flags for a port.  Refer to \ref exanic_port_flags_t.
     */
    REG_PORT_FLAGS                      = 4,

    /**
     * [RW] Base address of the RX DMA region (upper 32 bits).
     *
     * \warning This register must be set to 0 if a 32 bit address is in use.
     */
    REG_PORT_RX_DMA_BASE_ADDR_HI        = 5,

    /**
     * [RW] Base address of the RX DMA region (lower 32 bits).
     * Bit 0 is set to 1 for a 32 bit address and 0 for a 64 bit address
     * (see \ref exanic_dma_addr_cfg_t).
     *
     * \warning The region must be page aligned.
     */
    REG_PORT_RX_DMA_BASE_ADDR_LO        = 6,

    /**
     * [RO] TX engine supported types (a bitmask of \ref exanic_tx_type_id_t).
     * Availability: NIC only
     */
    REG_PORT_TX_SUPPORTED_TYPES         = 7,

    /**
     * [RW] TX command FIFO register.  To send a packet, write the offset
     * (from the beginning of the TX region) of the control word for the packet.
     * Availability: NIC only
     */
    REG_PORT_TX_COMMAND                 = 8,

    /**
     * [RO] The useable subset of the TX region for this engine begins at this
     * offset.
     * Availability: NIC only
     */
    REG_PORT_TX_REGION_OFFSET           = 9,

    /**
     * [RO] The useable subset of the TX region for this engine is of this size
     * (in bytes).
     * Availability: NIC only
     */
    REG_PORT_TX_REGION_SIZE             = 10,

    /**
     * [RO] Time of the last sent packet.  The time is recorded when the first byte
     * in the packet is sent on the wire.
     * Availability: NIC only
     */
    REG_PORT_TX_LAST_TIME               = 11,

    /**
     * [RW] The first 3 octets (OUI) of the MAC address.
     * 0x563412 in this register results in the OUI 12:34:56.
     * Availability: NIC only
     */
    REG_PORT_MAC_ADDR_OUI               = 12,

    /**
     * [RW] Interrupt configuration register for port.
     * [31]    Set to 1 to enable interrupts on port.
     * [21:14] Set to chunk ID to interrupt on.
     * [13:0]  Set to generation ID to interrupt on.
     */
    REG_PORT_IRQ_CONFIG                 = 13,

    /**
     * [RW] Flow hashing configuration register for port.
     * [31]   Enable flow hashing
     * [11:8] Hash function to use (\ref rx_hash_function).
     * [7:0]  Hash mask
     */
    REG_PORT_HASH_CONFIG                = 14,

    REG_PORT_RESERVED1                  = 15,
};
#define REG_PORT_OFFSET(port, reg) \
    (REG_PORT_BASE + (0x10 * (port) + (reg)) * sizeof(uint32_t))
#define REG_PORT_INDEX(port, reg) \
    (REG_PORT_OFFSET(port, reg) / sizeof(uint32_t))

/**
 * \brief 0x0800-0x0FFF: Extended port-specific registers
 *
 * Additional registers that allow configuration of a specific ExaNIC port.
 */
enum
{
    REG_EXTENDED_PORT_BASE                          = 0x0800,

    /**
     * [RO] The maximum number of IP flow steering rules that can be assigned
     * for this port.
     * Availability: X4, X2
     */
    REG_EXTENDED_PORT_NUM_IP_FILTER_RULES           = 0,

    /**
     * [RO] The maximum number of MAC flow steering rules that can be assigned
     * for this port.
     * Availability: X4, X2
     */
    REG_EXTENDED_PORT_NUM_MAC_FILTER_RULES          = 1,

    /**
     * [RO] The number of hash functions available in flow hashing mode for
     * this port.
     * Availability: X4, X2
     */
    REG_EXTENDED_PORT_NUM_HASH_FUNCTIONS            = 2,
};

#define REG_EXTENDED_PORT_OFFSET(port, reg) \
    (REG_EXTENDED_PORT_BASE + (0x40 * (port) + (reg)) * sizeof(uint32_t))
#define REG_EXTENDED_PORT_INDEX(port, reg) \
    (REG_EXTENDED_PORT_OFFSET(port, reg) / sizeof(uint32_t))


/**
 * \brief 0x1000-0x10FF: PTP grandmaster registers
 *
 * These registers provide information about the PTP grandmaster, and allows
 * configuration of the PTP grandmaster functionality.
 *
 * Availability: PTP grandmaster only
 */
enum
{
    REG_PTP_BASE                        = 0x1000,

    /**
     * [RW] IP address of the PTP grandmaster.
     */
    REG_PTP_IP_ADDR                     = 0,

    /**
     * [RW] PTP grandmaster configuration register 0.
     */
    REG_PTP_CONF0                       = 1,

    /**
     * [RW] PTP grandmaster configuration register 1.
     */
    REG_PTP_CONF1                       = 2,

    /**
     * [RW] PTP grandmaster configuration register 2.
     */
    REG_PTP_CONF2                       = 3,

    /**
     * [RO] GPS status register.
     */
    REG_PTP_GPS_STATUS                  = 4,

    REG_PTP_NUM_CLIENTS                 = 5,

    /**
     * [RO] Current TAI-UTC offset in seconds.
     */
    REG_PTP_TAI_OFFSET                  = 6,

    REG_PTP_FRAMES_TX                   = 8,

    REG_PTP_FRAMES_RX                   = 9,

    /**
     * [RW] PTP clock quality when clock is synchronized by the host.
     * (clockQuality struct in IEEE 1588-2008)
     * When set to 0xFFFFFFFF the PTP grandmaster is disabled.
     * This register is ignored if the time is synced using GPS.
     */
    REG_PTP_CLOCK_QUALITY               = 10,

    /**
     * [RW] PTP time source when clock is synchronized by the host.
     * (timeSource enumeration in IEEE 1588-2008)
     * This register is ignored if the time is synced using GPS.
     */
    REG_PTP_TIME_SOURCE                 = 11,

    /**
    *  [RO] Number of internal clock resync events
    */
    REG_PTP_RESYNC_COUNT                = 12,

    /**
    *  [RO] Number of times the clock has gone into holdover mode.
    */
    REG_PTP_HOLDOVER_COUNT              = 13,

    /**
    *  [RO] Number of announce messages sent.
    */
    REG_PTP_ANNOUNCE_COUNT              = 14,

    /**
    *  [RO] Number of delay req messages sent.
    */
    REG_PTP_DELAY_REQ_COUNT             = 15,

    /**
    *  [RO] Last measured phase error in 4ns steps (quad ns, QNS)
    */
    REG_PTP_PHASE_ERROR                 = 16,

    /**
    *  [RO] Last measured rate error in QNS per second
    */
    REG_PTP_RATE_ERROR                  = 17,

    /**
    *  [RO] Estimated clock accuracy in ns
    */
    REG_PTP_CLOCK_ACCURACY              = 18,

    /**
    *  [RO] Holdover duration, in seconds
    *  Time since the clock was last sync'd to GPS
    */
    REG_PTP_HOLDOVER_DURATION           = 19,

    /**
    *  [RO] PTP port state
    */
    REG_PTP_PORT_STATE                  = 20,
};

#define REG_PTP_OFFSET(reg) (REG_PTP_BASE + (reg) * sizeof(uint32_t))
#define REG_PTP_INDEX(reg) (REG_PTP_OFFSET(reg) / sizeof(uint32_t))

/**
 * \brief 0x0300-0x03FF: Firewall registers
 *
 * These registers provide information about the firewall, and allows
 * configuration of the firewall functionality.
 *
 * Availability: Firewall only
 */
enum
{
    REG_FIREWALL_BASE                   = 0x0300,

    /**
     * [RO] The number of filters available.
     */
    REG_FIREWALL_NUM_FILTERS            = 0,

    /**
     * [RW] Configures the firewall state.  Packets are passed only when the
     * firewall is enabled or in transparent mode.
     * (see \ref exanic_firewall_state_t)
     */
    REG_FIREWALL_STATE                  = 1,

    /**
     * [R] Reads 1 if the physical hardware is capable of acting as a firewall.
     */
    REG_FIREWALL_CAPABLE                = 2,

    /**
     * [RW] Filter configuration.  Register REG_FIREWALL_FILTER_CONTROL + n
     * contains the control bytes of filters 4n to 4n+3, with the least
     * significant byte controlling filter 4n, and so on.
     * (see \ref exanic_filter_control_t)
     */
    REG_FIREWALL_FILTER_CONTROL         = 32,
};
#define REG_FIREWALL_OFFSET(reg) (REG_FIREWALL_BASE + (reg) * sizeof(uint32_t))
#define REG_FIREWALL_INDEX(reg) (REG_FIREWALL_OFFSET(reg) / sizeof(uint32_t))

/**
 * \brief 0x0400-0x04FF: Port-specific statistics
 *
 * These registers provide statistics for each port.
 */
enum
{
    REG_PORT_STAT_BASE                  = 0x0400,

    /**
     * [WO] Reset counters.
     */
    REG_PORT_STAT_RESET                 = 0,

    /**
     * [RO] Number of frames sent.
     */
    REG_PORT_STAT_TX                    = 1,

    /**
     * [RO] Number of valid frames received and delivered.
     */
    REG_PORT_STAT_RX                    = 2,

    /**
     * [RO] Number of valid frames received but not delivered.
     */
    REG_PORT_STAT_RX_IGNORED            = 3,

    /**
     * [RO] Number of erroneous frames received.
     */
    REG_PORT_STAT_RX_ERROR              = 4,

    /**
     * [RO] Number of frames dropped in hardware.
     */
    REG_PORT_STAT_RX_DROPPED            = 5,
};
#define REG_PORT_STAT_OFFSET(port, reg) \
    (REG_PORT_STAT_BASE + (0x10 * (port) + (reg)) * sizeof(uint32_t))
#define REG_PORT_STAT_INDEX(port, reg) \
    (REG_PORT_STAT_OFFSET(port, reg) / sizeof(uint32_t))


/**
 * \brief Packet filters
 *
 * This region consists of IP packet filtering registers.
 *
 * Each ExaNIC port can deliver a packet to one of many memory buffers on the
 * host system. The choice of buffer is dependent on whether the port is
 * configured in flow hashing mode.
 *
 * # Flow Hashing
 *
 * When a port is configured in flow hashing mode, the IP and TCP/UDP headers
 * are used to calculate a hash value, with the intention being to evenly
 * distribute frames across buffers, whilst ensuring that individual connections
 * are always transferred to the same buffer. To enable this mode, the user
 * should first allocate a power of two number of RX regions and write the
 * physical address of each to the registers at REG_BUFFER_BASEADDR. The user
 * can determine the number of buffers supported by the ExaNIC by reading
 * REG_EXANIC_NUM_FILTER_BUFFERS in the port register space.
 *
 * The user can then enable hashing by writing to the REG_PORT_HASH_CONFIG
 * register. The hash mask should be set to 2^N - 1, where N is the number of
 * buffers that were allocated. The hash function should be selected based on
 * end application requirements.
 *
 * Only TCP and UDP frames will be redirected by flow hashing, all other frames
 * will be delivered to the buffer at the base address specified by
 * REG_PORT_BASE.
 *
 * # Flow Steering
 *
 * The ExaNIC also supports rule-based IP and MAC/VLAN packet steering. This
 * functionality is available on any port that has flow hashing disabled. The
 * user can determine the number of rules available per port by reading from
 * REG_EXTENDED_PORT_NUM_IP_FILTER_RULES and REG_EXTENDED_PORT_NUM_MAC_FILTER_RULES.
 *
 * The user defines a rule, and creates a mapping from the rule to a buffer.
 * Frames that match the rule are then delivered to that buffer. All frames
 * not matching any rule are delivered to the REG_PORT_BASE buffer.
 *
 * ## Defining a rule
 *
 * Rules are defined in the memory region starting at REG_FILTER_RULES. Rules
 * are matched over the 13 bytes defined by:
 *
 *    byte         12                                       0
 *          {protocol, src_addr, dst_addr, src_port, dst_port}
 *
 * Or the 10 bytes defined over:
 *
 *   byte                9                   0
 *          {is_vlan, vlan, ethertype, dst_mac}
 *
 * Rules programmed by writing to memory locations that are indexed by each of
 * the 13 bytes, and is best illustrated using an example. First, we form a mask
 * equivalent to:
 *
 *          rule_mask = 1 << (rule_number % 32)
 *
 * Then we write this mask to an address offset from REG_FILTER_MAC_RULES or
 * REG_FILTER_IP_RULES:
 *
 *           address_offset = ((byte_number << 11)  |
 *                             (byte_value  << 3)  |
 *                              rule_number / 32) *
 *                            sizeof(uint32_t);
 *
 * Where multiple rules share the same address offset, the mask written is simply
 * the bitwise OR of the individual masks. Creating a wildcard entry (for
 * example, all source IPs) is a matter of writing a rule mask to all
 * byte_value's in a given field. In hardware, rules are organised into regions,
 * where each region implements EXANIC_NUM_FILTERS_PER_REGION rules.
 *
 * When a frame matches a filter, the hardware will tag the frame with the
 * filter region and the filter number within that region. See \ref rx_chunk_info
 * for details.
 *
 * ## Mapping a rule to a buffer
 *
 * Each rule must map to valid buffer. To create a link between a rule and a
 * buffer, write the buffer number to the address REG_RULE_TO_BUFFER +
 * RULE_NUMBER * sizeof(uint32_t).
 *
 * Configure the base address of the individual buffers as described in the flow
 * hashing section.
 *
 */
enum
{
    REG_FILTERS_BASE = 0x400000,

    /**
     * [WO] Contains the buffer to base address lookup table
     * used by the hardware.
     * [N*8+0x00]: Base_Address[63:32] for buffer N
     * [N*8+0x04]: Base_Address[31:00] for buffer N
     */
    REG_BUFFER_BASEADDR                = 0x00000,

    /**
     * [WO] Contains the lookup used to match rules to buffers.
     * [M*4]: Buffer for rule M.
     */
    REG_RULE_TO_BUFFER                 = 0x20000,

    /**
     * [WO] MAC rule definitions.
     */
    REG_FILTER_MAC_RULES               = 0x40000,

    /**
     * [WO] IP rule definitions.
     */
    REG_FILTER_IP_RULES                = 0x60000,

};
#define REG_FILTERS_OFFSET(port, reg) \
    (REG_FILTERS_BASE + (0x100000 * (port) + (reg)) )

/**
 * \brief Each filter region consists of EXANIC_NUM_FILTERS_PER_REGION
 * filters.
 */
enum
{
    /** MAC Filter region */
    EXANIC_FILTER_REGION_MAC           = 0,

    /** 5 Tuple IP Filter region. */
    EXANIC_FILTER_REGION_IP            = 1,
};

/**
 * \brief Firewall Packet filters
 *
 * Firewall filters are only available on ExaNIC cards with firewall support.
 *
 * A firewall filter consists of two components: a mask and a pattern.
 *
 * A firewall filter is considered to be matched iff the result of applying
 * the mask to the first \ref EXANIC_FILTER_NUM_DWORDS DWORDs of the frame
 * yields the pattern.
 *
 * The pattern and mask are written to the registers in a byte interleaved
 * format, starting with byte 0 of the mask in the LSB of register 0:
 *
 * idx  31                  0
 * 0    | P1 | M1 | P0 | M0 |
 * 1    | P3 | M3 | P2 | M2 |
 * 2    ...
 *
 * Each filter is allocated its own 128-byte chunk of memory even though it
 * will only use the first 80 bytes of each chunk.  The remaining bytes may
 * be used for future expansion.
 *
 * Example:
 *  \code
 *  uint8_t mask[4 * EXANIC_FILTER_NUM_DWORDS]
 *  uint8_t pattern[4 * EXANIC_FILTER_NUM_DWORDS];
 *  int idx;
 *
 *  volatile uint32_t *filter_data = &exanic->registers[FILTER_INDEX(idx)];
 *
 *  for (int i = 0; i < 2 * EXANIC_FILTER_NUM_DWORDS; i++)
 *  {
 *      filter_data[i] = mask[2 * i] | (pattern[2 * i] << 8) |
 *          (mask[2 * i + 1] << 16) | (pattern[2 * i + 1] << 24);
 *  }
 *  \endcode
 */
enum
{
    FIREWALL_FILTER_BASE                         = 0x0000,
};
#define FIREWALL_FILTER_OFFSET(filter) (FIREWALL_FILTER_BASE + (128 * (filter)))
#define FIREWALL_FILTER_INDEX(filter) (FIREWALL_FILTER_OFFSET(filter) / sizeof(uint32_t))

/**
 * \brief Hardware IDs
 */
typedef enum
{
    EXANIC_HW_Z1            = 0, /**< Z1 */
    EXANIC_HW_Z10           = 1, /**< Z10 */
    EXANIC_HW_X4            = 2, /**< ExaNIC X4 */
    EXANIC_HW_X2            = 3, /**< ExaNIC X2 */
    EXANIC_HW_X10           = 4, /**< ExaNIC X10 */
    EXANIC_HW_X10_GM        = 5, /**< ExaNIC X10-GM */
    EXANIC_HW_X40           = 6, /**< ExaNIC X40 */
    EXANIC_HW_X10_HPT       = 7, /**< ExaNIC X10-HPT */
} exanic_hardware_id_t;

/**
 * \brief Returns a string representation of a hardware ID
 *
 * \param[in]   id
 *      The ExaNIC hardware ID returned from reading \ref REG_EXANIC_HW_ID.
 *
 * \return A string describing the ExaNIC hardware, or NULL if the hardware ID
 * is unknown.
 */
static inline const char * exanic_hardware_id_str(exanic_hardware_id_t id)
{
    switch (id)
    {
        case EXANIC_HW_Z1:
            return "Z1";
        case EXANIC_HW_Z10:
            return "Z10";
        case EXANIC_HW_X4:
            return "ExaNIC X4";
        case EXANIC_HW_X2:
            return "ExaNIC X2";
        case EXANIC_HW_X10:
            return "ExaNIC X10";
        case EXANIC_HW_X10_GM:
            return "ExaNIC X10-GM";
        case EXANIC_HW_X40:
            return "ExaNIC X40";
        case EXANIC_HW_X10_HPT:
            return "ExaNIC X10-HPT";
        default:
            return NULL;
    }
}

/**
 * \brief Function IDs
 */
typedef enum
{
    EXANIC_FUNCTION_NIC         = 0,
    EXANIC_FUNCTION_FIREWALL    = 1,
    EXANIC_FUNCTION_FORWARDER   = 2,
    EXANIC_FUNCTION_DEVKIT      = 3,
    EXANIC_FUNCTION_PTP_GM      = 4,
    EXANIC_FUNCTION_RECOVERY    = 0x80000000,
} exanic_function_id_t;

/**
 * \brief Returns a string representation of the ExaNIC function id
 *
 * \param[in]   type
 *      The ExaNIC function id returned from reading \ref REG_EXANIC_FUNCTION_ID.
 *
 * \return A string describing the function id, or NULL if unknown
 */
static inline const char * exanic_function_id_str(exanic_function_id_t type)
{
    switch (type)
    {
        case EXANIC_FUNCTION_NIC:
            return "network interface";
        case EXANIC_FUNCTION_FIREWALL:
            return "firewall";
        case EXANIC_FUNCTION_FORWARDER:
            return "forwarding device";
        case EXANIC_FUNCTION_DEVKIT:
            return "customer application";
        case EXANIC_FUNCTION_PTP_GM:
            return "PTP grandmaster";
        case EXANIC_FUNCTION_RECOVERY:
            return "recovery image";
        default:
            return NULL;
    }
}

/**
 * \brief TX engine supported payload types
 */
typedef enum
{
    /** Expects a full ethernet frame (without FCS). */
    EXANIC_TX_TYPE_RAW   = 0x01,
} exanic_tx_type_id_t;

/**
 * \brief Returns a string representation of the TX engine supported payload
 * types.
 *
 * \param[in]   type_id
 *      The type ID returned from reading REG_PORT_TX_SUPPORTED_TYPES
 *
 * \return A string representation of the supported type, or NULL if the type
 * is unknown.
 */
static inline const char * exanic_tx_type_id_str(exanic_tx_type_id_t type_id)
{
    switch (type_id)
    {
        case EXANIC_TX_TYPE_RAW:
            return "raw";
        default:
            return NULL;
    }
}

/**
 * \brief Capability flags to indicate availability of various features
 */
typedef enum
{
    EXANIC_CAP_RX_MSI           = 0x00000001, /**< MSI interrupt on RX */
    EXANIC_CAP_STEER_TWO        = 0x00000002, /**< Two-tuple flow steering */

    EXANIC_CAP_HW_TIME_HI       = 0x00000100, /**< 64 bit time counter */
    EXANIC_CAP_CLK_ADJ_EXT      = 0x00000200, /**< Extended clock correction */

    /** Bits which indicate that some kind of RX interrupt is available */
    EXANIC_CAP_RX_IRQ           = EXANIC_CAP_RX_MSI,

    EXANIC_CAP_BRIDGING         = 0x00010000, /**< bridging supported */

    EXANIC_CAP_100M             = 0x01000000, /**< 100M supported */
    EXANIC_CAP_1G               = 0x02000000, /**< 1G supported */
    EXANIC_CAP_10G              = 0x04000000, /**< 10G supported */
    EXANIC_CAP_40G              = 0x08000000, /**< 40G supported */
    EXANIC_CAP_100G             = 0x10000000, /**< 100G supported */
} exanic_caps_t;

/**
 * \brief Clock correction control bits
 */
typedef enum
{
    EXANIC_CLK_ADJ_INC          = 0x01000000, /**< Add a tick every n ticks */
    EXANIC_CLK_ADJ_DEC          = 0x00000000, /**< Skip a tick every n ticks */
    EXANIC_CLK_ADJ_MASK         = 0x00FFFFFF,
} exanic_clk_adj_t;

/**
 * \brief PPS connector signals
 */
typedef enum
{
    EXANIC_HW_SERIAL_PPS_SINGLE  = 0x00000020, /**< Set for single-ended mode */
    EXANIC_HW_SERIAL_PPS_TERM_EN = 0x00000040, /**< Set to enable 50ohm term */
    EXANIC_HW_SERIAL_PPS_OUT_EN  = 0x00000080, /**< Set to enable PPS out */
    EXANIC_HW_SERIAL_PPS_OUT_VAL = 0x00000100, /**< PPS output value */
    EXANIC_HW_SERIAL_PPS_EDGE_SEL = 0x00000200, /**< Set to latch rising edge */
} exanic_hw_serial_t;

/**
 * \brief PPS output configuration
 */
typedef enum
{
    EXANIC_HW_PER_OUT_CONFIG_PPS = 0x00000001, /**< Set for 1PPS output */
    EXANIC_HW_PER_OUT_CONFIG_10M = 0x00000002, /**< Set for 10MHz output */
} exanic_hw_per_out_config_t;

/**
 * \brief Firewall filter control byte bitfield
 */
typedef enum
{
    EXANIC_FILTER_ENABLE        = 0x01, /**< Enable the filter */
    EXANIC_FILTER_ALLOW         = 0x02, /**< Allow rule (1) or drop rule (0) */
} exanic_filter_control_t;

/**
 * \brief A bitfield containing status information for ExaNIC ports and
 * information on available functionality.
 */
typedef enum
{
    EXANIC_PORT_STATUS_ENABLED  = 0x01, /**< Port is enabled */
    EXANIC_PORT_STATUS_SFP      = 0x02, /**< An SFP is detected in the port */
    EXANIC_PORT_STATUS_SIGNAL   = 0x04, /**< A signal is detected by the SFP */
    EXANIC_PORT_STATUS_LINK     = 0x08, /**< The link is active */
    EXANIC_PORT_STATUS_AUTONEG_DONE = 0x10, /**< Auto-negotiation is complete */
    EXANIC_PORT_STATUS_RX_TIME_BAD = 0x20, /**< RX timestamping is not ready */
    EXANIC_PORT_STATUS_TX_TIME_BAD = 0x40, /**< TX timestamping is not ready */
    EXANIC_PORT_RX_UNSUPPORTED  = 0x01000000, /**< RX is not available */
    EXANIC_PORT_TX_UNSUPPORTED  = 0x02000000, /**< TX is not available */
    EXANIC_PORT_NOT_IMPLEMENTED = 0x80000000, /**< Port is not implemented */
} exanic_port_status_t;

/**
 * \brief A bitfield for bridging and mirroring configuration
 */
typedef enum
{
    EXANIC_FEATURE_MIRROR_RX_0  = 0x01, /**< Mirror port 0 RX */
    EXANIC_FEATURE_MIRROR_TX_0  = 0x02, /**< Mirror port 0 TX */
    EXANIC_FEATURE_MIRROR_RX_1  = 0x04, /**< Mirror port 1 RX */
    EXANIC_FEATURE_MIRROR_TX_1  = 0x08, /**< Mirror port 1 TX */
    EXANIC_FEATURE_MIRROR_RX_2  = 0x10, /**< Mirror port 2 RX */
    EXANIC_FEATURE_MIRROR_TX_2  = 0x20, /**< Mirror port 2 TX */
    EXANIC_FEATURE_BRIDGE       = 0x40, /**< Bridge ports 0 and 1 */

    /** Bit mask for all bridging and mirroring settings */
    EXANIC_FEATURE_BRIDGE_MIRROR_MASK = 0x7F,

    /** Auxiliary bridging and mirroring settings */
    EXANIC_FEATURE_AUX_MASK     = 0x7F00,
    /** Shift to move auxiliary settings to real config bits */
    EXANIC_FEATURE_AUX_SHIFT    = 8,
    /** Disconnects auxiliary bridging and mirroring when set to 0 */
    EXANIC_FEATURE_AUX_ENABLE   = 0x10000,

    /** Wait until this bit is unset before initialising the card. */
    EXANIC_STATUS_HW_STARTUP    = 0x20000,
} exanic_feature_cfg_t;

/**
 * \brief Returns a string representation of a feature bit
 *
 * \param[in]   bit
 *
 * \return A string representation of the feature, or NULL if invalid.
 */
static inline const char * exanic_feature_str(exanic_feature_cfg_t bit)
{
    switch (bit)
    {
        case EXANIC_FEATURE_MIRROR_RX_0:
            return "Port 0 RX mirroring";
        case EXANIC_FEATURE_MIRROR_TX_0:
            return "Port 0 TX mirroring";
        case EXANIC_FEATURE_MIRROR_RX_1:
            return "Port 1 RX mirroring";
        case EXANIC_FEATURE_MIRROR_TX_1:
            return "Port 1 TX mirroring";
        case EXANIC_FEATURE_MIRROR_RX_2:
            return "Port 2 RX mirroring";
        case EXANIC_FEATURE_MIRROR_TX_2:
            return "Port 2 TX mirroring";
        case EXANIC_FEATURE_BRIDGE:
            return "Port 0 and 1 bridging";
        default:
            return NULL;
    }
}

/**
 * \brief REG_PORT_FLAGS configuration bits
 */
typedef enum
{
    /**
     * If enabled, then no matching will be attempted and all RX frames
     * will be delivered to the host
     */
    EXANIC_PORT_FLAG_PROMISCUOUS        = 0x01,

    /**
     * For Forwarding device ports 0-2 only.
     * If enabled, every incoming packet updates the MAC for that port
     */
    EXANIC_PORT_FLAG_MAC_LEARNING_MODE  = 0x02,

    /**
     * Auto-neg config codes are sent momentarily when this bit goes from 0-1
     * Availability: Z1 NIC only
     */
    EXANIC_PORT_FLAG_AUTONEG_TX         = 0x04,

    /**
     * Enable auto-negotiation
     * Availability: X4, X2
     */
    EXANIC_PORT_FLAG_AUTONEG_ENABLE     = 0x08,

    /**
     * If enabled, then local loopback will be enabled from
     * Tx to RX of that port
     */
    EXANIC_PORT_FLAG_LOOPBACK           = 0x10,
} exanic_port_flags_t;

/**
 * \brief DMA address width configuration bits
 */
typedef enum
{
    EXANIC_DMA_ADDR_CFG_64_BIT  = 0x00, /**< 64 bit addressing */
    EXANIC_DMA_ADDR_CFG_32_BIT  = 0x01, /**< 32 bit addressing */
} exanic_dma_addr_cfg_t;

/**
 * \brief Firewall state values
 */
typedef enum
{
    EXANIC_FIREWALL_DISABLE     = 0, /**< No packets are passed */
    EXANIC_FIREWALL_ENABLE      = 1, /**< Packets are filtered */
    EXANIC_FIREWALL_TRANSPARENT = 2, /**< All packets are passed */
} exanic_firewall_state_t;

/**
 * \brief The ExaNIC mmap-able regions
 *
 * The ExaNIC memory regions are mapped to the user according to the following
 * configuration:
 *
 *            Page Offset 0  +---------------------+
 *                           |      Registers      |
 *                        3  +---------------------+
 *                           |        Info         |
 *                        4  +---------------------+
 *                           |       Filters       |
 *                        8  +---------------------+
 *                           |      TX region      |
 *                       256 +---------------------+
 *                           |     TX feedback     |
 *                       512 +---------------------+
 *                           |  RX region (port0)  |
 *                      1024 +---------------------+
 *                           |  RX region (port1)  |
 *                      1536 +---------------------+
 *                           |  RX region (port2)  |
 *                      2048 +---------------------+
 *                           |  RX region (port3)  |
 *                      2560 +---------------------+
 *                           |    Filter region    |
 *                    262144 +---------------------+
 *                           | Devkit user region  |
 *                    524288 +---------------------+
 *                           | Extended TX region  |
 *                    557056 +---------------------+
 *                           | Extended RX region  |
 *                           +---------------------+
 *
 */
enum
{
    EXANIC_PGOFF_REGISTERS      = 0,
    EXANIC_PGOFF_INFO           = 3,
    EXANIC_PGOFF_FILTERS        = 4,
    EXANIC_PGOFF_TX_REGION      = 8,
    EXANIC_PGOFF_TX_FEEDBACK    = 256,
    EXANIC_PGOFF_RX_REGION      = 512,
    EXANIC_PGOFF_FILTER_REGION  = 2560,
    EXANIC_PGOFF_DEVKIT_REGS    = 262144,
    EXANIC_PGOFF_DEVKIT_MEM     = 262148,
    EXANIC_PGOFF_TX_REGION_EXT  = 524288UL,
    EXANIC_PGOFF_RX_REGION_EXT  = 557056UL,
};

/**
 * \brief Z1 GPIO lines
 */
enum
{
    Z1_GPIO_DRV_SDA0        = 0,
    Z1_GPIO_DRV_SCL0        = 4,
    Z1_GPIO_SDA0            = 8,
};

/**
 * \brief ExaNIC I2C lines
 */
enum
{
    EXANIC_GPIO_DRV_SDA0    = 0,
    EXANIC_GPIO_DRV_SCL0    = 7,
    EXANIC_GPIO_SDA0        = 8,
    EXANIC_GPIO_MOD0NSEL    = 16,
};

/**
 * \brief REG_HW_POWERDOWN bits
 */
enum
{
    EXANIC_PHY_POWERDOWN0   = 0,
    EXANIC_SFP_TXDIS0       = 4
};

/**
 * \brief REG_PORT_IRQ_CONFIG bits.
 */
enum
{
    EXANIC_PORT_IRQ_ENABLE      = 0x80000000,
};


/**
 * \brief EXANIC_PORT_HASH_CONFIG bits
 */
enum
{
    EXANIC_PORT_HASH_ENABLE         = 0x80000000,
    EXANIC_PORT_HASH_MASK_MASK      = 0xFF,
    EXANIC_PORT_HASH_MASK_SHIFT     = 0,
    EXANIC_PORT_HASH_FUNCTION_MASK  = 0xF00,
    EXANIC_PORT_HASH_FUNCTION_SHIFT = 8,
};

/**
 * \brief Hash function identifiers.
 *
 */
enum rx_hash_function
{
    /* Symmetric hash over source port, destination port */
    EXANIC_RX_HASH_FUNCTION_PORT = 0,

    /* Symmetric hash over source ip, destination ip */
    EXANIC_RX_HASH_FUNCTION_IP = 1,

    /* Symmetric hash over source ip & port, destination ip & port */
    EXANIC_RX_HASH_FUNCTION_PORT_IP = 2,

};

/**
 * \brief VLAN tag match methods for MAC filters.
 */
enum vlan_match_method
{
    /** Match on all frames, whether VLAN or not. */
    EXANIC_VLAN_MATCH_METHOD_ALL        = 0,

    /** Only match on the VLAN given. */
    EXANIC_VLAN_MATCH_METHOD_SPECIFIC   = 1,

    /** Only match if frame does not have a vlan tag. */
    EXANIC_VLAN_MATCH_METHOD_NOT_VLAN   = 2,

    /** Match frames that have a VLAN tag, but not those that don't. */
    EXANIC_VLAN_MATCH_METHOD_ALL_VLAN   = 3,
};

/**
 * \brief PTP configuration register bits.
 */
enum
{
    EXANIC_PTP_CONF0_PTP_ENABLE                 = 0x00000001,
    EXANIC_PTP_CONF0_ETH_MULTICAST              = 0x00000002,
    EXANIC_PTP_CONF0_IP_MULTICAST               = 0x00000004,
    EXANIC_PTP_CONF0_IP_UNICAST                 = 0x00000008,
    EXANIC_PTP_CONF0_GPS_CLOCK_SYNC             = 0x00000010,

    EXANIC_PTP_CONF0_DOMAIN_MASK                = 0x0000FF00,
    EXANIC_PTP_CONF0_DOMAIN_SHIFT               = 8,

    EXANIC_PTP_CONF0_PRIORITY1_MASK             = 0x00FF0000,
    EXANIC_PTP_CONF0_PRIORITY1_SHIFT            = 16,

    EXANIC_PTP_CONF0_PRIORITY2_MASK             = 0xFF000000,
    EXANIC_PTP_CONF0_PRIORITY2_SHIFT            = 24,

    EXANIC_PTP_CONF1_ANNOUNCE_INTERVAL_MASK     = 0x000000FF,
    EXANIC_PTP_CONF1_ANNOUNCE_INTERVAL_SHIFT    = 0,

    EXANIC_PTP_CONF1_SYNC_INTERVAL_MASK         = 0x0000FF00,
    EXANIC_PTP_CONF1_SYNC_INTERVAL_SHIFT        = 8,

    EXANIC_PTP_CONF1_PTP_PROFILE_MASK           = 0x000F0000,
    EXANIC_PTP_CONF1_PTP_PROFILE_SHIFT          = 16,

    EXANIC_PTP_CONF1_PPS_OUT_EN                 = 0x10000000,
    EXANIC_PTP_CONF1_PPS_OUT_VAL                = 0x20000000,
    EXANIC_PTP_CONF1_PPS_OUT_PPS                = 0x40000000,
    EXANIC_PTP_CONF1_PPS_OUT_10M                = 0x80000000,

    EXANIC_PTP_CONF2_ANNOUNCE_RECEIPT_TIMEOUT_MASK  = 0x000000FF,
    EXANIC_PTP_CONF2_ANNOUNCE_RECEIPT_TIMEOUT_SHIFT = 0,
    EXANIC_PTP_CONF2_ANTENNA_CABLE_DELAY_MASK   = 0xFFFF0000,
    EXANIC_PTP_CONF2_ANTENNA_CABLE_DELAY_SHIFT  = 16,
};

/**
 * \brief PTP Profile options.
 */
enum ptp_profile
{
    /** Factory defaults, minimal range checking. */
    NO_PROFILE        = 0,

    /** Default PTP profile. */
    DEFAULT_PROFILE   = 1,

    /** Default Telecom profile. */
    TELECOM_PROFILE   = 2,
};

/**
 * \brief GPS status information
 */
enum
{
    EXANIC_PTP_GPS_STATUS_FIX_NONE              = 0x00000000,
    EXANIC_PTP_GPS_STATUS_FIX_2D                = 0x00000002,
    EXANIC_PTP_GPS_STATUS_FIX_3D                = 0x00000003,
    EXANIC_PTP_GPS_STATUS_FIX_MASK              = 0x000000FF,

    EXANIC_PTP_GPS_STATUS_NUM_SATS_MASK         = 0x0000FF00,
    EXANIC_PTP_GPS_STATUS_NUM_SATS_SHIFT        = 8,

    EXANIC_PTP_GPS_STATUS_TIME_OK               = 0x00010000,

    EXANIC_PTP_GPS_STATUS_CLOCK_STATE_MASK      = 0xFF000000,
    EXANIC_PTP_GPS_STATUS_CLOCK_STATE_SHIFT     = 24,
};

/**
 * \brief Clock sync state codes
 */
enum
{
    EXANIC_PTP_CLOCK_STATE_UNSYNCED     = 0,
    EXANIC_PTP_CLOCK_STATE_SYNCED       = 1,
    EXANIC_PTP_CLOCK_STATE_WAITING      = 2,
    EXANIC_PTP_CLOCK_STATE_WARMUP       = 3,
    EXANIC_PTP_CLOCK_STATE_HOLDOVER     = 4,
};

/**
 * \brief PTP port state codes (as defined in IEEE 1588)
 */
enum ptp_best_master_state
{
    EXANIC_PTP_PORT_STATE_INITIALIZING = 1,
    EXANIC_PTP_PORT_STATE_FAULTY = 2,
    EXANIC_PTP_PORT_STATE_DISABLED = 3,
    EXANIC_PTP_PORT_STATE_LISTENING = 4,
    EXANIC_PTP_PORT_STATE_PRE_MASTER = 5,
    EXANIC_PTP_PORT_STATE_MASTER = 6,
    EXANIC_PTP_PORT_STATE_PASSIVE = 7,
    EXANIC_PTP_PORT_STATE_UNCALIBRATED = 8,
    EXANIC_PTP_PORT_STATE_SLAVE = 9,
};

#endif /* EXANIC_PCIE_IF_H */
