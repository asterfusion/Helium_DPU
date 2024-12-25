// SPDX-License-Identifier: GPL-2.0+
// Cadence XSPI flash controller driver
// Copyright (C) 2020-21 Cadence

#include <linux/acpi.h>
#include <linux/completion.h>
#include <linux/delay.h>
#include <linux/dmi.h>
#include <linux/err.h>
#include <linux/errno.h>
#include <linux/interrupt.h>
#include <linux/io.h>
#include <linux/iopoll.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/of_device.h>
#include <linux/of.h>
#include <linux/platform_device.h>
#include <linux/pm_runtime.h>
#include <linux/property.h>
#include <linux/spi/spi.h>
#include <linux/spi/spi-mem.h>
#include <linux/bitfield.h>
#include <linux/limits.h>
#include <linux/log2.h>
#include <linux/mtd/spi-nor.h>

#include <soc/marvell/octeontx/octeontx_smc.h>
#include <linux/gpio.h>

#if IS_ENABLED(CONFIG_SPI_CADENCE_HW_WO)
#include <linux/debugfs.h>
struct dentry *mrvl_spi_debug_root;
#endif

#define CDNS_XSPI_MAGIC_NUM_VALUE	0x6522
#define CDNS_XSPI_MAX_BANKS		8
#define CDNS_XSPI_NAME			"cadence-xspi"

/*
 * Note: below are additional auxiliary registers to
 * configure XSPI controller pin-strap settings
 */

/* PHY DQ timing register */
#define CDNS_XSPI_CCP_PHY_DQ_TIMING		0x0000

/* PHY DQS timing register */
#define CDNS_XSPI_CCP_PHY_DQS_TIMING		0x0004

/* PHY gate loopback control register */
#define CDNS_XSPI_CCP_PHY_GATE_LPBCK_CTRL	0x0008

/* PHY DLL slave control register */
#define CDNS_XSPI_CCP_PHY_DLL_SLAVE_CTRL	0x0010

/* DLL PHY control register */
#define CDNS_XSPI_DLL_PHY_CTRL			0x1034

/* Command registers */
#define CDNS_XSPI_CMD_REG_0			0x0000
#define CDNS_XSPI_CMD_REG_1			0x0004
#define CDNS_XSPI_CMD_REG_2			0x0008
#define CDNS_XSPI_CMD_REG_3			0x000C
#define CDNS_XSPI_CMD_REG_4			0x0010
#define CDNS_XSPI_CMD_REG_5			0x0014

/* Command status registers */
#define CDNS_XSPI_CMD_STATUS_REG		0x0044

/* Controller status register */
#define CDNS_XSPI_CTRL_STATUS_REG		0x0100
#define CDNS_XSPI_INIT_COMPLETED		BIT(16)
#define CDNS_XSPI_INIT_LEGACY			BIT(9)
#define CDNS_XSPI_INIT_FAIL			BIT(8)
#define CDNS_XSPI_CTRL_BUSY			BIT(7)

/* Controller interrupt status register */
#define CDNS_XSPI_INTR_STATUS_REG		0x0110
#define CDNS_XSPI_STIG_DONE			BIT(23)
#define CDNS_XSPI_SDMA_ERROR			BIT(22)
#define CDNS_XSPI_SDMA_TRIGGER			BIT(21)
#define CDNS_XSPI_CMD_IGNRD_EN			BIT(20)
#define CDNS_XSPI_DDMA_TERR_EN			BIT(18)
#define CDNS_XSPI_CDMA_TREE_EN			BIT(17)
#define CDNS_XSPI_CTRL_IDLE_EN			BIT(16)

#define CDNS_XSPI_TRD_COMP_INTR_STATUS		0x0120
#define CDNS_XSPI_TRD_ERR_INTR_STATUS		0x0130
#define CDNS_XSPI_TRD_ERR_INTR_EN		0x0134

/* Controller interrupt enable register */
#define CDNS_XSPI_INTR_ENABLE_REG		0x0114
#define CDNS_XSPI_INTR_EN			BIT(31)
#define CDNS_XSPI_STIG_DONE_EN			BIT(23)
#define CDNS_XSPI_SDMA_ERROR_EN			BIT(22)
#define CDNS_XSPI_SDMA_TRIGGER_EN		BIT(21)

#define CDNS_XSPI_INTR_MASK (CDNS_XSPI_INTR_EN | \
	CDNS_XSPI_STIG_DONE_EN  | \
	CDNS_XSPI_SDMA_ERROR_EN | \
	CDNS_XSPI_SDMA_TRIGGER_EN)

/* Controller config register */
#define CDNS_XSPI_CTRL_CONFIG_REG		0x0230
#define CDNS_XSPI_CTRL_WORK_MODE		GENMASK(6, 5)

#define CDNS_XSPI_WORK_MODE_DIRECT		0
#define CDNS_XSPI_WORK_MODE_STIG		1
#define CDNS_XSPI_WORK_MODE_ACMD		3

/* SDMA trigger transaction registers */
#define CDNS_XSPI_SDMA_SIZE_REG			0x0240
#define CDNS_XSPI_SDMA_TRD_INFO_REG		0x0244
#define CDNS_XSPI_SDMA_DIR			BIT(8)

/* Controller features register */
#define CDNS_XSPI_CTRL_FEATURES_REG		0x0F04
#define CDNS_XSPI_NUM_BANKS			GENMASK(25, 24)
#define CDNS_XSPI_DMA_DATA_WIDTH		BIT(21)
#define CDNS_XSPI_NUM_THREADS			GENMASK(3, 0)

/* Controller version register */
#define CDNS_XSPI_CTRL_VERSION_REG		0x0F00
#define CDNS_XSPI_MAGIC_NUM			GENMASK(31, 16)
#define CDNS_XSPI_CTRL_REV			GENMASK(7, 0)

/* STIG Profile 1.0 instruction fields (split into registers) */
#define CDNS_XSPI_CMD_INSTR_TYPE		GENMASK(6, 0)
#define CDNS_XSPI_CMD_P1_R1_ADDR0		GENMASK(31, 24)
#define CDNS_XSPI_CMD_P1_R2_ADDR1		GENMASK(7, 0)
#define CDNS_XSPI_CMD_P1_R2_ADDR2		GENMASK(15, 8)
#define CDNS_XSPI_CMD_P1_R2_ADDR3		GENMASK(23, 16)
#define CDNS_XSPI_CMD_P1_R2_ADDR4		GENMASK(31, 24)
#define CDNS_XSPI_CMD_P1_R3_ADDR5		GENMASK(7, 0)
#define CDNS_XSPI_CMD_P1_R3_CMD			GENMASK(23, 16)
#define CDNS_XSPI_CMD_P1_R3_NUM_ADDR_BYTES	GENMASK(30, 28)
#define CDNS_XSPI_CMD_P1_R4_ADDR_IOS		GENMASK(1, 0)
#define CDNS_XSPI_CMD_P1_R4_CMD_IOS		GENMASK(9, 8)
#define CDNS_XSPI_CMD_P1_R4_BANK		GENMASK(14, 12)

/* STIG data sequence instruction fields (split into registers) */
#define CDNS_XSPI_CMD_DSEQ_R2_DCNT_L		GENMASK(31, 16)
#define CDNS_XSPI_CMD_DSEQ_R3_DCNT_H		GENMASK(15, 0)
#define CDNS_XSPI_CMD_DSEQ_R3_NUM_OF_DUMMY	GENMASK(25, 20)
#define CDNS_XSPI_CMD_DSEQ_R4_BANK		GENMASK(14, 12)
#define CDNS_XSPI_CMD_DSEQ_R4_DATA_IOS		GENMASK(9, 8)
#define CDNS_XSPI_CMD_DSEQ_R4_DIR		BIT(4)

/* STIG command status fields */
#define CDNS_XSPI_CMD_STATUS_COMPLETED		BIT(15)
#define CDNS_XSPI_CMD_STATUS_FAILED		BIT(14)
#define CDNS_XSPI_CMD_STATUS_DQS_ERROR		BIT(3)
#define CDNS_XSPI_CMD_STATUS_CRC_ERROR		BIT(2)
#define CDNS_XSPI_CMD_STATUS_BUS_ERROR		BIT(1)
#define CDNS_XSPI_CMD_STATUS_INV_SEQ_ERROR	BIT(0)

#define CDNS_XSPI_STIG_DONE_FLAG		BIT(0)
#define CDNS_XSPI_TRD_STATUS			0x0104

#define MODE_NO_OF_BYTES			GENMASK(25, 24)
#define MODEBYTES_COUNT			1

/* Helper macros for filling command registers */
#define CDNS_XSPI_CMD_FLD_P1_INSTR_CMD_1(op, data_phase) ( \
	FIELD_PREP(CDNS_XSPI_CMD_INSTR_TYPE, (data_phase) ? \
		CDNS_XSPI_STIG_INSTR_TYPE_1 : CDNS_XSPI_STIG_INSTR_TYPE_0) | \
	FIELD_PREP(CDNS_XSPI_CMD_P1_R1_ADDR0, (op)->addr.val & 0xff))

#define CDNS_XSPI_CMD_FLD_P1_INSTR_CMD_2(op) ( \
	FIELD_PREP(CDNS_XSPI_CMD_P1_R2_ADDR1, ((op)->addr.val >> 8)  & 0xFF) | \
	FIELD_PREP(CDNS_XSPI_CMD_P1_R2_ADDR2, ((op)->addr.val >> 16) & 0xFF) | \
	FIELD_PREP(CDNS_XSPI_CMD_P1_R2_ADDR3, ((op)->addr.val >> 24) & 0xFF) | \
	FIELD_PREP(CDNS_XSPI_CMD_P1_R2_ADDR4, ((op)->addr.val >> 32) & 0xFF))

#define CDNS_XSPI_CMD_FLD_P1_INSTR_CMD_3(op, modebytes) ( \
	FIELD_PREP(CDNS_XSPI_CMD_P1_R3_ADDR5, ((op)->addr.val >> 40) & 0xFF) | \
	FIELD_PREP(CDNS_XSPI_CMD_P1_R3_CMD, (op)->cmd.opcode) | \
	FIELD_PREP(MODE_NO_OF_BYTES, modebytes) | \
	FIELD_PREP(CDNS_XSPI_CMD_P1_R3_NUM_ADDR_BYTES, (op)->addr.nbytes))

#define CDNS_XSPI_CMD_FLD_P1_INSTR_CMD_4(op, chipsel) ( \
	FIELD_PREP(CDNS_XSPI_CMD_P1_R4_ADDR_IOS, ilog2((op)->addr.buswidth)) | \
	FIELD_PREP(CDNS_XSPI_CMD_P1_R4_CMD_IOS, ilog2((op)->cmd.buswidth)) | \
	FIELD_PREP(CDNS_XSPI_CMD_P1_R4_BANK, chipsel))

#define CDNS_XSPI_CMD_FLD_DSEQ_CMD_1(op) \
	FIELD_PREP(CDNS_XSPI_CMD_INSTR_TYPE, CDNS_XSPI_STIG_INSTR_TYPE_DATA_SEQ)

#define CDNS_XSPI_CMD_FLD_DSEQ_CMD_2(op) \
	FIELD_PREP(CDNS_XSPI_CMD_DSEQ_R2_DCNT_L, (op)->data.nbytes & 0xFFFF)

#define CDNS_XSPI_CMD_FLD_DSEQ_CMD_3(op, dummybytes) ( \
	FIELD_PREP(CDNS_XSPI_CMD_DSEQ_R3_DCNT_H, \
		((op)->data.nbytes >> 16) & 0xffff) | \
	FIELD_PREP(CDNS_XSPI_CMD_DSEQ_R3_NUM_OF_DUMMY, \
		  (op)->dummy.buswidth != 0 ? \
		  (((dummybytes) * 8) / (op)->dummy.buswidth) : \
		  0))

#define CDNS_XSPI_CMD_FLD_DSEQ_CMD_4(op, chipsel) ( \
	FIELD_PREP(CDNS_XSPI_CMD_DSEQ_R4_BANK, chipsel) | \
	FIELD_PREP(CDNS_XSPI_CMD_DSEQ_R4_DATA_IOS, \
		ilog2((op)->data.buswidth)) | \
	FIELD_PREP(CDNS_XSPI_CMD_DSEQ_R4_DIR, \
		((op)->data.dir == SPI_MEM_DATA_IN) ? \
		CDNS_XSPI_STIG_CMD_DIR_READ : CDNS_XSPI_STIG_CMD_DIR_WRITE))

#define CDNS_XSPI_POLL_TIMEOUT_US	1000
#define CDNS_XSPI_POLL_DELAY_US	10

#if IS_ENABLED(CONFIG_SPI_CADENCE_MRVL_XSPI)
/* clock config register */
#define CDNS_XSPI_CLK_CTRL_AUX_REG	0x2020
#define CDNS_XSPI_CLK_ENABLE		BIT(0)
#define CDNS_XSPI_CLK_DIV		GENMASK(4, 1)
#define CDNS_XSPI_XFER_SUPPORTED	BIT(7)

/* Clock macros */
#define CDNS_XSPI_CLOCK_IO_HZ 800000000
#define CDNS_XSPI_CLOCK_DIVIDED(div) ((CDNS_XSPI_CLOCK_IO_HZ) / (div))

/*PHY default values*/
#define REGS_DLL_PHY_CTRL		0x00000707
#define CTB_RFILE_PHY_CTRL		0x00004000
#define RFILE_PHY_TSEL			0x00000000
#define RFILE_PHY_DQ_TIMING		0x00000101
#define RFILE_PHY_DQS_TIMING		0x00700404
#define RFILE_PHY_GATE_LPBK_CTRL	0x00200030
#define RFILE_PHY_DLL_MASTER_CTRL	0x00800000
#define RFILE_PHY_DLL_SLAVE_CTRL	0x0000ff01

/*PHY config rtegisters*/
#define CDNS_XSPI_RF_MINICTRL_REGS_DLL_PHY_CTRL		0x1034
#define CDNS_XSPI_PHY_CTB_RFILE_PHY_CTRL			0x0080
#define CDNS_XSPI_PHY_CTB_RFILE_PHY_TSEL			0x0084
#define CDNS_XSPI_PHY_DATASLICE_RFILE_PHY_DQ_TIMING		0x0000
#define CDNS_XSPI_PHY_DATASLICE_RFILE_PHY_DQS_TIMING		0x0004
#define CDNS_XSPI_PHY_DATASLICE_RFILE_PHY_GATE_LPBK_CTRL	0x0008
#define CDNS_XSPI_PHY_DATASLICE_RFILE_PHY_DLL_MASTER_CTRL	0x000c
#define CDNS_XSPI_PHY_DATASLICE_RFILE_PHY_DLL_SLAVE_CTRL	0x0010
#define CDNS_XSPI_DATASLICE_RFILE_PHY_DLL_OBS_REG_0		0x001c

#define CDNS_XSPI_DLL_RST_N BIT(24)
#define CDNS_XSPI_DLL_LOCK  BIT(0)

/* MSI-X clear interrupt register */
#define CDNS_XSPI_SPIX_INTR_AUX				0x2000
#define CDNS_MSIX_CLEAR_IRQ					0x01

#define SPIX_XFER_FUNC_CTRL 0x210
#define SPIX_XFER_FUNC_CTRL_READ_DATA(i) (0x000 + 8 * (i))

#define XFER_SOFT_RESET		BIT(11)
#define XFER_CS_N_HOLD		GENMASK(9, 6)
#define XFER_RECEIVE_ENABLE	BIT(4)
#define XFER_FUNC_ENABLE	BIT(3)
#define XFER_CLK_CAPTURE_POL	BIT(2)
#define XFER_CLK_DRIVE_POL	BIT(1)
#define XFER_FUNC_START		BIT(0)

#define XFER_QWORD_COUNT 32
#define XFER_QWORD_BYTECOUNT 8

#define SPI1_CLK 38
#define SPI1_CS0 40
#define SPI1_CS1 41
#define SPI1_IO0 30
#define SPI1_IO1 31

#define SPI0_CLK 24
#define SPI0_CS0 26
#define SPI0_CS1 27
#define SPI0_IO0 16
#define SPI0_IO1 17

#define GPIO_OFFSET 436

#define CHANGE_GPIO_SMC_ID 0xc2000b14
#define SPI_GPIO(x) (x+GPIO_OFFSET)

#define SPI0_BASE 0x8040
#define SPI1_BASE 0x8050

#define SPI_NOT_CLAIMED				0x00
#define SPI_AP_NS_OWN				0x02
#define CDNS_XSPI_PHY_CTB_RFILE_PHY_GPIO_CTRL_1	0x8c
#define SPI_LOCK_TIMEOUT			100
#define	SPI_LOCK_CHECK_TIMEOUT			10
#define SPI_LOCK_SLEEP_DURATION_MS		10
#endif

enum cdns_xspi_stig_instr_type {
	CDNS_XSPI_STIG_INSTR_TYPE_0,
	CDNS_XSPI_STIG_INSTR_TYPE_1,
	CDNS_XSPI_STIG_INSTR_TYPE_DATA_SEQ = 127,
};

enum cdns_xspi_sdma_dir {
	CDNS_XSPI_SDMA_DIR_READ,
	CDNS_XSPI_SDMA_DIR_WRITE,
};

enum cdns_xspi_stig_cmd_dir {
	CDNS_XSPI_STIG_CMD_DIR_READ,
	CDNS_XSPI_STIG_CMD_DIR_WRITE,
};

enum cdns_xspi_sdma_size {
	CDNS_XSPI_SDMA_SIZE_8B = 0,
	CDNS_XSPI_SDMA_SIZE_64B = 1,
};

struct cdns_xspi_dev {
	struct platform_device *pdev;
	struct device *dev;

	void __iomem *iobase;
	void __iomem *auxbase;
	void __iomem *sdmabase;
	void __iomem *xferbase;

	int irq;
	int cur_cs;
	unsigned int sdmasize;

	struct completion cmd_complete;
	struct completion auto_cmd_complete;
	struct completion sdma_complete;
	bool sdma_error;

	void *in_buffer;
	const void *out_buffer;

	u8 hw_num_banks;

	enum cdns_xspi_sdma_size read_size;

#if IS_ENABLED(CONFIG_SPI_CADENCE_MRVL_XSPI)
	bool xfer_in_progress;
	int current_xfer_qword;
	int write_len;
	int xspi_id;
	bool wo_mode;
	int cs_defined;
#endif
};

#if IS_ENABLED(CONFIG_SPI_CADENCE_MRVL_XSPI)

#define MRVL_DEFAULT_CLK 25000000

const int cdns_xspi_clk_div_list[] = {
	4,	//0x0 = Divide by 4.   SPI clock is 200 MHz.
	6,	//0x1 = Divide by 6.   SPI clock is 133.33 MHz.
	8,	//0x2 = Divide by 8.   SPI clock is 100 MHz.
	10,	//0x3 = Divide by 10.  SPI clock is 80 MHz.
	12,	//0x4 = Divide by 12.  SPI clock is 66.666 MHz.
	16,	//0x5 = Divide by 16.  SPI clock is 50 MHz.
	18,	//0x6 = Divide by 18.  SPI clock is 44.44 MHz.
	20,	//0x7 = Divide by 20.  SPI clock is 40 MHz.
	24,	//0x8 = Divide by 24.  SPI clock is 33.33 MHz.
	32,	//0x9 = Divide by 32.  SPI clock is 25 MHz.
	40,	//0xA = Divide by 40.  SPI clock is 20 MHz.
	50,	//0xB = Divide by 50.  SPI clock is 16 MHz.
	64,	//0xC = Divide by 64.  SPI clock is 12.5 MHz.
	128,	//0xD = Divide by 128. SPI clock is 6.25 MHz.
	-1	//End of list
};
static int unlock_spi_bus(struct cdns_xspi_dev *cdns_xspi)
{
	if (readl(cdns_xspi->auxbase + CDNS_XSPI_PHY_CTB_RFILE_PHY_GPIO_CTRL_1) == SPI_AP_NS_OWN) {
		writel(SPI_NOT_CLAIMED,
		       cdns_xspi->auxbase + CDNS_XSPI_PHY_CTB_RFILE_PHY_GPIO_CTRL_1);
		return 0;
	}
	pr_err("Trying to unlock NOT locked bus: %d!\n",
		readl(cdns_xspi->auxbase + CDNS_XSPI_PHY_CTB_RFILE_PHY_GPIO_CTRL_1));

	return -1;
}

static int lock_spi_bus(struct cdns_xspi_dev *cdns_xspi)
{
	uint32_t val = 0;
	int timeout = SPI_LOCK_TIMEOUT; //10 second timeout

	while (timeout >= 0) {
		val = readl(cdns_xspi->auxbase + CDNS_XSPI_PHY_CTB_RFILE_PHY_GPIO_CTRL_1);
		if (val == SPI_NOT_CLAIMED || val == SPI_AP_NS_OWN) {
			writel(SPI_AP_NS_OWN,
			       cdns_xspi->auxbase + CDNS_XSPI_PHY_CTB_RFILE_PHY_GPIO_CTRL_1);
			break;
		}
		mdelay(SPI_LOCK_SLEEP_DURATION_MS);
		timeout--;
	}

	if (timeout < 0)
		goto fail;

	timeout = SPI_LOCK_CHECK_TIMEOUT;
	while (timeout >= 0) {
		if (readl(cdns_xspi->auxbase + CDNS_XSPI_PHY_CTB_RFILE_PHY_GPIO_CTRL_1) !=
			  SPI_AP_NS_OWN)
			break;
		timeout--;
	}

	if (timeout != -1)
		goto fail;

	return 0;

fail:
	pr_err("Flash arbitration failed, lock is owned by: %d\n",
		readl(cdns_xspi->auxbase + CDNS_XSPI_PHY_CTB_RFILE_PHY_GPIO_CTRL_1));
	return -1;
}

static int gpio_as_sw(struct cdns_xspi_dev *cdns_xspi)
{
	struct arm_smccc_res res;

	arm_smccc_smc(CHANGE_GPIO_SMC_ID, cdns_xspi->xspi_id,
		      0, 0, 0, 0, 0, 0, &res);

	if (res.a0 == 1)
		return 1;

	return 0;
}

static void gpio_as_spi(struct cdns_xspi_dev *cdns_xspi)
{
	struct arm_smccc_res res;

	arm_smccc_smc(CHANGE_GPIO_SMC_ID, cdns_xspi->xspi_id,
		      1, 0, 0, 0, 0, 0, &res);
}

static void set_gpio_mode(struct cdns_xspi_dev *cdns_xspi)
{
	if (cdns_xspi->xspi_id == 1) {
		gpio_direction_output(SPI_GPIO(SPI1_CLK), 1);
		gpio_direction_output(SPI_GPIO(SPI1_CS1), 1);
		gpio_direction_output(SPI_GPIO(SPI1_CS0), 1);
		gpio_direction_output(SPI_GPIO(SPI1_IO0), 1);
		gpio_direction_input(SPI_GPIO(SPI1_IO1));
	} else {
		gpio_direction_output(SPI_GPIO(SPI0_CLK), 1);
		gpio_direction_output(SPI_GPIO(SPI0_CS1), 1);
		gpio_direction_output(SPI_GPIO(SPI0_CS0), 1);
		gpio_direction_output(SPI_GPIO(SPI0_IO0), 1);
		gpio_direction_input(SPI_GPIO(SPI0_IO1));
	}
}

static void spi_gpio_prepare(struct cdns_xspi_dev *cdns_xspi)
{
	int ret = 0;
	char namestr[32];
	int pin;

	gpio_as_sw(cdns_xspi);

	sprintf(namestr, "spi%d_clk", cdns_xspi->xspi_id);
	pin = cdns_xspi->xspi_id == 0 ? (SPI_GPIO(SPI0_CLK)) : (SPI_GPIO(SPI1_CLK));
	ret = gpio_request(pin, namestr);
	gpio_export(pin, false);

	if (cdns_xspi->cs_defined & BIT(0)) {
		sprintf(namestr, "spi%d_cs0", cdns_xspi->xspi_id);
		pin = cdns_xspi->xspi_id == 0 ? (SPI_GPIO(SPI0_CS0)) : (SPI_GPIO(SPI1_CS0));
		ret = gpio_request(pin, namestr);
		gpio_export(pin, false);
	}

	if (cdns_xspi->cs_defined & BIT(1)) {
		sprintf(namestr, "spi%d_cs1", cdns_xspi->xspi_id);
		pin = cdns_xspi->xspi_id == 0 ? (SPI_GPIO(SPI0_CS1)) : (SPI_GPIO(SPI1_CS1));
		ret = gpio_request(pin, namestr);
		gpio_export(pin, false);
	}

	sprintf(namestr, "spi%d_io0", cdns_xspi->xspi_id);
	pin = cdns_xspi->xspi_id == 0 ? (SPI_GPIO(SPI0_IO0)) : (SPI_GPIO(SPI1_IO0));
	ret = gpio_request(pin, namestr);
	gpio_export(pin, false);

	sprintf(namestr, "spi%d_io1", cdns_xspi->xspi_id);
	pin = cdns_xspi->xspi_id == 0 ? (SPI_GPIO(SPI0_IO1)) : (SPI_GPIO(SPI1_IO1));
	ret = gpio_request(pin, namestr);
	gpio_export(pin, false);

	gpio_as_spi(cdns_xspi);
}

static void setsck(struct spi_device *dev, int is_on);
static void setmosi(struct spi_device *dev, int is_on);
static int getmiso(struct spi_device *dev);
static void spidelay(unsigned int d);

static void setsck(struct spi_device *dev, int is_on)
{
	struct cdns_xspi_dev *cdns_xspi = (struct cdns_xspi_dev *)dev;
	int pin = cdns_xspi->xspi_id == 0 ? (SPI_GPIO(SPI0_CLK)) : (SPI_GPIO(SPI1_CLK));

	if (is_on)
		gpio_set_value_cansleep(pin, 1);
	else
		gpio_set_value_cansleep(pin, 0);
}
static void setmosi(struct spi_device *dev, int is_on)
{
	struct cdns_xspi_dev *cdns_xspi = (struct cdns_xspi_dev *)dev;
	int pin = cdns_xspi->xspi_id == 0 ? (SPI_GPIO(SPI0_IO0)) : (SPI_GPIO(SPI1_IO0));

	if (is_on)
		gpio_set_value_cansleep(pin, 1);
	else
		gpio_set_value_cansleep(pin, 0);
}
static int getmiso(struct spi_device *dev)
{
	struct cdns_xspi_dev *cdns_xspi = (struct cdns_xspi_dev *)dev;
	int pin = cdns_xspi->xspi_id == 0 ? (SPI_GPIO(SPI0_IO1)) : (SPI_GPIO(SPI1_IO1));
	int val = gpio_get_value_cansleep(pin);

	return val;
}
static void spidelay(unsigned int d)
{
	do {} while (0);
}

#include "spi-bitbang-txrx.h"


static bool cdns_xspi_reset_dll(struct cdns_xspi_dev *cdns_xspi)
{
	u32 dll_cntrl = readl(cdns_xspi->iobase + CDNS_XSPI_RF_MINICTRL_REGS_DLL_PHY_CTRL);
	u32 dll_lock;

	/*Reset DLL*/
	dll_cntrl |= CDNS_XSPI_DLL_RST_N;
	writel(dll_cntrl, cdns_xspi->iobase + CDNS_XSPI_RF_MINICTRL_REGS_DLL_PHY_CTRL);

	/*Wait for DLL lock*/
	return readl_relaxed_poll_timeout(cdns_xspi->iobase +
		CDNS_XSPI_INTR_STATUS_REG,
		dll_lock, ((dll_lock & CDNS_XSPI_DLL_LOCK) == 1), 10, 10000);
}

//Static confiuration of PHY
static bool cdns_xspi_configure_phy(struct cdns_xspi_dev *cdns_xspi)
{
	writel(REGS_DLL_PHY_CTRL,
		cdns_xspi->iobase + CDNS_XSPI_RF_MINICTRL_REGS_DLL_PHY_CTRL);
	writel(CTB_RFILE_PHY_CTRL,
		cdns_xspi->auxbase + CDNS_XSPI_PHY_CTB_RFILE_PHY_CTRL);
	writel(RFILE_PHY_TSEL,
		cdns_xspi->auxbase + CDNS_XSPI_PHY_CTB_RFILE_PHY_TSEL);
	writel(RFILE_PHY_DQ_TIMING,
		cdns_xspi->auxbase + CDNS_XSPI_PHY_DATASLICE_RFILE_PHY_DQ_TIMING);
	writel(RFILE_PHY_DQS_TIMING,
		cdns_xspi->auxbase + CDNS_XSPI_PHY_DATASLICE_RFILE_PHY_DQS_TIMING);
	writel(RFILE_PHY_GATE_LPBK_CTRL,
		cdns_xspi->auxbase + CDNS_XSPI_PHY_DATASLICE_RFILE_PHY_GATE_LPBK_CTRL);
	writel(RFILE_PHY_DLL_MASTER_CTRL,
		cdns_xspi->auxbase + CDNS_XSPI_PHY_DATASLICE_RFILE_PHY_DLL_MASTER_CTRL);
	writel(RFILE_PHY_DLL_SLAVE_CTRL,
		cdns_xspi->auxbase + CDNS_XSPI_PHY_DATASLICE_RFILE_PHY_DLL_SLAVE_CTRL);

	return cdns_xspi_reset_dll(cdns_xspi);
}

// Find max avalible clock
static bool cdns_xspi_setup_clock(struct cdns_xspi_dev *cdns_xspi, int requested_clk)
{
	int i = 0;
	int clk_val;
	u32 clk_reg;
	bool update_clk = false;

	while (cdns_xspi_clk_div_list[i] > 0) {
		clk_val = CDNS_XSPI_CLOCK_DIVIDED(cdns_xspi_clk_div_list[i]);
		if (clk_val <= requested_clk)
			break;
		i++;
	}

	if (cdns_xspi_clk_div_list[i] == -1) {
		dev_info(cdns_xspi->dev, "Unable to find clock divider for CLK: %d - setting 6.25MHz\n",
		       requested_clk);
		i = 0x0D;
	} else {
		dev_dbg(cdns_xspi->dev, "Found clk div: %d, clk val: %d\n",
			cdns_xspi_clk_div_list[i],
			CDNS_XSPI_CLOCK_DIVIDED(cdns_xspi_clk_div_list[i]));
	}

	clk_reg = readl(cdns_xspi->auxbase + CDNS_XSPI_CLK_CTRL_AUX_REG);

	if (FIELD_GET(CDNS_XSPI_CLK_DIV, clk_reg) != i) {
		clk_reg &= ~CDNS_XSPI_CLK_ENABLE;
		writel(clk_reg, cdns_xspi->auxbase + CDNS_XSPI_CLK_CTRL_AUX_REG);
		clk_reg &= ~CDNS_XSPI_CLK_DIV;
		clk_reg |= FIELD_PREP(CDNS_XSPI_CLK_DIV, i);
		clk_reg |= CDNS_XSPI_CLK_ENABLE;
		update_clk = true;
	}

	if (update_clk)
		writel(clk_reg, cdns_xspi->auxbase + CDNS_XSPI_CLK_CTRL_AUX_REG);

	return update_clk;
}
#endif

static int cdns_xspi_wait_for_controller_idle(struct cdns_xspi_dev *cdns_xspi)
{
	u32 ctrl_stat;

	return readl_relaxed_poll_timeout(cdns_xspi->iobase +
					  CDNS_XSPI_CTRL_STATUS_REG,
					  ctrl_stat,
					  ((ctrl_stat &
					    CDNS_XSPI_CTRL_BUSY) == 0),
					  100, 1000);
}

static void cdns_xspi_trigger_command(struct cdns_xspi_dev *cdns_xspi,
				      u32 cmd_regs[6])
{
	writel(cmd_regs[5], cdns_xspi->iobase + CDNS_XSPI_CMD_REG_5);
	writel(cmd_regs[4], cdns_xspi->iobase + CDNS_XSPI_CMD_REG_4);
	writel(cmd_regs[3], cdns_xspi->iobase + CDNS_XSPI_CMD_REG_3);
	writel(cmd_regs[2], cdns_xspi->iobase + CDNS_XSPI_CMD_REG_2);
	writel(cmd_regs[1], cdns_xspi->iobase + CDNS_XSPI_CMD_REG_1);
	writel(cmd_regs[0], cdns_xspi->iobase + CDNS_XSPI_CMD_REG_0);
}

static int cdns_xspi_check_command_status(struct cdns_xspi_dev *cdns_xspi)
{
	int ret = 0;
	u32 cmd_status = readl(cdns_xspi->iobase + CDNS_XSPI_CMD_STATUS_REG);

	if (cmd_status & CDNS_XSPI_CMD_STATUS_COMPLETED) {
		if ((cmd_status & CDNS_XSPI_CMD_STATUS_FAILED) != 0) {
			if (cmd_status & CDNS_XSPI_CMD_STATUS_DQS_ERROR) {
				dev_err(cdns_xspi->dev,
					"Incorrect DQS pulses detected\n");
				ret = -EPROTO;
			}
			if (cmd_status & CDNS_XSPI_CMD_STATUS_CRC_ERROR) {
				dev_err(cdns_xspi->dev,
					"CRC error received\n");
				ret = -EPROTO;
			}
			if (cmd_status & CDNS_XSPI_CMD_STATUS_BUS_ERROR) {
				dev_err(cdns_xspi->dev,
					"Error resp on system DMA interface\n");
				ret = -EPROTO;
			}
			if (cmd_status & CDNS_XSPI_CMD_STATUS_INV_SEQ_ERROR) {
				dev_err(cdns_xspi->dev,
					"Invalid command sequence detected\n");
				ret = -EPROTO;
			}
		}
	} else {
		dev_err(cdns_xspi->dev, "Fatal err - command not completed\n");
		ret = -EPROTO;
	}

	return ret;
}

static void cdns_xspi_set_interrupts(struct cdns_xspi_dev *cdns_xspi,
				     bool enabled)
{
	u32 intr_enable;
	u32 irq_status;

	if (!cdns_xspi->irq)
		return;

	irq_status = readl(cdns_xspi->iobase + CDNS_XSPI_INTR_STATUS_REG);
	writel(irq_status, cdns_xspi->iobase + CDNS_XSPI_INTR_STATUS_REG);

	intr_enable = readl(cdns_xspi->iobase + CDNS_XSPI_INTR_ENABLE_REG);
	if (enabled)
		intr_enable |= CDNS_XSPI_INTR_MASK;
	else
		intr_enable &= ~CDNS_XSPI_INTR_MASK;
	writel(intr_enable, cdns_xspi->iobase + CDNS_XSPI_INTR_ENABLE_REG);
}

static int cdns_xspi_controller_init(struct cdns_xspi_dev *cdns_xspi)
{
	u32 ctrl_ver;
	u32 ctrl_features;
	u16 hw_magic_num;

	ctrl_ver = readl(cdns_xspi->iobase + CDNS_XSPI_CTRL_VERSION_REG);
	hw_magic_num = FIELD_GET(CDNS_XSPI_MAGIC_NUM, ctrl_ver);
	if (hw_magic_num != CDNS_XSPI_MAGIC_NUM_VALUE) {
		dev_err(cdns_xspi->dev,
			"Incorrect XSPI magic number: %x, expected: %x\n",
			hw_magic_num, CDNS_XSPI_MAGIC_NUM_VALUE);
		return -EIO;
	}

	writel(FIELD_PREP(CDNS_XSPI_CTRL_WORK_MODE, CDNS_XSPI_WORK_MODE_STIG),
	       cdns_xspi->iobase + CDNS_XSPI_CTRL_CONFIG_REG);

	ctrl_features = readl(cdns_xspi->iobase + CDNS_XSPI_CTRL_FEATURES_REG);
	cdns_xspi->hw_num_banks = FIELD_GET(CDNS_XSPI_NUM_BANKS, ctrl_features);
	cdns_xspi_set_interrupts(cdns_xspi, false);

	return 0;
}

static void cdns_ioreadq(void __iomem  *addr, void *buf, int len)
{
	int i = 0;
	int rcount = len / 8;
	int rcount_nf = len % 8;
	uint64_t tmp;
	uint64_t *buf64 = (uint64_t *)buf;

	if (((uint64_t)buf % 8) == 0) {
		for (i = 0; i < rcount; i++)
			*buf64++ = readq(addr);
	} else {
		for (i = 0; i < rcount; i++) {
			tmp = readq(addr);
			memcpy(buf+(i*8), &tmp, 8);
		}
	}

	if (rcount_nf != 0) {
		tmp = readq(addr);
		memcpy(buf+(i*8), &tmp, rcount_nf);
	}
}

static void cdns_iowriteq(void __iomem *addr, const void *buf, int len)
{
	int i = 0;
	int rcount = len / 8;
	int rcount_nf = len % 8;
	uint64_t tmp;
	uint64_t *buf64 = (uint64_t *)buf;

	if (((uint64_t)buf % 8) == 0) {
		for (i = 0; i < rcount; i++)
			writeq(*buf64++, addr);
	} else {
		for (i = 0; i < rcount; i++) {
			memcpy(&tmp, buf+(i*8), 8);
			writeq(tmp, addr);
		}
	}

	if (rcount_nf != 0) {
		memcpy(&tmp, buf+(i*8), rcount_nf);
		writeq(tmp, addr);
	}
}

static void cdns_xspi_sdma_memread(struct cdns_xspi_dev *cdns_xspi,
				   enum cdns_xspi_sdma_size size, int len)
{
	switch (size) {
	case CDNS_XSPI_SDMA_SIZE_8B:
		ioread8_rep(cdns_xspi->sdmabase,
			    cdns_xspi->in_buffer, len);
		break;
	case CDNS_XSPI_SDMA_SIZE_64B:
		cdns_ioreadq(cdns_xspi->sdmabase, cdns_xspi->in_buffer, len);
		break;
	}
}

static void cdns_xspi_sdma_memwrite(struct cdns_xspi_dev *cdns_xspi,
				    enum cdns_xspi_sdma_size size, int len)
{
	switch (size) {
	case CDNS_XSPI_SDMA_SIZE_8B:
		iowrite8_rep(cdns_xspi->sdmabase,
			     cdns_xspi->out_buffer, len);
		break;
	case CDNS_XSPI_SDMA_SIZE_64B:
		cdns_iowriteq(cdns_xspi->sdmabase, cdns_xspi->out_buffer, len);
		break;
	}
}

static void cdns_xspi_sdma_handle(struct cdns_xspi_dev *cdns_xspi)
{
	u32 sdma_size, sdma_trd_info;
	u8 sdma_dir;

	sdma_size = readl(cdns_xspi->iobase + CDNS_XSPI_SDMA_SIZE_REG);
	sdma_trd_info = readl(cdns_xspi->iobase + CDNS_XSPI_SDMA_TRD_INFO_REG);
	sdma_dir = FIELD_GET(CDNS_XSPI_SDMA_DIR, sdma_trd_info);

	switch (sdma_dir) {
	case CDNS_XSPI_SDMA_DIR_READ:
		cdns_xspi_sdma_memread(cdns_xspi,
				       cdns_xspi->read_size,
				       sdma_size);
		break;

	case CDNS_XSPI_SDMA_DIR_WRITE:
		cdns_xspi_sdma_memwrite(cdns_xspi,
					cdns_xspi->read_size,
					sdma_size);
		break;
	}
}

bool cdns_xspi_stig_ready(struct cdns_xspi_dev *cdns_xspi, bool sleep)
{
	u32 ctrl_stat;

	return readl_relaxed_poll_timeout
		(cdns_xspi->iobase + CDNS_XSPI_CTRL_STATUS_REG,
		ctrl_stat,
		((ctrl_stat & BIT(3)) == 0),
		sleep ? CDNS_XSPI_POLL_DELAY_US : 0,
		sleep ? CDNS_XSPI_POLL_TIMEOUT_US : 0);
}

bool cdns_xspi_sdma_ready(struct cdns_xspi_dev *cdns_xspi, bool sleep)
{
	u32 ctrl_stat;

	return readl_relaxed_poll_timeout
		(cdns_xspi->iobase + CDNS_XSPI_INTR_STATUS_REG,
		ctrl_stat,
		(ctrl_stat & CDNS_XSPI_SDMA_TRIGGER),
		sleep ? CDNS_XSPI_POLL_DELAY_US : 0,
		sleep ? CDNS_XSPI_POLL_TIMEOUT_US : 0);
}

static int cdns_xspi_send_stig_command(struct cdns_xspi_dev *cdns_xspi,
				       const struct spi_mem_op *op,
				       bool data_phase,
				       bool pstore_sleep)
{
	u32 cmd_regs[6];
	u32 cmd_status;
	int ret = 0;
	int dummybytes = op->dummy.nbytes;

#if IS_ENABLED(CONFIG_SPI_CADENCE_MRVL_XSPI)
	if (lock_spi_bus(cdns_xspi) != 0) {
		pr_err("Failed to lock SPI bus\n");
		return -EIO;
	}
#if !IS_ENABLED(CONFIG_SPI_CADENCE_HW_WO)
	if (cdns_xspi->wo_mode)
		gpio_as_spi(cdns_xspi);
#endif
#endif
	ret = cdns_xspi_wait_for_controller_idle(cdns_xspi);
	if (ret < 0) {
		ret = -EIO;
		goto fail;
	}

	writel(FIELD_PREP(CDNS_XSPI_CTRL_WORK_MODE, CDNS_XSPI_WORK_MODE_STIG),
	       cdns_xspi->iobase + CDNS_XSPI_CTRL_CONFIG_REG);

	cdns_xspi_set_interrupts(cdns_xspi, true);
	cdns_xspi->sdma_error = false;

	memset(cmd_regs, 0, sizeof(cmd_regs));
	cmd_regs[1] = CDNS_XSPI_CMD_FLD_P1_INSTR_CMD_1(op, data_phase);
	cmd_regs[2] = CDNS_XSPI_CMD_FLD_P1_INSTR_CMD_2(op);
	if (dummybytes != 0) {
		cmd_regs[3] = CDNS_XSPI_CMD_FLD_P1_INSTR_CMD_3(op, 1);
		dummybytes--;
	} else {
		cmd_regs[3] = CDNS_XSPI_CMD_FLD_P1_INSTR_CMD_3(op, 0);
	}
	cmd_regs[4] = CDNS_XSPI_CMD_FLD_P1_INSTR_CMD_4(op,
						       cdns_xspi->cur_cs);

	cdns_xspi_trigger_command(cdns_xspi, cmd_regs);

	if (data_phase) {
		cmd_regs[0] = CDNS_XSPI_STIG_DONE_FLAG;
		cmd_regs[1] = CDNS_XSPI_CMD_FLD_DSEQ_CMD_1(op);
		cmd_regs[2] = CDNS_XSPI_CMD_FLD_DSEQ_CMD_2(op);
		cmd_regs[3] = CDNS_XSPI_CMD_FLD_DSEQ_CMD_3(op, dummybytes);
		cmd_regs[4] = CDNS_XSPI_CMD_FLD_DSEQ_CMD_4(op,
							   cdns_xspi->cur_cs);

		cdns_xspi->in_buffer = op->data.buf.in;
		cdns_xspi->out_buffer = op->data.buf.out;

		cdns_xspi_trigger_command(cdns_xspi, cmd_regs);

		if (cdns_xspi->irq && pstore_sleep) {
			wait_for_completion(&cdns_xspi->sdma_complete);
			if (cdns_xspi->sdma_error) {
				cdns_xspi_set_interrupts(cdns_xspi, false);
				ret = -EIO;
				goto fail;
			}
		} else {
			if (cdns_xspi_sdma_ready(cdns_xspi, pstore_sleep)) {
				ret = -EIO;
				goto fail;
			}
		}
		cdns_xspi_sdma_handle(cdns_xspi);
	}

	if (cdns_xspi->irq && pstore_sleep) {
		wait_for_completion(&cdns_xspi->cmd_complete);
		cdns_xspi_set_interrupts(cdns_xspi, false);
	} else {
		if (cdns_xspi_stig_ready(cdns_xspi, pstore_sleep)) {
			ret = -EIO;
			goto fail;
		}
	}

	cmd_status = cdns_xspi_check_command_status(cdns_xspi);
	if (cmd_status) {
		ret = -EPROTO;
		goto fail;
	}

fail:
#if IS_ENABLED(CONFIG_SPI_CADENCE_MRVL_XSPI)
	unlock_spi_bus(cdns_xspi);
#endif
	return ret;
}

static int cdns_xspi_mem_op(struct cdns_xspi_dev *cdns_xspi,
			    struct spi_mem *mem,
			    const struct spi_mem_op *op,
			    bool pstore)
{
	enum spi_mem_data_dir dir = op->data.dir;

	if (cdns_xspi->cur_cs != mem->spi->chip_select)
		cdns_xspi->cur_cs = mem->spi->chip_select;

#if IS_ENABLED(CONFIG_SPI_CADENCE_MRVL_XSPI)
	cdns_xspi_setup_clock(cdns_xspi, mem->spi->max_speed_hz);
#endif

	return cdns_xspi_send_stig_command(cdns_xspi, op,
					   (dir != SPI_MEM_NO_DATA),
					   !pstore);
}

#ifdef CONFIG_ACPI
static bool cdns_xspi_supports_op(struct spi_mem *mem,
				  const struct spi_mem_op *op)
{
	struct spi_device *spi = mem->spi;
	const union acpi_object *obj;
	struct acpi_device *adev;

	adev = ACPI_COMPANION(&spi->dev);

	if (!acpi_dev_get_property(adev, "spi-tx-bus-width", ACPI_TYPE_INTEGER,
				   &obj)) {
		switch (obj->integer.value) {
		case 1:
			break;
		case 2:
			spi->mode |= SPI_TX_DUAL;
			break;
		case 4:
			spi->mode |= SPI_TX_QUAD;
			break;
		case 8:
			spi->mode |= SPI_TX_OCTAL;
			break;
		default:
			dev_warn(&spi->dev,
				 "spi-tx-bus-width %lld not supported\n",
				 obj->integer.value);
			break;
		}
	}

	if (!acpi_dev_get_property(adev, "spi-rx-bus-width", ACPI_TYPE_INTEGER,
				   &obj)) {
		switch (obj->integer.value) {
		case 1:
			break;
		case 2:
			spi->mode |= SPI_RX_DUAL;
			break;
		case 4:
			spi->mode |= SPI_RX_QUAD;
			break;
		case 8:
			spi->mode |= SPI_RX_OCTAL;
			break;
		default:
			dev_warn(&spi->dev,
				 "spi-rx-bus-width %lld not supported\n",
				 obj->integer.value);
			break;
		}
	}

	if (!spi_mem_default_supports_op(mem, op))
		return false;

	return true;
}
#endif

static int cdns_xspi_mem_op_execute(struct spi_mem *mem,
				    const struct spi_mem_op *op)
{
	struct cdns_xspi_dev *cdns_xspi =
		spi_master_get_devdata(mem->spi->master);
	struct spi_nor *nor = spi_mem_get_drvdata(mem);

	int ret = 0;

	ret = cdns_xspi_mem_op(cdns_xspi, mem, op, nor->pstore);

	return ret;
}

static int cdns_xspi_adjust_mem_op_size(struct spi_mem *mem, struct spi_mem_op *op)
{
	struct cdns_xspi_dev *cdns_xspi =
		spi_master_get_devdata(mem->spi->master);

	op->data.nbytes = clamp_val(op->data.nbytes, 0, cdns_xspi->sdmasize);

	return 0;
}

static const struct spi_controller_mem_ops cadence_xspi_mem_ops = {
#ifdef CONFIG_ACPI
	.supports_op = cdns_xspi_supports_op,
#endif
	.exec_op = cdns_xspi_mem_op_execute,
	.adjust_op_size = cdns_xspi_adjust_mem_op_size,
};

static irqreturn_t cdns_xspi_irq_handler(int this_irq, void *dev)
{
	struct cdns_xspi_dev *cdns_xspi = dev;
	u32 irq_status;
	irqreturn_t result = IRQ_NONE;

	irq_status = readl(cdns_xspi->iobase + CDNS_XSPI_INTR_STATUS_REG);
	writel(irq_status, cdns_xspi->iobase + CDNS_XSPI_INTR_STATUS_REG);

#if IS_ENABLED(CONFIG_SPI_CADENCE_MRVL_XSPI)
	writel(CDNS_MSIX_CLEAR_IRQ, cdns_xspi->auxbase + CDNS_XSPI_SPIX_INTR_AUX);
#endif

	if (irq_status &
	    (CDNS_XSPI_SDMA_ERROR | CDNS_XSPI_SDMA_TRIGGER |
	     CDNS_XSPI_STIG_DONE)) {
		if (irq_status & CDNS_XSPI_SDMA_ERROR) {
			dev_err(cdns_xspi->dev,
				"Slave DMA transaction error\n");
			cdns_xspi->sdma_error = true;
			complete(&cdns_xspi->sdma_complete);
		}

		if (irq_status & CDNS_XSPI_SDMA_TRIGGER)
			complete(&cdns_xspi->sdma_complete);

		if (irq_status & CDNS_XSPI_STIG_DONE)
			complete(&cdns_xspi->cmd_complete);

		result = IRQ_HANDLED;
	}

	irq_status = readl(cdns_xspi->iobase + CDNS_XSPI_TRD_COMP_INTR_STATUS);
	if (irq_status) {
		writel(irq_status,
		       cdns_xspi->iobase + CDNS_XSPI_TRD_COMP_INTR_STATUS);

		complete(&cdns_xspi->auto_cmd_complete);

		result = IRQ_HANDLED;
	}

	return result;
}

static int cdns_xspi_of_get_plat_data(struct platform_device *pdev)
{
	struct fwnode_handle *fwnode_child;
	struct spi_master *master = platform_get_drvdata(pdev);
	struct cdns_xspi_dev *cdns_xspi = spi_master_get_devdata(master);
	unsigned int cs;
	unsigned int read_size = 0;

#if IS_ENABLED(CONFIG_SPI_CADENCE_MRVL_XSPI)
	unsigned int base_addr = 0;

	if (device_property_read_u32(&pdev->dev, "reg", &base_addr))
		dev_info(&pdev->dev, "Missing reg property");

	if (base_addr == SPI0_BASE)
		cdns_xspi->xspi_id = 0;
	else
		cdns_xspi->xspi_id = 1;

#endif

	if (device_property_read_u32(&pdev->dev, "cdns,read-size", &read_size))
		dev_info(&pdev->dev, "Missing read size property, usining byte access\n");
	cdns_xspi->read_size = read_size;

	device_for_each_child_node(&pdev->dev, fwnode_child) {
		if (!fwnode_device_is_available(fwnode_child))
			continue;

		if (fwnode_property_read_u32(fwnode_child, "reg", &cs)) {
			dev_err(&pdev->dev, "Couldn't get memory chip select\n");
			fwnode_handle_put(fwnode_child);
			return -ENXIO;
		} else if (cs >= CDNS_XSPI_MAX_BANKS) {
			dev_err(&pdev->dev, "reg (cs) parameter value too large\n");
			fwnode_handle_put(fwnode_child);
			return -ENXIO;
		}
		cdns_xspi->cs_defined |= BIT(cs);
	}

	return 0;
}

static void cdns_xspi_print_phy_config(struct cdns_xspi_dev *cdns_xspi)
{
	struct device *dev = cdns_xspi->dev;

	dev_info(dev, "PHY configuration\n");
	dev_info(dev, "   * xspi_dll_phy_ctrl: %08x\n",
		 readl(cdns_xspi->iobase + CDNS_XSPI_DLL_PHY_CTRL));
	dev_info(dev, "   * phy_dq_timing: %08x\n",
		 readl(cdns_xspi->auxbase + CDNS_XSPI_CCP_PHY_DQ_TIMING));
	dev_info(dev, "   * phy_dqs_timing: %08x\n",
		 readl(cdns_xspi->auxbase + CDNS_XSPI_CCP_PHY_DQS_TIMING));
	dev_info(dev, "   * phy_gate_loopback_ctrl: %08x\n",
		 readl(cdns_xspi->auxbase + CDNS_XSPI_CCP_PHY_GATE_LPBCK_CTRL));
	dev_info(dev, "   * phy_dll_slave_ctrl: %08x\n",
		 readl(cdns_xspi->auxbase + CDNS_XSPI_CCP_PHY_DLL_SLAVE_CTRL));
}

#if IS_ENABLED(CONFIG_SPI_CADENCE_MRVL_XSPI)
static int cdns_xspi_setup(struct spi_device *spi_dev)
{
	struct cdns_xspi_dev *cdns_xspi = spi_master_get_devdata(spi_dev->master);

	cdns_xspi_setup_clock(cdns_xspi, spi_dev->max_speed_hz);

	return 0;
}

static bool cdns_xspi_is_xfer_supported(struct cdns_xspi_dev *cdns_xspi)
{
	u32 clk_reg = readl(cdns_xspi->auxbase + CDNS_XSPI_CLK_CTRL_AUX_REG);

	if (clk_reg & CDNS_XSPI_XFER_SUPPORTED)
		return true;

	return false;
}

static int cdns_xspi_prepare_generic(int cs, const void *dout, int len, int glue, u32 *cmd_regs)
{
	u8 *data = (u8 *)dout;
	int i;
	int data_counter = 0;

	memset(cmd_regs, 0x00, 6*4);

	if (len > 7) {
		for (i = (len >= 10 ? 2 : len - 8); i >= 0 ; i--)
			cmd_regs[3] |= data[data_counter++] << (8*i);
	}
	if (len > 3) {
		for (i = (len >= 7 ? 3 : len - 4); i >= 0; i--)
			cmd_regs[2] |= data[data_counter++] << (8*i);
	}
	for (i = (len >= 3 ? 2 : len - 1); i >= 0 ; i--)
		cmd_regs[1] |= data[data_counter++] << (8 + 8*i);

	cmd_regs[1] |= 96;
	cmd_regs[3] |= len << 24;
	cmd_regs[4] |= cs << 12;

	if (glue == 1)
		cmd_regs[4] |= 1 << 28;

	return 0;
}

unsigned char reverse_bits(unsigned char num)
{
	unsigned int count = sizeof(num) * 8 - 1;
	unsigned int reverse_num = num;

	num >>= 1;
	while (num) {
		reverse_num <<= 1;
		reverse_num |= num & 1;
		num >>= 1;
		count--;
	}
	reverse_num <<= count;
	return reverse_num;
}

static void cdns_xspi_read_single_qword(struct cdns_xspi_dev *cdns_xspi, u8 **buffer)
{
	u64 d = readq(cdns_xspi->xferbase +
		      SPIX_XFER_FUNC_CTRL_READ_DATA(cdns_xspi->current_xfer_qword));
	u8 *ptr = (u8 *)&d;
	int k;

	for (k = 0; k < 8; k++) {
		u8 val = reverse_bits((ptr[k]));
		**buffer = val;
		*buffer = *buffer + 1;
	}

	cdns_xspi->current_xfer_qword++;
	cdns_xspi->current_xfer_qword %= XFER_QWORD_COUNT;
}

static void cdns_xspi_finish_read(struct cdns_xspi_dev *cdns_xspi, u8 **buffer, u32 data_count)
{
	u64 d = readq(cdns_xspi->xferbase +
		      SPIX_XFER_FUNC_CTRL_READ_DATA(cdns_xspi->current_xfer_qword));
	u8 *ptr = (u8 *)&d;
	int k;

	for (k = 0; k < data_count % XFER_QWORD_BYTECOUNT; k++) {
		u8 val = reverse_bits((ptr[k]));
		**buffer = val;
		*buffer = *buffer + 1;
	}

	cdns_xspi->current_xfer_qword++;
	cdns_xspi->current_xfer_qword %= XFER_QWORD_COUNT;
}

static int cdns_xspi_prepare_transfer(int cs, int dir, int len, u32 *cmd_regs)
{
	memset(cmd_regs, 0x00, 6*4);

	cmd_regs[1] |= 127;
	cmd_regs[2] |= len << 16;
	cmd_regs[4] |= dir << 4; //dir = 0 read, dir =1 write
	cmd_regs[4] |= cs << 12;

	return 0;
}

int cdns_xspi_transfer_one_message(struct spi_controller *master,
				   struct spi_message *m)
{
	struct cdns_xspi_dev *cdns_xspi = spi_master_get_devdata(master);
	struct spi_device *spi = m->spi;
	struct spi_transfer *t = NULL;

	const int max_len = XFER_QWORD_BYTECOUNT * XFER_QWORD_COUNT;
	int current_cycle_count;
	int cs = spi->chip_select;
	int cs_change = 0;

	if (cdns_xspi_wait_for_controller_idle(cdns_xspi) < 0)
		return -EIO;

	writel(FIELD_PREP(CDNS_XSPI_CTRL_WORK_MODE, CDNS_XSPI_WORK_MODE_STIG),
	       cdns_xspi->iobase + CDNS_XSPI_CTRL_CONFIG_REG);

	/* Enable xfer state machine */
	if (!cdns_xspi->xfer_in_progress) {
		u32 xfer_control = readl(cdns_xspi->xferbase + SPIX_XFER_FUNC_CTRL);

		cdns_xspi->current_xfer_qword = 0;
		cdns_xspi->xfer_in_progress = true;
		xfer_control |= (XFER_RECEIVE_ENABLE |
				 XFER_CLK_CAPTURE_POL |
				 XFER_FUNC_START |
				 XFER_SOFT_RESET |
				 FIELD_PREP(XFER_CS_N_HOLD, (1 << cs)));
		xfer_control &= ~(XFER_FUNC_ENABLE | XFER_CLK_DRIVE_POL);
		writel(xfer_control, cdns_xspi->xferbase + SPIX_XFER_FUNC_CTRL);
	}

	list_for_each_entry(t, &m->transfers, transfer_list) {
		u8 *txd = (u8 *) t->tx_buf;
		u8 *rxd = (u8 *) t->rx_buf;
		u8 data[10];
		u32 cmd_regs[6];

		if (!txd)
			txd = data;

		cdns_xspi->in_buffer = txd + 1;
		cdns_xspi->out_buffer = txd + 1;

		while (t->len) {

			current_cycle_count = t->len > max_len ? max_len : t->len;

			if (current_cycle_count < 10) {
				cdns_xspi_prepare_generic(cs, txd, current_cycle_count,
							  false, cmd_regs);
				cdns_xspi_trigger_command(cdns_xspi, cmd_regs);
				if (cdns_xspi_stig_ready(cdns_xspi, true))
					return -EIO;
			} else {
				cdns_xspi_prepare_generic(cs, txd, 1, true, cmd_regs);
				cdns_xspi_trigger_command(cdns_xspi, cmd_regs);
				cdns_xspi_prepare_transfer(cs, 1, current_cycle_count - 1,
							   cmd_regs);
				cdns_xspi_trigger_command(cdns_xspi, cmd_regs);
				if (cdns_xspi_sdma_ready(cdns_xspi, true))
					return -EIO;
				cdns_xspi_sdma_handle(cdns_xspi);
				if (cdns_xspi_stig_ready(cdns_xspi, true))
					return -EIO;

				cdns_xspi->in_buffer += current_cycle_count;
				cdns_xspi->out_buffer += current_cycle_count;
			}

			if (rxd) {
				int j;

				for (j = 0; j < current_cycle_count / 8; j++)
					cdns_xspi_read_single_qword(cdns_xspi, &rxd);
				cdns_xspi_finish_read(cdns_xspi, &rxd, current_cycle_count);
			} else {
				cdns_xspi->current_xfer_qword += current_cycle_count /
								 XFER_QWORD_BYTECOUNT;
				if (current_cycle_count % XFER_QWORD_BYTECOUNT)
					cdns_xspi->current_xfer_qword++;

				cdns_xspi->current_xfer_qword %= XFER_QWORD_COUNT;
			}
			cs_change = t->cs_change;
			t->len -= current_cycle_count;
		}
	}

	if (!cs_change) {
		u32 xfer_control = readl(cdns_xspi->xferbase + SPIX_XFER_FUNC_CTRL);

		xfer_control &= ~(XFER_RECEIVE_ENABLE |
				  XFER_SOFT_RESET);
		writel(xfer_control, cdns_xspi->xferbase + SPIX_XFER_FUNC_CTRL);
		cdns_xspi->xfer_in_progress = false;
	}

	m->status = 0;
	spi_finalize_current_message(master);

	return 0;
}

static int spi_swap(int val, int len)
{
	uint8_t *buf8 = (uint8_t *) &val;
	uint8_t temp;
	int *intswapped = (int *)buf8;


	if (len == 4) {
		temp = buf8[0];
		buf8[0] = buf8[3];
		buf8[3] = temp;
		temp = buf8[1];
		buf8[1] = buf8[2];
		buf8[2] = temp;
	}

	if (len == 3) {
		temp = buf8[0];
		buf8[0] = buf8[2];
		buf8[2] = temp;
	}

	if (len == 2) {
		temp = buf8[0];
		buf8[0] = buf8[1];
		buf8[1] = temp;
	}


	return *intswapped;
}

#if IS_ENABLED(CONFIG_SPI_CADENCE_HW_WO)
static int handle_tx_rx(struct cdns_xspi_dev *cdns_xspi, void *tx_buf,
			void *rx_buf, int write_len, int len)
{
	u32 cmd_regs[6] = {0};
	u32 cmd_status;
	int read_dir = 0;
	int glue_command = 0;

	/* Incorrect params */
	if (write_len > len) {
		pr_info("Write len cannot be bigger than len\n");
		return -ENODEV;
	}

	/* NO transmit buffer - not supported */
	if (tx_buf == NULL || write_len == 0) {
		pr_info("RX only operation not supported\n");
		return -ENODEV;
	}

	/* TX RX operation requested */
	if (rx_buf != NULL && write_len != len) {
		read_dir = 0;
		glue_command = 1;
	} else {
		read_dir = 1;
		if (len > 10) {
			glue_command = 1;
			write_len = 10;
		}
	}

	cdns_xspi_set_interrupts(cdns_xspi, true);

	cdns_xspi->in_buffer = rx_buf + write_len;
	cdns_xspi->out_buffer = tx_buf + 10;

	cdns_xspi_prepare_generic(cdns_xspi->cur_cs, tx_buf, write_len, glue_command, cmd_regs);
	cdns_xspi_trigger_command(cdns_xspi, cmd_regs);
	if (glue_command) {
		cdns_xspi_prepare_transfer(cdns_xspi->cur_cs, read_dir, len - write_len, cmd_regs);
		cdns_xspi_trigger_command(cdns_xspi, cmd_regs);
		wait_for_completion(&cdns_xspi->sdma_complete);
		if (cdns_xspi->sdma_error) {
			cdns_xspi_set_interrupts(cdns_xspi, false);
			return -EIO;
		}
		cdns_xspi_sdma_handle(cdns_xspi);
		wait_for_completion(&cdns_xspi->cmd_complete);
	}

	cdns_xspi_set_interrupts(cdns_xspi, false);

	cmd_status = cdns_xspi_check_command_status(cdns_xspi);
	if (cmd_status)
		return -EPROTO;

	return 0;
}
#endif

static int cdns_xspi_transfer_one_message_wo(struct spi_controller *master,
					   struct spi_message *m)
{
	struct cdns_xspi_dev *cdns_xspi = spi_master_get_devdata(master);
	struct spi_device *spi = m->spi;
	struct spi_transfer *t = NULL;
	int cs = spi->chip_select;

#if IS_ENABLED(CONFIG_SPI_CADENCE_HW_WO)
	cdns_xspi->cur_cs = cs;

	list_for_each_entry(t, &m->transfers, transfer_list) {
		handle_tx_rx(cdns_xspi, (void *)t->tx_buf, t->rx_buf, cdns_xspi->write_len, t->len);
	}

#else
	int cs_change = 0;

	if (gpio_as_sw(cdns_xspi) == 1)
		set_gpio_mode(cdns_xspi);

	if (cs == 1)
		gpio_set_value_cansleep(SPI_GPIO(SPI1_CS1), 0);
	else
		gpio_set_value_cansleep(SPI_GPIO(SPI1_CS0), 0);

	list_for_each_entry(t, &m->transfers, transfer_list) {
		int *txbuf = (int *) t->tx_buf;
		int *rxbuf = (int *) t->rx_buf;
		int txbuf_swap = 0;
		int rxbuf_swap = 0;
		int transfer_len;

		while (t->len) {
			transfer_len = t->len > 4 ? 4 : t->len;
			if (txbuf) {
				txbuf_swap = spi_swap(*txbuf, transfer_len);
				txbuf += 1;
			}
			rxbuf_swap = bitbang_txrx_be_cpha0(
						(struct spi_device *)cdns_xspi,
						100, 0, 0, txbuf_swap,
						transfer_len*8);
			m->actual_length +=  transfer_len;
			t->len -= transfer_len;
			if (rxbuf) {
				*rxbuf = spi_swap(rxbuf_swap, transfer_len);
				rxbuf++;
			}
			cs_change = t->cs_change;
		}
	}

	if (!cs_change) {
		if (cs == 1)
			gpio_set_value_cansleep(SPI_GPIO(SPI1_CS1), 1);
		else
			gpio_set_value_cansleep(SPI_GPIO(SPI1_CS0), 1);

		/* Transfer compleded, switch GPIOs back to SPI mode */
		/* For some reason quick changing GPIO function can cause issues */
		//gpio_as_spi();
	}
#endif
	m->status = 0;
	spi_finalize_current_message(master);

	return 0;
}

#if IS_ENABLED(CONFIG_SPI_CADENCE_HW_WO)
static struct cdns_xspi_dev *cdns_xspi_debug;
int mrvl_spi_open(struct inode *i, struct file *f)
{
	cdns_xspi_debug = i->i_private;
	return 0;
}
ssize_t mrvl_spi_wl_write(struct file *f, const char __user *user_buf, size_t size, loff_t *l)
{
	char buf[20] = {0};
	long val;

	if (copy_from_user(buf, user_buf, size)) {
		pr_info("SPI_%d: Failed to set write length\n", cdns_xspi_debug->xspi_id);
		return -EACCES;
	}
	if (kstrtol(buf, 10, &val))
		val = 1;
	cdns_xspi_debug->write_len = val;
	pr_info("SPI_%d: Setting write length to: %ld\n", cdns_xspi_debug->xspi_id, val);

	return size;
}

static const struct file_operations mrvl_spi_wl_fops = {
	.owner			= THIS_MODULE,
	.write			= mrvl_spi_wl_write,
	.open			= mrvl_spi_open,
};


static int mrvl_spi_setup_debugfs(struct cdns_xspi_dev *cdns_xspi)
{
	struct dentry *pfile;
	char file_name[30];

	if (mrvl_spi_debug_root == NULL)
		mrvl_spi_debug_root = debugfs_create_dir("cn10k_spi", NULL);

	sprintf(file_name, "SPI_%d_WriteLength", cdns_xspi->xspi_id);
	pfile = debugfs_create_file(file_name, 0644, mrvl_spi_debug_root, cdns_xspi,
				    &mrvl_spi_wl_fops);

	return 0;
}
#endif
#endif

static int cdns_xspi_probe(struct platform_device *pdev)
{
	struct device *dev = &pdev->dev;
	struct spi_master *master = NULL;
	struct cdns_xspi_dev *cdns_xspi = NULL;
	struct resource *res;
	int ret;

	master = devm_spi_alloc_master(dev, sizeof(*cdns_xspi));
	if (!master)
		return -ENOMEM;

	master->mode_bits = SPI_3WIRE | SPI_TX_DUAL  | SPI_TX_QUAD  |
		SPI_RX_DUAL | SPI_RX_QUAD | SPI_TX_OCTAL | SPI_RX_OCTAL |
		SPI_MODE_0  | SPI_MODE_3;

	master->mem_ops = &cadence_xspi_mem_ops;
	master->dev.of_node = pdev->dev.of_node;
	master->dev.fwnode = pdev->dev.fwnode;
	master->bus_num = -1;
#if IS_ENABLED(CONFIG_SPI_CADENCE_MRVL_XSPI)
	master->setup = cdns_xspi_setup;
#endif

	platform_set_drvdata(pdev, master);

	cdns_xspi = spi_master_get_devdata(master);
	cdns_xspi->pdev = pdev;
	cdns_xspi->dev = &pdev->dev;
	cdns_xspi->cur_cs = 0;
#if IS_ENABLED(CONFIG_SPI_CADENCE_MRVL_XSPI)
	cdns_xspi->cs_defined = 0;
#endif

	init_completion(&cdns_xspi->cmd_complete);
	init_completion(&cdns_xspi->auto_cmd_complete);
	init_completion(&cdns_xspi->sdma_complete);

	ret = cdns_xspi_of_get_plat_data(pdev);
	if (ret)
		return -ENODEV;

	res = platform_get_resource(pdev, IORESOURCE_MEM, 0);
	cdns_xspi->iobase = devm_ioremap_resource(dev, res);
	if (IS_ERR(cdns_xspi->iobase)) {
		dev_err(dev, "Failed to remap controller base address\n");
		return PTR_ERR(cdns_xspi->iobase);
	}

	res = platform_get_resource(pdev, IORESOURCE_MEM, 1);
	cdns_xspi->sdmabase = devm_ioremap_resource(dev, res);
	if (IS_ERR(cdns_xspi->sdmabase))
		return PTR_ERR(cdns_xspi->sdmabase);
	cdns_xspi->sdmasize = resource_size(res);

	res = platform_get_resource(pdev, IORESOURCE_MEM, 2);
	cdns_xspi->auxbase = devm_ioremap_resource(dev, res);
	if (IS_ERR(cdns_xspi->auxbase)) {
		dev_err(dev, "Failed to remap AUX address\n");
		return PTR_ERR(cdns_xspi->auxbase);
	}

#if IS_ENABLED(CONFIG_SPI_CADENCE_MRVL_XSPI)
	res = platform_get_resource(pdev, IORESOURCE_MEM, 3);
	if (res)
		cdns_xspi->xferbase = devm_ioremap_resource(dev, res);
	if (!res || IS_ERR(cdns_xspi->xferbase)) {
		dev_info(dev, "XFER register base not found, set it\n");
		// For compatibility with older firmware
		cdns_xspi->xferbase = cdns_xspi->iobase + 0x8000;
	}
#endif

	cdns_xspi->irq = platform_get_irq(pdev, 0);
	if (cdns_xspi->irq < 0)
		cdns_xspi->irq = 0;

	if (cdns_xspi->irq) {
		ret = devm_request_irq(dev, cdns_xspi->irq, cdns_xspi_irq_handler,
				IRQF_SHARED, pdev->name, cdns_xspi);
		if (ret) {
			dev_err(dev, "Failed to request IRQ: %d\n", cdns_xspi->irq);
			return ret;
		}
	}

#if IS_ENABLED(CONFIG_SPI_CADENCE_MRVL_XSPI)
	cdns_xspi_setup_clock(cdns_xspi, MRVL_DEFAULT_CLK);
	cdns_xspi_configure_phy(cdns_xspi);

	if (cdns_xspi_is_xfer_supported(cdns_xspi)) {
		master->transfer_one_message = cdns_xspi_transfer_one_message;
		cdns_xspi->wo_mode = false;
	} else {
		master->transfer_one_message = cdns_xspi_transfer_one_message_wo;
		cdns_xspi->wo_mode = true;
	}
#endif

	cdns_xspi_print_phy_config(cdns_xspi);
	ret = cdns_xspi_controller_init(cdns_xspi);
	if (ret) {
		dev_err(dev, "Failed to initialize controller\n");
		return ret;
	}

	master->num_chipselect = 1 << cdns_xspi->hw_num_banks;

	ret = devm_spi_register_master(dev, master);
	if (ret) {
		dev_err(dev, "Failed to register SPI master\n");
		return ret;
	}

	dev_info(dev, "Successfully registered SPI master\n");
#if IS_ENABLED(CONFIG_SPI_CADENCE_MRVL_XSPI)
	if (cdns_xspi->wo_mode) {
#if IS_ENABLED(CONFIG_SPI_CADENCE_HW_WO)
		mrvl_spi_setup_debugfs(cdns_xspi);
#else
		spi_gpio_prepare(cdns_xspi);
#endif
	}
#endif

	return 0;
}

static const struct acpi_device_id cdns_xspi_acpi_match[] = {
	{"cdns,xspi-nor", 0},
	{},
};
MODULE_DEVICE_TABLE(acpi, cdns_xspi_acpi_match);

#ifdef CONFIG_OF
static const struct of_device_id cdns_xspi_of_match[] = {
	{
		.compatible = "cdns,xspi-nor",
	},
	{ /* end of table */}
};
MODULE_DEVICE_TABLE(of, cdns_xspi_of_match);
#else
#define cdns_xspi_of_match NULL
#endif /* CONFIG_OF */

static struct platform_driver cdns_xspi_platform_driver = {
	.probe          = cdns_xspi_probe,
	.remove         = NULL,
	.driver = {
		.name = CDNS_XSPI_NAME,
		.of_match_table = cdns_xspi_of_match,
		.acpi_match_table = cdns_xspi_acpi_match,
	},
};

module_platform_driver(cdns_xspi_platform_driver);

MODULE_DESCRIPTION("Cadence XSPI Controller Driver");
MODULE_LICENSE("GPL v2");
MODULE_ALIAS("platform:" CDNS_XSPI_NAME);
MODULE_AUTHOR("Konrad Kociolek <konrad@cadence.com>");
MODULE_AUTHOR("Jayshri Pawar <jpawar@cadence.com>");
MODULE_AUTHOR("Parshuram Thombare <pthombar@cadence.com>");
