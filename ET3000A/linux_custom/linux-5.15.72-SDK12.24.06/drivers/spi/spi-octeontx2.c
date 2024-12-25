// SPDX-License-Identifier: GPL-2.0
/*
 * Marvell OcteonTX2 SPI driver.
 *
 * Copyright (C) 2018 Marvell International Ltd.
 */

#include <linux/acpi.h>
#include <linux/of.h>
#include <linux/delay.h>
#include <linux/module.h>
#include <linux/pci.h>
#include <linux/property.h>
#include <linux/spi/spi.h>
#ifdef CONFIG_ACPI
#include <linux/spi/spi-mem.h>
#endif

#include "spi-octeontx2.h"

#define DRV_NAME "spi-octeontx2"

#define TBI_FREQ 100000000 /* 100 Mhz */
#define SYS_FREQ_DEFAULT 700000000 /* 700 Mhz */

static int tbi_clk_en = 1;
module_param(tbi_clk_en, uint, 0644);
MODULE_PARM_DESC(tbi_clk_en,
		 "Use Fixed Time Base 100MHz Reference Clock (0=Disable, 1=Enable [default])");

static int cfg_mode_delay = 30;
module_param(cfg_mode_delay, uint, 0644);
MODULE_PARM_DESC(cfg_mode_delay,
		 "Delay in micro-seconds for mode change in MPI CFG register (30 [default])");

static void octeontx2_spi_wait_ready(struct octeontx2_spi *p)
{
	union mpix_sts mpi_sts;
	unsigned int loops = 0;

	mpi_sts.u64 = 0; /* Prevents infinite loop */
	do {
		if (loops++)
			__delay(500);
		mpi_sts.u64 = readq(p->register_base + OCTEONTX2_SPI_STS(p));
	} while (mpi_sts.s.busy);
}

static int octeontx2_spi_do_transfer(struct octeontx2_spi *p,
				     struct spi_message *msg,
				     struct spi_transfer *xfer,
				     bool last_xfer,
				     int cs)
{
	struct spi_device *spi = msg->spi;
	union mpix_cfg mpi_cfg;
	union mpix_xmit mpi_xmit;
	unsigned int clkdiv, calc_spd;
	int mode;
	bool cpha, cpol;
	const u8 *tx_buf;
	u8 *rx_buf;
	int len, rem;
	int i;
	void __iomem *wbuf_ptr = p->register_base + OCTEONTX2_SPI_WBUF(p);
	void __iomem *rx_ptr = wbuf_ptr;

	mode = spi->mode;
	cpha = mode & SPI_CPHA;
	cpol = mode & SPI_CPOL;

	clkdiv = p->sys_freq / (2 * xfer->speed_hz);
	/* Perform check to not exceed requested speed */
	while (1) {
		calc_spd = p->sys_freq / (2 * clkdiv);
		if (calc_spd <= xfer->speed_hz)
			break;
		clkdiv += 1;
	}

	if (clkdiv > 8191 || (!tbi_clk_en && clkdiv == 1)) {
		dev_err(&spi->dev,
			"can't support xfer->speed_hz %d for reference clock %d\n",
			xfer->speed_hz,	p->sys_freq);
		return -EINVAL;
	}

	mpi_cfg.u64 = 0;

	mpi_cfg.s.clkdiv = clkdiv;
	mpi_cfg.s.cshi = (mode & SPI_CS_HIGH) ? 1 : 0;
	mpi_cfg.s.lsbfirst = (mode & SPI_LSB_FIRST) ? 1 : 0;
	mpi_cfg.s.wireor = (mode & SPI_3WIRE) ? 1 : 0;
	mpi_cfg.s.idlelo = cpha != cpol;
	mpi_cfg.s.cslate = cpha ? 1 : 0;
	mpi_cfg.s.tritx = 1;
	mpi_cfg.s.enable = 1;
	mpi_cfg.s.cs_sticky = 1;
	mpi_cfg.s.legacy_dis = 1;
	if (tbi_clk_en)
		mpi_cfg.s.tb100_en = 1;

	/* Set x1 mode as default */
	mpi_cfg.s.iomode = 0;
	/* Set x2 mode if either tx or rx request dual */
	if (xfer->tx_nbits == SPI_NBITS_DUAL ||
	    xfer->rx_nbits == SPI_NBITS_DUAL)
		mpi_cfg.s.iomode = 2;
	/* Set x4 mode if either tx or rx request quad */
	if (xfer->tx_nbits == SPI_NBITS_QUAD ||
	    xfer->rx_nbits == SPI_NBITS_QUAD)
		mpi_cfg.s.iomode = 3;

	p->cs_enax |= (0xFull << 12);
	mpi_cfg.u64 |= p->cs_enax;

	if (mpi_cfg.u64 != p->last_cfg) {
		p->last_cfg = mpi_cfg.u64;
		writeq(mpi_cfg.u64, p->register_base + OCTEONTX2_SPI_CFG(p));
		mpi_cfg.u64 = readq(p->register_base + OCTEONTX2_SPI_CFG(p));
		udelay(cfg_mode_delay); /* allow CS change to settle */
	}
	tx_buf = xfer->tx_buf;
	rx_buf = xfer->rx_buf;
	len = xfer->len;

	/* Except T96 A0, use rcvdx register for x1 uni-directional mode */
	if (!mpi_cfg.s.iomode && p->rcvd_present)
		rx_ptr = p->register_base + OCTEONTX2_SPI_RCVD(p);

	while (len > OCTEONTX2_SPI_MAX_BYTES) {
		if (tx_buf) {
			/* 8 bytes per iteration */
			for (i = 0; i < OCTEONTX2_SPI_MAX_BYTES / 8; i++) {
				u64 data = *(uint64_t *)tx_buf;

				tx_buf += 8;
				writeq(data, wbuf_ptr + (8 * i));
			}
		}
		mpi_xmit.u64 = 0;
		mpi_xmit.s.csid = cs;
		mpi_xmit.s.leavecs = 1;
		mpi_xmit.s.txnum = tx_buf ? OCTEONTX2_SPI_MAX_BYTES : 0;
		mpi_xmit.s.totnum = OCTEONTX2_SPI_MAX_BYTES;
		writeq(mpi_xmit.u64, p->register_base + OCTEONTX2_SPI_XMIT(p));

		octeontx2_spi_wait_ready(p);
		if (rx_buf) {
			/* 8 bytes per iteration */
			for (i = 0; i < OCTEONTX2_SPI_MAX_BYTES / 8; i++) {
				u64 v;

				v = readq(rx_ptr + (8 * i));
				*(uint64_t *)rx_buf = v;
				rx_buf += 8;
			}
		}
		len -= OCTEONTX2_SPI_MAX_BYTES;
	}

	rem = len % 8;

	if (tx_buf) {
		u64 data;
		/* 8 bytes per iteration */
		for (i = 0; i < len / 8; i++) {
			data = *(uint64_t *)tx_buf;
			tx_buf += 8;
			writeq(data, wbuf_ptr + (8 * i));
		}
		/* remaining <8 bytes */
		if (rem) {
			data = 0;
			memcpy(&data, tx_buf, rem);
			writeq(data, wbuf_ptr + (8 * i));
		}
	}

	mpi_xmit.u64 = 0;
	mpi_xmit.s.csid = cs;
	if (last_xfer)
		mpi_xmit.s.leavecs = xfer->cs_change;
	else
		mpi_xmit.s.leavecs = !xfer->cs_change;
	mpi_xmit.s.txnum = tx_buf ? len : 0;
	mpi_xmit.s.totnum = len;
	writeq(mpi_xmit.u64, p->register_base + OCTEONTX2_SPI_XMIT(p));

	octeontx2_spi_wait_ready(p);
	if (rx_buf) {
		u64 v;
		/* 8 bytes per iteration */
		for (i = 0; i < len / 8; i++) {
			v = readq(rx_ptr + (8 * i));
			*(uint64_t *)rx_buf = v;
			rx_buf += 8;
		}
		/* remaining <8 bytes */
		if (rem) {
			v = readq(rx_ptr + (8 * i));
			memcpy(rx_buf, &v, rem);
			rx_buf += rem;
		}
	}

	spi_transfer_delay_exec(xfer);

	return xfer->len;
}

int octeontx2_spi_transfer_one_message(struct spi_master *master,
				       struct spi_message *msg)
{
	struct octeontx2_spi *p = spi_master_get_devdata(master);
	unsigned int total_len = 0;
	int status = 0;
	struct spi_transfer *xfer;
	int cs = msg->spi->chip_select;

	list_for_each_entry(xfer, &msg->transfers, transfer_list) {
		bool last_xfer = list_is_last(&xfer->transfer_list,
					      &msg->transfers);
		int r = octeontx2_spi_do_transfer(p, msg, xfer, last_xfer, cs);

		if (r < 0) {
			status = r;
			goto err;
		}
		total_len += r;
	}
err:
	msg->status = status;
	msg->actual_length = total_len;
	spi_finalize_current_message(master);
	return status;
}

#ifdef CONFIG_ACPI
static int octeontx2_spi_exec_op(struct spi_mem *mem,
				 const struct spi_mem_op *op)
{
	return -ENOTSUPP;
}

static bool octeontx2_spi_supports_op(struct spi_mem *mem,
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

static const struct spi_controller_mem_ops octeontx2_spi_mem_ops = {
	.supports_op = octeontx2_spi_supports_op,
	.exec_op = octeontx2_spi_exec_op
};
#endif

static int octeontx2_spi_probe(struct pci_dev *pdev,
			       const struct pci_device_id *ent)
{
	struct device *dev = &pdev->dev;
	struct spi_master *master;
	struct octeontx2_spi *p;
	union mpix_sts mpi_sts;
	int ret = -ENOENT;
	bool has_acpi;

	/* may need to hunt for devtree entry */
	if (!pdev->dev.of_node) {
		struct device_node *np = of_find_node_by_name(NULL, "spi");

		if (IS_ERR(np)) {
			ret = PTR_ERR(np);
			goto error;
		}
		pdev->dev.of_node = np;
		of_node_put(np);
	}

	has_acpi = has_acpi_companion(dev);

	master = spi_alloc_master(dev, sizeof(struct octeontx2_spi));
	if (!master)
		return -ENOMEM;

	p = spi_master_get_devdata(master);

	ret = pcim_enable_device(pdev);
	if (ret)
		goto error_put;

	ret = pci_request_regions(pdev, DRV_NAME);
	if (ret)
		goto error_disable;

	p->register_base = pcim_iomap(pdev, 0, pci_resource_len(pdev, 0));
	if (!p->register_base) {
		ret = -EINVAL;
		goto error_disable;
	}

	p->regs.config = 0x1000;
	p->regs.status = 0x1008;
	p->regs.xmit = 0x1018;
	p->regs.wbuf = 0x1800;
	p->regs.rcvd = 0x2800;
	p->last_cfg = 0x0;

	mpi_sts.u64 = readq(p->register_base + OCTEONTX2_SPI_STS(p));
	p->rcvd_present = mpi_sts.u64 & 0x4 ? true : false;

	if (!has_acpi) {
		/* FIXME: need a proper clocksource object for SCLK */
		p->clk = devm_clk_get(dev, NULL);
		if (IS_ERR(p->clk)) {
			p->clk = devm_clk_get(dev, "sclk");
			p->sys_freq = 0;
		} else {
			ret = clk_prepare_enable(p->clk);
			if (!ret)
				p->sys_freq = clk_get_rate(p->clk);
		}

		if (!p->sys_freq)
			p->sys_freq = SYS_FREQ_DEFAULT;
		if (tbi_clk_en)
			p->sys_freq = TBI_FREQ;
	} else {
		device_property_read_u32(dev, "sclk", &p->sys_freq);
		if (!p->sys_freq)
			p->sys_freq = TBI_FREQ;
	}
	dev_info(dev, "Reference clock is %u\n", p->sys_freq);

	master->num_chipselect = 4;
	master->mode_bits = SPI_CPHA | SPI_CPOL | SPI_CS_HIGH |
			    SPI_LSB_FIRST | SPI_3WIRE |
			    SPI_TX_DUAL | SPI_RX_DUAL |
			    SPI_TX_QUAD | SPI_RX_QUAD;
	master->transfer_one_message = octeontx2_spi_transfer_one_message;
	master->bits_per_word_mask = SPI_BPW_MASK(8);
	master->max_speed_hz = OCTEONTX2_SPI_MAX_CLOCK_HZ;
	master->dev.of_node = pdev->dev.of_node;
	master->dev.fwnode = pdev->dev.fwnode;
	#ifdef CONFIG_ACPI
		master->mem_ops = &octeontx2_spi_mem_ops;
	#endif

	pci_set_drvdata(pdev, master);

	ret = devm_spi_register_master(dev, master);
	if (ret)
		goto error_disable;

	return 0;

error_disable:
	if (!has_acpi)
		clk_disable_unprepare(p->clk);
error_put:
	spi_master_put(master);
error:
	return ret;
}

static void octeontx2_spi_remove(struct pci_dev *pdev)
{
	struct spi_master *master = pci_get_drvdata(pdev);
	struct octeontx2_spi *p;

	bool has_acpi = has_acpi_companion(&pdev->dev);

	p = spi_master_get_devdata(master);

	/* Put everything in a known state. */
	if (p) {
		if (!has_acpi)
			clk_disable_unprepare(p->clk);
		writeq(0, p->register_base + OCTEONTX2_SPI_CFG(p));
	}

	pci_disable_device(pdev);
	spi_master_put(master);
}

static const struct pci_device_id octeontx2_spi_pci_id_table[] = {
	{ PCI_DEVICE_SUB(PCI_VENDOR_ID_CAVIUM,
			 PCI_DEVID_OCTEONTX2_SPI,
			 PCI_VENDOR_ID_CAVIUM,
			 PCI_SUBSYS_DEVID_OTX2_98XX) },
	{ PCI_DEVICE_SUB(PCI_VENDOR_ID_CAVIUM,
			 PCI_DEVID_OCTEONTX2_SPI,
			 PCI_VENDOR_ID_CAVIUM,
			 PCI_SUBSYS_DEVID_OTX2_96XX) },
	{ PCI_DEVICE_SUB(PCI_VENDOR_ID_CAVIUM,
			 PCI_DEVID_OCTEONTX2_SPI,
			 PCI_VENDOR_ID_CAVIUM,
			 PCI_SUBSYS_DEVID_OTX2_95XX) },
	{ PCI_DEVICE_SUB(PCI_VENDOR_ID_CAVIUM,
			 PCI_DEVID_OCTEONTX2_SPI,
			 PCI_VENDOR_ID_CAVIUM,
			 PCI_SUBSYS_DEVID_OTX2_LOKI) },
	{ PCI_DEVICE_SUB(PCI_VENDOR_ID_CAVIUM,
			 PCI_DEVID_OCTEONTX2_SPI,
			 PCI_VENDOR_ID_CAVIUM,
			 PCI_SUBSYS_DEVID_OTX2_95MM) },

	{ 0, }
};

MODULE_DEVICE_TABLE(pci, octeontx2_spi_pci_id_table);

static struct pci_driver octeontx2_spi_driver = {
	.name		= DRV_NAME,
	.id_table	= octeontx2_spi_pci_id_table,
	.probe		= octeontx2_spi_probe,
	.remove		= octeontx2_spi_remove,
};

module_pci_driver(octeontx2_spi_driver);

MODULE_DESCRIPTION("OcteonTX2 SPI bus driver");
MODULE_AUTHOR("Marvell Inc.");
MODULE_LICENSE("GPL");
