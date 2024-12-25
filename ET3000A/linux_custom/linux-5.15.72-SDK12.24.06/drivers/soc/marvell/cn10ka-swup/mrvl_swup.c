// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2021 Marvell
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include <linux/miscdevice.h>
#include <linux/fs.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/arm-smccc.h>
#include <linux/uaccess.h>
#include <linux/ioctl.h>
#include <linux/slab.h>
#include <linux/bitops.h>
#include <linux/debugfs.h>
#include <linux/smp.h>
#include <linux/delay.h>

#include <linux/dma-mapping.h>
#include <linux/dmapool.h>
#include <linux/device.h>
#include <linux/gfp.h>

#include <soc/marvell/octeontx/octeontx_smc.h>
#include "mrvl_swup.h"

#include <linux/timekeeping.h>
#include <linux/ktime.h>

#define TO_VERSION_DESC(x) ((struct mrvl_get_versions *)(x))
#define TO_CLONE_DESC(x) ((struct mrvl_clone_fw *)(x))
#define TO_UPDATE_DESC(x) ((struct mrvl_update *)(x))
#define TO_PHYS_BUFFER(x) ((struct mrvl_phys_buffer *)(x))
#define TO_READ_FLASH_DESC(x) ((struct mrvl_read_flash *)(x))

static int alloc_buffers(struct memory_desc *memdesc, uint32_t required_buf);
static void free_buffers(void);

/*Debugfs interface root */;
struct dentry *mrvl_swup_root;

/*Device*/
static struct device dev;

/* Buffers for SMC call
 * 0 -> 25MB for SW update CPIO blob
 * 1 -> 1MB for passing data structures
 */
#define BUF_CPIO 0
#define BUF_DATA 1
#define BUF_SIGNATURE 2
#define BUF_READ 3
#define BUF_LOG 4
#define BUF_SMCLOG 5
#define BUF_WORK 6
#define BUF_COUNT 7
static struct memory_desc memdesc[BUF_COUNT] = {
	{0, 0, 32*1024*1024, "cpio buffer"},
	{0, 0, 1*1024*1024,  "data buffer"},
	{0, 0, 1*1024*1024,  "signature buffer"},
	{0, 0, 32*1024*1024, "read buffer"},
	{0, 0, 1*1024*1024,  "log buffer"},
	{0, 0, 1*1024*1024,  "smclog buffer"},
	{0, 0, 0,            "work buffer"},
};

/* IOCTL mapping to fw name */
static const struct {
	const char *str;
	uint8_t bit;
} name_to_sel_obj[] = {
	{"tim0", 0},
	{"gserp-cn10xx.fw", 1},
	{"scp_bl1.bin", 2},
	{"mcp_bl1.bin", 3},
	{"ecp_bl1.bin", 4},
	{"init.bin", 5},
	{"gserm-cn10xx.fw", 6},
	{"bl2.bin", 7},
	{"bl31.bin", 8},
	{"u-boot-nodtb.bin", 9},
	{"npc_mkex-cn10xx.fw", 10},
	{"efi_app1.efi", 11},
	{"switch_fw_ap.fw", 12},
	{"switch_fw_super.fw", 13},
};

static const char *obj_bit_to_str(uint32_t bit)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(name_to_sel_obj); i++) {
		if (name_to_sel_obj[i].bit == bit)
			return name_to_sel_obj[i].str;
	}
	return NULL;
}

/* Prepare objects for limited read */
static void prepare_names(struct smc_version_info *info, uint32_t objects)
{
	int i;
	int obj_count = 0;
	const char *tmp = NULL;

	for (i = 0; i < SMC_MAX_VERSION_ENTRIES; i++) {
		if (objects & (1<<i)) {
			tmp = obj_bit_to_str((i));
			if (tmp == NULL) {
				pr_info("incorrect object selected!\n");
			} else {
				memcpy(info->objects[obj_count].name, tmp, VER_MAX_NAME_LENGTH);
				obj_count++;
			}
		}
	}
}

struct arm_smccc_res mrvl_exec_smc(uint64_t smc, uint64_t buf, uint64_t size)
{
	struct arm_smccc_res res;

	arm_smccc_smc(smc, buf, size, 0, 0, 0, 0, 0, &res);
	return res;
}

static enum smc_version_entry_retcode mrvl_get_version(unsigned long arg, uint8_t calculate_hash)
{
	int i, ret = 0;
	struct mrvl_get_versions *user_desc;
	struct arm_smccc_res res;
	struct smc_version_info *swup_info = (struct smc_version_info *)memdesc[BUF_DATA].virt;
	int spi_in_progress = 0;

	memset(memdesc[BUF_LOG].virt, 0x00, memdesc[BUF_LOG].size);
	res = mrvl_exec_smc(PLAT_OCTEON_SET_FIRMWARE_LOGGING,
			    memdesc[BUF_LOG].phys,
			    memdesc[BUF_LOG].size);
	if (res.a0)
		pr_err("Failed to enable firmware logging\n");

	user_desc = kzalloc(sizeof(*user_desc), GFP_KERNEL);
	if (!user_desc) {
		mrvl_exec_smc(PLAT_OCTEON_CLEAR_FIRMWARE_LOGGING, 0, 0);
		return -ENOMEM;
	}

	if (copy_from_user(user_desc,
			  TO_VERSION_DESC(arg),
			  sizeof(*user_desc))) {
		pr_err("Data Read Error\n");
		ret = -EFAULT;
		goto mem_error;
	}

	pr_info("Version request: SPI: %d, CS: %d, Objects: %x, Timeout: %lld, Flags: %x/%llx\n",
							user_desc->bus,
							user_desc->cs,
							user_desc->selected_objects,
							user_desc->timeout,
							user_desc->version_flags,
							user_desc->compatibility_flags);

	/* We have to perform conversion from IOCTL interface to smc */
	memset(swup_info, 0x00, sizeof(*swup_info));

	swup_info->magic_number = VERSION_MAGIC;
	swup_info->version      = VERSION_INFO_VERSION;
	swup_info->bus          = user_desc->bus;
	swup_info->cs           = user_desc->cs;
	swup_info->timeout      = user_desc->timeout;

	if (calculate_hash)
		swup_info->version_flags |= SMC_VERSION_CHECK_VALIDATE_HASH;

	if (user_desc->version_flags & MARLIN_CHECK_PREDEFINED_OBJ) {
		swup_info->version_flags |= SMC_VERSION_CHECK_SPECIFIC_OBJECTS;
		prepare_names(swup_info, user_desc->selected_objects);
		swup_info->num_objects = hweight_long(user_desc->selected_objects);
	} else {
		swup_info->num_objects = SMC_MAX_OBJECTS;
	}

	if (user_desc->version_flags & MARLIN_FORCE_ASYNC)
		swup_info->version_flags |= SMC_VERSION_ASYNC_HASH;

	if (user_desc->version_flags & MARLIN_DEBUG)
		swup_info->version_flags |= SMC_VERSION_DEBUG;

	swup_info->version_flags |= SMC_VERSION_LOG_PROGRESS;

	/* Buffer for ATF logs */
	memset(memdesc[BUF_SMCLOG].virt, 0x00, memdesc[BUF_SMCLOG].size);
	swup_info->output_console = memdesc[BUF_SMCLOG].phys;
	swup_info->output_console_size = memdesc[BUF_SMCLOG].size;

	if (user_desc->compatibility_flags & VERSION_COMPAT_FLAG_USE_OLD_VERSION_BEFORE_LOG) {
		swup_info->version = VERSION_OLD_VERSION_BEFORE_LOG;
	}

	res = mrvl_exec_smc(PLAT_CN10K_VERIFY_FIRMWARE,
			    memdesc[BUF_DATA].phys,
			    sizeof(struct smc_version_info));

	if (res.a0) {
		pr_err("Error during SMC processing\n");
		ret = res.a0;
		goto mem_error;
	}

	do {
		msleep(500);
		res = mrvl_exec_smc(PLAT_CN10K_ASYNC_STATUS, 0, 0);
		spi_in_progress = res.a0;
	} while (spi_in_progress);

	user_desc->retcode = swup_info->retcode;
	for (i = 0; i < SMC_MAX_VERSION_ENTRIES; i++)
		memcpy(&user_desc->desc[i],
		       &swup_info->objects[i],
		       sizeof(struct smc_version_info_entry));

	if (copy_to_user(TO_VERSION_DESC(arg),
			user_desc,
			sizeof(*user_desc))) {
		pr_err("Data Write Error\n");
		ret = -EFAULT;
	}

mem_error:
	mrvl_exec_smc(PLAT_OCTEON_CLEAR_FIRMWARE_LOGGING, 0, 0);
	kfree(user_desc);
	return ret;
}

static int mrvl_clone_fw(unsigned long arg)
{
	int i, ret = 0;
	struct mrvl_clone_fw *user_desc;
	struct arm_smccc_res res;
	struct smc_version_info *swup_info = (struct smc_version_info *)memdesc[BUF_DATA].virt;
	int spi_in_progress = 0;

	memset(memdesc[BUF_LOG].virt, 0x00, memdesc[BUF_LOG].size);
	res = mrvl_exec_smc(PLAT_OCTEON_SET_FIRMWARE_LOGGING,
			    memdesc[BUF_LOG].phys,
			    memdesc[BUF_LOG].size);
	if (res.a0)
		pr_err("Failed to enable firmware logging\n");

	user_desc = kzalloc(sizeof(*user_desc), GFP_KERNEL);
	if (!user_desc) {
		mrvl_exec_smc(PLAT_OCTEON_CLEAR_FIRMWARE_LOGGING, 0, 0);
		return -ENOMEM;
	}

	if (copy_from_user(user_desc,
			  TO_CLONE_DESC(arg),
			  sizeof(*user_desc))) {
		pr_err("Data Read Error\n");
		ret = -EFAULT;
		goto mem_error;
	}

	pr_info("Clone request: SPI: %d->%d, CS: %d->%d, Op: %d, Objects: %x, Flags: %x/%llx\n",
							user_desc->bus, user_desc->target_bus,
							user_desc->cs, user_desc->target_cs,
							user_desc->clone_op,
							user_desc->selected_objects,
							user_desc->version_flags,
							user_desc->compatibility_flags);

	memset(swup_info, 0x00, sizeof(*swup_info));

	swup_info->magic_number = VERSION_MAGIC;
	swup_info->version      = VERSION_INFO_VERSION;
	swup_info->bus = user_desc->bus;
	swup_info->cs = user_desc->cs;
	swup_info->version_flags |= SMC_VERSION_CHECK_VALIDATE_HASH;

	if (user_desc->version_flags & MARLIN_FORCE_CLONE)
		swup_info->version_flags |= SMC_VERSION_FORCE_COPY_OBJECTS;

	if (user_desc->version_flags & MARLIN_FORCE_ASYNC)
		swup_info->version_flags |= SMC_VERSION_ASYNC_HASH;

	if (user_desc->version_flags & MARLIN_CHECK_PREDEFINED_OBJ) {
		swup_info->version_flags |= SMC_VERSION_CHECK_SPECIFIC_OBJECTS;
		prepare_names(swup_info, user_desc->selected_objects);
		swup_info->num_objects = hweight_long(user_desc->selected_objects);
	} else {
		swup_info->num_objects = SMC_MAX_OBJECTS;
	}

	if (user_desc->version_flags & MARLIN_SKIP_FAIL_CLONE_CHECK)
		swup_info->version_flags |= SMC_VERSION_SKIP_FAIL_CHECK;

	if (!(user_desc->version_flags & MARLIN_SKIP_EBF_ERASE))
		swup_info->version_flags |= SMC_VERSION_ERASE_EBF_CONFIG;

	switch (user_desc->clone_op) {
	case CLONE_SPI:
		swup_info->target_bus = user_desc->target_bus;
		swup_info->target_cs = user_desc->target_cs;
		swup_info->version_flags |= SMC_VERSION_COPY_TO_BACKUP_FLASH;
		break;
	case CLONE_MMC:
		swup_info->version_flags |= SMC_VERSION_COPY_TO_BACKUP_EMMC;
		break;
	case CLONE_OFFSET:
		swup_info->version_flags |= SMC_VERSION_COPY_TO_BACKUP_OFFSET;
		break;
	default:
		pr_err("Incorrect clone parameter.\n");
		goto mem_error;
	}

	swup_info->version_flags |= SMC_VERSION_LOG_PROGRESS;

	/* Buffer for ATF logs */
	memset(memdesc[BUF_SMCLOG].virt, 0x00, memdesc[BUF_SMCLOG].size);
	swup_info->output_console = memdesc[BUF_SMCLOG].phys;
	swup_info->output_console_size = memdesc[BUF_SMCLOG].size;

	if (user_desc->compatibility_flags & VERSION_COMPAT_FLAG_USE_OLD_VERSION_BEFORE_LOG)
		swup_info->version = VERSION_OLD_VERSION_BEFORE_LOG;

	res = mrvl_exec_smc(PLAT_CN10K_VERIFY_FIRMWARE,
			    memdesc[BUF_DATA].phys,
			    sizeof(struct smc_version_info));

	if (res.a0) {
		pr_err("Error during SMC processing\n");
		ret = res.a0;
		goto mem_error;
	}

	do {
		msleep(500);
		res = mrvl_exec_smc(PLAT_CN10K_ASYNC_STATUS, 0, 0);
		spi_in_progress = res.a0;
	} while (spi_in_progress);

	user_desc->retcode = swup_info->retcode;
	for (i = 0; i < SMC_MAX_VERSION_ENTRIES; i++)
		memcpy(&user_desc->desc[i],
		       &swup_info->objects[i],
		       sizeof(struct smc_version_info_entry));

	if (copy_to_user(TO_CLONE_DESC(arg),
			user_desc,
			sizeof(*user_desc))) {
		pr_err("Data Write Error\n");
		ret = -EFAULT;
	}

mem_error:
	mrvl_exec_smc(PLAT_OCTEON_CLEAR_FIRMWARE_LOGGING, 0, 0);
	kfree(user_desc);
	return ret;
}

static int mrvl_get_membuf(unsigned long arg)
{
	struct mrvl_phys_buffer buf;

	pr_info("Get memory buffer request\n");

	buf.cpio_buf = memdesc[BUF_CPIO].phys;
	buf.cpio_buf_size = memdesc[BUF_CPIO].size;
	buf.sign_buf = memdesc[BUF_SIGNATURE].phys;
	buf.sign_buf_size = memdesc[BUF_SIGNATURE].size;
	buf.log_buf = memdesc[BUF_LOG].phys;
	buf.log_buf_size = memdesc[BUF_LOG].size;
	buf.smclog_buf = memdesc[BUF_SMCLOG].phys;
	buf.smclog_buf_size = memdesc[BUF_SMCLOG].size;
	buf.read_buf = memdesc[BUF_READ].phys;
	buf.read_buf_size = memdesc[BUF_READ].size;

	if (copy_to_user(TO_PHYS_BUFFER(arg),
			  &buf,
			  sizeof(buf))) {
		pr_err("Data Write Error\n");
		return -EFAULT;
	}
	return 0;
}

static int mrvl_run_fw_update(unsigned long arg)
{
	struct mrvl_update ioctl_desc = {0};
	struct smc_update_descriptor *smc_desc;
	struct arm_smccc_res res, res_update;
	int spi_in_progress = 0;

	ktime_t tstart, tsyncend, tend;

	memset(memdesc[BUF_LOG].virt, 0x00, memdesc[BUF_LOG].size);
	res = mrvl_exec_smc(PLAT_OCTEON_SET_FIRMWARE_LOGGING,
			    memdesc[BUF_LOG].phys,
			    memdesc[BUF_LOG].size);
	if (res.a0) {
		pr_err("Failed to enable firmware logging\n");
	}

	smc_desc = (struct smc_update_descriptor *)memdesc[BUF_DATA].virt;
	memset(smc_desc, 0x00, sizeof(*smc_desc));

	if (copy_from_user(&ioctl_desc,
			  TO_UPDATE_DESC(arg),
			  sizeof(ioctl_desc))) {
		pr_err("Data Read Error\n");
		mrvl_exec_smc(PLAT_OCTEON_CLEAR_FIRMWARE_LOGGING, 0, 0);
		return -EFAULT;
	}

	pr_info("Update request: SPI: %d, CS: %d, Image Size: %llx, User Size: %llx, Timeout: %d, Flags: %llx/%llx/%llx\n",
							ioctl_desc.bus,
							ioctl_desc.cs,
							ioctl_desc.image_size,
							ioctl_desc.user_size,
							ioctl_desc.timeout,
							ioctl_desc.flags,
							ioctl_desc.user_flags,
							ioctl_desc.compatibility_flags);

	/*Verify data size*/
	if (ioctl_desc.image_size > memdesc[BUF_CPIO].size) {
		pr_err("Incorrect CPIO data size\n");
		mrvl_exec_smc(PLAT_OCTEON_CLEAR_FIRMWARE_LOGGING, 0, 0);
		return -EFAULT;
	}

	/* Verify userdata */
	if (ioctl_desc.user_size > memdesc[BUF_SIGNATURE].size) {
		pr_err("Incorrect user data size\n");
		mrvl_exec_smc(PLAT_OCTEON_CLEAR_FIRMWARE_LOGGING, 0, 0);
		return -EFAULT;
	}

	smc_desc->magic      = UPDATE_MAGIC;
	smc_desc->version    = UPDATE_VERSION;

	/* Set addresses and flags*/
	smc_desc->image_addr = memdesc[BUF_CPIO].phys;
	smc_desc->image_size = ioctl_desc.image_size;
	if (ioctl_desc.user_size != 0) {
		smc_desc->user_addr = memdesc[BUF_SIGNATURE].phys;
		smc_desc->user_size = ioctl_desc.user_size;
	}
	smc_desc->user_flags = ioctl_desc.user_flags;
	smc_desc->update_flags = ioctl_desc.flags | UPDATE_FLAG_LOG_PROGRESS;

	/* Buffer for ATF logs */
	memset(memdesc[BUF_SMCLOG].virt, 0x00, memdesc[BUF_SMCLOG].size);
	smc_desc->output_console = memdesc[BUF_SMCLOG].phys;
	smc_desc->output_console_size = memdesc[BUF_SMCLOG].size;

	/* In linux use asynchronus SPI operation */
	smc_desc->async_spi = 1;

	/* SPI config */
	smc_desc->bus        = ioctl_desc.bus;
	smc_desc->cs	     = ioctl_desc.cs;

	/* Use full async update*/
	smc_desc->retcode = 0x01;

	tstart = ktime_get();
	if (ioctl_desc.compatibility_flags & UPDATE_COMPAT_FLAG_USE_OLD_VERSION_BEFORE_LOG) {
		smc_desc->version = UPDATE_VERSION_PREV;
		res_update = mrvl_exec_smc(PLAT_OCTEONTX_SPI_SECURE_UPDATE,
			    memdesc[BUF_DATA].phys,
			    sizeof(struct smc_update_descriptor_prev));
	} else {
		res_update = mrvl_exec_smc(PLAT_OCTEONTX_SPI_SECURE_UPDATE,
			    memdesc[BUF_DATA].phys,
			    sizeof(struct smc_update_descriptor));
	}

	tsyncend = ktime_get();
	do {
		msleep(500);
		res = mrvl_exec_smc(PLAT_CN10K_ASYNC_STATUS, 0, 0);
		spi_in_progress = res.a0;
	} while (spi_in_progress);

	/* Detect if ATF will use async operations
	 * ATF without full async support won't modify
	 * smc_desc->retcode field
	 */

	if (smc_desc->retcode == 0x01) {
		pr_info("ATF - partial async enabled\n");
		ioctl_desc.ret = res_update.a1;
	} else {
		pr_info("ATF - full async enabled\n");
		ioctl_desc.ret = smc_desc->retcode;
	}


	if (copy_to_user(TO_UPDATE_DESC(arg),
			 &ioctl_desc,
			 sizeof(ioctl_desc))) {
		pr_err("Data Write Error\n");
		mrvl_exec_smc(PLAT_OCTEON_CLEAR_FIRMWARE_LOGGING, 0, 0);
		return -EFAULT;
	}

	tend = ktime_get();

	pr_info("Tsync: %lld, ttot: %lld\n", tsyncend - tstart, tend - tstart);

	mrvl_exec_smc(PLAT_OCTEON_CLEAR_FIRMWARE_LOGGING, 0, 0);
	return ioctl_desc.ret;
}

static int mrvl_read_flash_data(unsigned long arg)
{
	struct mrvl_read_flash ioctl_desc = {0};
	struct smc_read_flash_descriptor *smc_desc;
	struct arm_smccc_res res;
	int spi_in_progress = 0;

	memset(memdesc[BUF_LOG].virt, 0x00, memdesc[BUF_LOG].size);
	res = mrvl_exec_smc(PLAT_OCTEON_SET_FIRMWARE_LOGGING,
			    memdesc[BUF_LOG].phys,
			    memdesc[BUF_LOG].size);
	if (res.a0)
		pr_err("Failed to enable firmware logging\n");

	if (copy_from_user(&ioctl_desc,
			  TO_READ_FLASH_DESC(arg),
			  sizeof(ioctl_desc))) {
		pr_err("Data Read Error\n");
		mrvl_exec_smc(PLAT_OCTEON_CLEAR_FIRMWARE_LOGGING, 0, 0);
		return -EFAULT;
	}

	smc_desc = (struct smc_read_flash_descriptor *)memdesc[BUF_DATA].virt;
	memset(smc_desc, 0x00, sizeof(*smc_desc));

	pr_info("Read request: SPI: %d, CS: %d, Offset: %llx, Length: %llx, Flags: %llx/%llx\n",
							ioctl_desc.bus,
							ioctl_desc.cs,
							ioctl_desc.offset,
							ioctl_desc.len,
							ioctl_desc.ioctl_flags,
							ioctl_desc.compatibility_flags);

	smc_desc->version = READ_VERSION;

	/* Set location and length */
	smc_desc->offset = ioctl_desc.offset;
	smc_desc->length = ioctl_desc.len;

	/* In linux use asynchronous SPI operation */
	smc_desc->async_spi = 1;

	/* enable ATF logs */
	smc_desc->read_flags = READ_FLAG_LOG_PROGRESS;
	memset(memdesc[BUF_SMCLOG].virt, 0x00, memdesc[BUF_SMCLOG].size);
	smc_desc->output_console = memdesc[BUF_SMCLOG].phys;
	smc_desc->output_console_size = memdesc[BUF_SMCLOG].size;

	if (ioctl_desc.ioctl_flags & READ_IOCTL_FLAG_DEBUG)
		smc_desc->read_flags |= READ_FLAG_DEBUG;

	/* SPI config */
	smc_desc->bus        = ioctl_desc.bus;
	smc_desc->cs	     = ioctl_desc.cs;
	smc_desc->addr       = memdesc[BUF_READ].phys;

	if (ioctl_desc.compatibility_flags & READ_COMPAT_FLAG_USE_OLD_VERSION_BEFORE_LOG) {
		smc_desc->version = READ_VERSION_PREV;
		res = mrvl_exec_smc(PLAT_CN10K_SPI_READ_FLASH,
			    memdesc[BUF_DATA].phys,
			    sizeof(struct smc_read_flash_descriptor_prev));
	} else {
		res = mrvl_exec_smc(PLAT_CN10K_SPI_READ_FLASH,
			    memdesc[BUF_DATA].phys,
			    sizeof(struct smc_read_flash_descriptor));
	}

	ioctl_desc.ret = res.a0;
	if (copy_to_user(TO_READ_FLASH_DESC(arg),
			 &ioctl_desc,
			 sizeof(ioctl_desc))) {
		pr_err("Data Write Error\n");
		mrvl_exec_smc(PLAT_OCTEON_CLEAR_FIRMWARE_LOGGING, 0, 0);
		return -EFAULT;
	}

	do {
		msleep(500);
		res = mrvl_exec_smc(PLAT_CN10K_ASYNC_STATUS, 0, 0);
		spi_in_progress = res.a0;
	} while (spi_in_progress);


	mrvl_exec_smc(PLAT_OCTEON_CLEAR_FIRMWARE_LOGGING, 0, 0);
	return 0;
}

static void mrvl_free_rd_buf(unsigned long arg)
{
	free_buffers();
}

static long mrvl_swup_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	int ret;

	switch (cmd) {
	case GET_VERSION:
	case VERIFY_HASH:
	case CLONE_FW:
		ret = alloc_buffers(memdesc, BIT(BUF_DATA) | BIT(BUF_LOG) | BIT(BUF_SMCLOG));
		break;
	case GET_MEMBUF:
		ret = alloc_buffers(memdesc, BIT(BUF_DATA) | BIT(BUF_SIGNATURE) | BIT(BUF_CPIO) |
					     BIT(BUF_LOG) | BIT(BUF_SMCLOG));
		break;
	case READ_FLASH:
		ret = alloc_buffers(memdesc, BIT(BUF_DATA) | BIT(BUF_READ) | BIT(BUF_LOG) |
					     BIT(BUF_SMCLOG));
		break;
	case RUN_UPDATE:
	case FREE_RD_BUF:
		ret = 0;
		break;
	default:
		ret = -ENXIO; /* Illegal cmd */
		break;
	}

	if (ret)
		return ret;

	switch (cmd) {
	case GET_VERSION:
		ret = mrvl_get_version(arg, 0);
		break;
	case VERIFY_HASH:
		ret = mrvl_get_version(arg, 1);
		break;
	case GET_MEMBUF:
		ret = mrvl_get_membuf(arg);
		break;
	case RUN_UPDATE:
		ret = mrvl_run_fw_update(arg);
		break;
	case CLONE_FW:
		ret = mrvl_clone_fw(arg);
		break;
	case READ_FLASH:
		ret = mrvl_read_flash_data(arg);
		break;
	case FREE_RD_BUF:
		mrvl_free_rd_buf(arg);
		break;
	case FREE_ALL_BUF:
		free_buffers();
		break;
	default:
		pr_err("Not supported IOCTL\n");
		return -ENXIO;
	}
	return ret;
}

static const struct file_operations mrvl_fops = {
	.owner			= THIS_MODULE,
	.unlocked_ioctl		= mrvl_swup_ioctl,
	.llseek			= no_llseek,
};

static int alloc_buffers(struct memory_desc *memdesc, uint32_t required_buf)
{
	int i = 0, j, ret = 0;

	for (j = 0; j < BUF_COUNT; j++) {
		if (required_buf == 0)
			break;

		for (i = 0; i < BUF_COUNT; i++) {
			if (required_buf & BIT(i)) {
				required_buf &= ~(BIT(i));
				break;
			}
		}

		if (memdesc[i].virt != NULL)
			continue;

		memdesc[i].virt = dma_alloc_coherent(&dev, memdesc[i].size,
						     &memdesc[i].phys, GFP_KERNEL);

		if (!memdesc[i].virt) {
			pr_err("Failed to alloc for %s\n", memdesc[i].pool_name);
			ret = -ENOMEM;
			break;
		}

		memset(memdesc[i].virt, 0x00, memdesc[i].size);
	}

	for (j = 0; j < BUF_COUNT; j++)
		pr_info("Pool: %s virt: %llx, phys: %llx, size: 0x%llx\n",
			memdesc[j].pool_name,
			(uint64_t)memdesc[j].virt,
			(uint64_t)memdesc[j].phys,
			memdesc[j].size);

	return ret;
}


/* As we are going to use CMA buffers do not deallocate here */
static void free_buffers(void)
{

}

static int mrvl_swup_setup_debugfs(void)
{
	struct dentry *pfile;

	mrvl_swup_root = debugfs_create_dir("cn10k_swup", NULL);

	pfile = debugfs_create_file("verification", 0644, mrvl_swup_root, NULL,
				    &mrvl_fops);
	if (!pfile)
		goto create_failed;

	return 0;

create_failed:
	pr_err("Failed to create debugfs dir/file for firmware update\n");
	debugfs_remove_recursive(mrvl_swup_root);
	return 1;
}

static int __init mrvl_swup_init(void)
{
	int ret;

	ret = octeontx_soc_check_smc();
	if (ret != 2) {
		pr_debug("%s: Not supported\n", __func__);
		return -EPERM;
	}

	dev_set_name(&dev, "mrvl_swup_dev");
	ret = device_register(&dev);

	if (ret) {
		pr_err("Failed to register device\n");
		return ret;
	}

	/* Will not be used bt any HW, so use mask with ones only */
	dev.coherent_dma_mask = ~0;

	return mrvl_swup_setup_debugfs();
}

static void __exit mrvl_swup_exit(void)
{
	debugfs_remove_recursive(mrvl_swup_root);
}

module_init(mrvl_swup_init)
module_exit(mrvl_swup_exit)

MODULE_DESCRIPTION("Marvell firmware update");
MODULE_AUTHOR("Witold Sadowski <wsadowski@marvell.com>");
MODULE_LICENSE("GPL");
