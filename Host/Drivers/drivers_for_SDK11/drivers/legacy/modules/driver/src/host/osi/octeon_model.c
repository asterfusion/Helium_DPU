/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2021 Marvell.
 */
#include <linux/types.h>
#include <linux/string.h>
#include "octeon_hw.h"
#include "octeon_model.h"

struct octeon_model octeon_model;

/* SoC and CPU IDs and revisions */
#define VENDOR_ARM    0x41 /* 'A' */
#define VENDOR_CAVIUM 0x43 /* 'C' */

#define SOC_PART_CN10K 0xD49

#define PART_106xx  0xB9
#define PART_105xx  0xBA
#define PART_105xxN 0xBC
#define PART_103xx  0xBD
#define PART_98xx   0xB1
#define PART_96xx   0xB2
#define PART_95xx   0xB3
#define PART_95xxN  0xB4
#define PART_95xxMM 0xB5
#define PART_95O    0xB6

#define MODEL_IMPL_BITS	  8
#define MODEL_IMPL_SHIFT  24
#define MODEL_IMPL_MASK	  ((1 << MODEL_IMPL_BITS) - 1)
#define MODEL_PART_BITS	  12
#define MODEL_PART_SHIFT  4
#define MODEL_PART_MASK	  ((1 << MODEL_PART_BITS) - 1)
#define MODEL_MAJOR_BITS  4
#define MODEL_MAJOR_SHIFT 20
#define MODEL_MAJOR_MASK  ((1 << MODEL_MAJOR_BITS) - 1)
#define MODEL_MINOR_BITS  4
#define MODEL_MINOR_SHIFT 0
#define MODEL_MINOR_MASK  ((1 << MODEL_MINOR_BITS) - 1)

#define MODEL_CN10K_PART_SHIFT	8
#define MODEL_CN10K_PASS_BITS	4
#define MODEL_CN10K_PASS_MASK	((1 << MODEL_CN10K_PASS_BITS) - 1)
#define MODEL_CN10K_MAJOR_BITS	2
#define MODEL_CN10K_MAJOR_SHIFT 2
#define MODEL_CN10K_MAJOR_MASK	((1 << MODEL_CN10K_MAJOR_BITS) - 1)
#define MODEL_CN10K_MINOR_BITS	2
#define MODEL_CN10K_MINOR_SHIFT 0
#define MODEL_CN10K_MINOR_MASK	((1 << MODEL_CN10K_MINOR_BITS) - 1)

const struct model_db {
	uint32_t impl;
	uint32_t part;
	uint32_t major;
	uint32_t minor;
	uint64_t flag;
	char name[OCTEON_MODEL_STR_LEN_MAX];
} model_db[] = {
	{VENDOR_ARM, PART_106xx, 0, 0, OCTEON_MODEL_CN106xx_A0, "cn10ka_a0"},
	{VENDOR_ARM, PART_106xx, 0, 1, OCTEON_MODEL_CN106xx_A1, "cn10ka_a1"},
	{VENDOR_ARM, PART_105xx, 0, 0, OCTEON_MODEL_CNF105xx_A0, "cnf10ka_a0"},
	{VENDOR_ARM, PART_105xx, 0, 1, OCTEON_MODEL_CNF105xx_A1, "cnf10ka_a1"},
	{VENDOR_ARM, PART_103xx, 0, 0, OCTEON_MODEL_CN103xx_A0, "cn10kb_a0"},
	{VENDOR_ARM, PART_105xxN, 0, 0, OCTEON_MODEL_CNF105xxN_A0, "cnf10kb_a0"},
	{VENDOR_CAVIUM, PART_98xx, 0, 0, OCTEON_MODEL_CN98xx_A0, "cn98xx_a0"},
	{VENDOR_CAVIUM, PART_98xx, 0, 1, OCTEON_MODEL_CN98xx_A1, "cn98xx_a1"},
	{VENDOR_CAVIUM, PART_96xx, 0, 0, OCTEON_MODEL_CN96xx_A0, "cn96xx_a0"},
	{VENDOR_CAVIUM, PART_96xx, 0, 1, OCTEON_MODEL_CN96xx_B0, "cn96xx_b0"},
	{VENDOR_CAVIUM, PART_96xx, 2, 0, OCTEON_MODEL_CN96xx_C0, "cn96xx_c0"},
	{VENDOR_CAVIUM, PART_96xx, 2, 1, OCTEON_MODEL_CN96xx_C0, "cn96xx_c1"},
	{VENDOR_CAVIUM, PART_95xx, 0, 0, OCTEON_MODEL_CNF95xx_A0, "cnf95xx_a0"},
	{VENDOR_CAVIUM, PART_95xx, 1, 0, OCTEON_MODEL_CNF95xx_B0, "cnf95xx_b0"},
	{VENDOR_CAVIUM, PART_95xxN, 0, 0, OCTEON_MODEL_CNF95xxN_A0, "cnf95xxn_a0"},
	{VENDOR_CAVIUM, PART_95xxN, 0, 1, OCTEON_MODEL_CNF95xxN_A0, "cnf95xxn_a1"},
	{VENDOR_CAVIUM, PART_95xxN, 1, 0, OCTEON_MODEL_CNF95xxN_B0, "cnf95xxn_b0"},
	{VENDOR_CAVIUM, PART_95O, 0, 0, OCTEON_MODEL_CNF95xxO_A0, "cnf95O_a0"},
	{VENDOR_CAVIUM, PART_95xxMM, 0, 0, OCTEON_MODEL_CNF95xxMM_A0,
	 "cnf95xxmm_a0"}};

static int
populate_model(struct octeon_model *model, uint64_t midr)
{
	uint32_t impl, major, part, minor, size;
	int found = 0;
	size_t i;

	impl = (midr >> MODEL_IMPL_SHIFT) & MODEL_IMPL_MASK;
	part = (midr >> MODEL_PART_SHIFT) & MODEL_PART_MASK;
	major = (midr >> MODEL_MAJOR_SHIFT) & MODEL_MAJOR_MASK;
	minor = (midr >> MODEL_MINOR_SHIFT) & MODEL_MINOR_MASK;

	size = (sizeof(model_db) / sizeof((model_db)[0]));
	for (i = 0; i < size; i++)
		if (model_db[i].impl == impl && model_db[i].part == part &&
		    model_db[i].major == major && model_db[i].minor == minor) {
			model->flag = model_db[i].flag;
			strncpy(model->name, model_db[i].name,
				OCTEON_MODEL_STR_LEN_MAX - 1);
			found = true;
			break;
		}
	if (!found) {
		model->flag = 0;
		strncpy(model->name, "unknown", OCTEON_MODEL_STR_LEN_MAX - 1);
		cavium_print_msg("Invalid Oct model impl=0x%x, part=0x%x, major=0x%x, minor=0x%x\n",
			impl, part, major, minor);
	}

	return found;
}

static uint64_t
get_main_id_register_val(octeon_device_t *oct)
{
	uint64_t addr, reg_val;

	addr = (MAIN_ID_REG_ADDRESS | (2ull << 53));
	OCTEON_WRITE64(oct->reg_list.pci_win_rd_addr, addr);
	reg_val = OCTEON_READ64(oct->reg_list.pci_win_rd_data);
	return reg_val;
}

int octeon_model_info(struct octeon_model *model, octeon_device_t *oct)
{
	int rc = -1;
	uint64_t main_id;

	if (!model || !oct)
		goto err;

	main_id = get_main_id_register_val(oct);
	if (!populate_model(model, main_id))
		goto err;
	rc = 0;
err:
	return rc;
}
