/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2022 Marvell.
 */

#include <rte_bitops.h>
#include <rte_common.h>
#include <rte_cycles.h>
#include <rte_eal.h>
#include <rte_io.h>
#include <rte_rawdev.h>

#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "bphy_irq.h"
#include "../../../drivers/raw/cnxk_bphy/rte_pmd_bphy.h"

struct bphy_test {
	int irq_num;
	cnxk_bphy_intr_handler_t handler;
	void *data;
	int cpu;
	bool handled;
	int handled_data;
	int handled_irq;
	int test_data;
};

static struct bphy_test test;

struct irq_def {
	uint64_t ena_w1c;
	uint64_t ena_w1s;
	uint64_t sum_w1s;
};

static const struct irq_def irqs_9k[] = {
	{PSM_INT_GP_ENA_W1CX(0), PSM_INT_GP_ENA_W1SX(0), PSM_INT_GP_SUM_W1SX(0)},
	{PSM_INT_GP_ENA_W1CX(1), PSM_INT_GP_ENA_W1SX(1), PSM_INT_GP_SUM_W1SX(1)},
	{PSM_INT_GP_ENA_W1CX(2), PSM_INT_GP_ENA_W1SX(2), PSM_INT_GP_SUM_W1SX(2)},
	{PSM_INT_GP_ENA_W1CX(3), PSM_INT_GP_ENA_W1SX(3), PSM_INT_GP_SUM_W1SX(3)},
	{PSM_INT_ERRINT_9K_ENA_W1C, PSM_INT_ERRINT_9K_ENA_W1S, PSM_INT_ERRINT_9K_SUM_W1S},
	{PSM_INT_QOVF_ENA_W1CX(0), PSM_INT_QOVF_ENA_W1SX(0), PSM_INT_QOVF_SUM_W1SX(0)},
	{PSM_INT_QOVF_ENA_W1CX(1), PSM_INT_QOVF_ENA_W1SX(1), PSM_INT_QOVF_SUM_W1SX(1)},
	{PSM_INT_QTO_ENA_W1CX(0), PSM_INT_QTO_ENA_W1SX(0), PSM_INT_QTO_SUM_W1SX(0)},
	{PSM_INT_QTO_ENA_W1CX(1), PSM_INT_QTO_ENA_W1SX(1), PSM_INT_QTO_SUM_W1SX(1)},
	{PSM_INT_SETX_JERR_ENA_W1C(0), PSM_INT_SETX_JERR_ENA_W1S(0), PSM_INT_SETX_JERR_SUM_W1S(0)},
	{PSM_INT_SETX_JERR_ENA_W1C(1), PSM_INT_SETX_JERR_ENA_W1S(1), PSM_INT_SETX_JERR_SUM_W1S(1)},
	{PSM_INT_SETX_JERR_ENA_W1C(2), PSM_INT_SETX_JERR_ENA_W1S(2), PSM_INT_SETX_JERR_SUM_W1S(2)},
	{PSM_INT_SETX_JNFAT_ENA_W1C(0), PSM_INT_SETX_JNFAT_ENA_W1S(0), PSM_INT_SETX_JNFAT_SUM_W1S(0)},
	{PSM_INT_SETX_JNFAT_ENA_W1C(1), PSM_INT_SETX_JNFAT_ENA_W1S(1), PSM_INT_SETX_JNFAT_SUM_W1S(1)},
	{PSM_INT_SETX_JNFAT_ENA_W1C(2), PSM_INT_SETX_JNFAT_ENA_W1S(2), PSM_INT_SETX_JNFAT_SUM_W1S(2)},
	{PSM_INT_SETX_JTO_ENA_W1C(0), PSM_INT_SETX_JTO_ENA_W1S(0), PSM_INT_SETX_JTO_SUM_W1S(0)},
	{PSM_INT_SETX_JTO_ENA_W1C(1), PSM_INT_SETX_JTO_ENA_W1S(1), PSM_INT_SETX_JTO_SUM_W1S(1)},
	{PSM_INT_SETX_JTO_ENA_W1C(2), PSM_INT_SETX_JTO_ENA_W1S(2), PSM_INT_SETX_JTO_SUM_W1S(2)},
	{PSM_INT_SETX_DERR_ENA_W1C(0), PSM_INT_SETX_DERR_ENA_W1S(0), PSM_INT_SETX_DERR_SUM_W1S(0)},
	{PSM_INT_SETX_DERR_ENA_W1C(1), PSM_INT_SETX_DERR_ENA_W1S(1), PSM_INT_SETX_DERR_SUM_W1S(1)},
	{PSM_INT_SETX_DERR_ENA_W1C(2), PSM_INT_SETX_DERR_ENA_W1S(2), PSM_INT_SETX_DERR_SUM_W1S(2)},
	{PSM_INT_SETX_AERR_ENA_W1C(0), PSM_INT_SETX_AERR_ENA_W1S(0), PSM_INT_SETX_AERR_SUM_W1S(0)},
	{PSM_INT_SETX_AERR_ENA_W1C(1), PSM_INT_SETX_AERR_ENA_W1S(1), PSM_INT_SETX_AERR_SUM_W1S(1)},
	{PSM_INT_SETX_AERR_ENA_W1C(2), PSM_INT_SETX_AERR_ENA_W1S(2), PSM_INT_SETX_AERR_SUM_W1S(2)},
	{PSM_INT_SETX_MTO_ENA_W1C(0), PSM_INT_SETX_MTO_ENA_W1S(0), PSM_INT_SETX_MTO_SUM_W1S(0)},
	{PSM_INT_SETX_MTO_ENA_W1C(1), PSM_INT_SETX_MTO_ENA_W1S(1), PSM_INT_SETX_MTO_SUM_W1S(1)},
	{PSM_INT_SETX_MTO_ENA_W1C(2), PSM_INT_SETX_MTO_ENA_W1S(2), PSM_INT_SETX_MTO_SUM_W1S(2)},
};

static int
bphy_trigger_intr(int irq_num)
{
	volatile uint64_t *ena_w1c, *ena_w1s, *sum_w1s;
	const struct irq_def *irqs;
	uint64_t irq_addr;
	uint64_t pg_mask;
	uint64_t pg_size;
	char *psm_base;
	int mem_fd;

	irqs = irqs_9k;

	pg_size = sysconf(_SC_PAGE_SIZE);
	pg_mask = pg_size - 1;
	/* Interrupt registers go in tuples spreading over 4 adjacent locations
	 * 64 its each. It is safe to assume they do not cross page boundary, so
	 * using first one from the set seems legitimate.
	 */
	irq_addr = BPHY_BAR_BPHY_PF_BAR0 + (irqs[irq_num].ena_w1c & ~pg_mask);

	mem_fd = open("/dev/mem", O_RDWR | O_SYNC);
	psm_base = mmap(NULL, pg_size, PROT_READ | PROT_WRITE,
			MAP_SHARED, mem_fd, irq_addr);
	close(mem_fd);

	if (psm_base == MAP_FAILED)
		return -1;

	ena_w1c = (volatile uint64_t *)(psm_base + (irqs[irq_num].ena_w1c & pg_mask));
	ena_w1s = (volatile uint64_t *)(psm_base + (irqs[irq_num].ena_w1s & pg_mask));
	sum_w1s = (volatile uint64_t *)(psm_base + (irqs[irq_num].sum_w1s & pg_mask));

	/* It must be write of 32b FFs rather than 64b into 64b register */
	rte_write64(UINT_MAX, ena_w1c);
	rte_write64(RTE_BIT64(irq_num), ena_w1s);
	rte_delay_ms(1);
	rte_write64(RTE_BIT64(irq_num), sum_w1s);

	munmap(psm_base, pg_size);

	return 0;
}

static void
bphy_test_handler_fn(int irq_num, void *isr_data)
{
	test.handled = true;
	test.handled_data = *((int *)isr_data);
	test.handled_irq = irq_num;
}

int
main(int argc, char **argv)
{
	char dev_name[RTE_RAWDEV_NAME_MAX_LEN];
	bool fail = false;
	uint16_t dev_id;
	unsigned int i;
	int ret;

	ret = rte_eal_init(argc, argv);
	if (ret < 0)
		printf("ERR Invalid EAL arguments\n");
	argc -= ret;
	argv += ret;

	if (argc > 1) {
		snprintf(dev_name, RTE_RAWDEV_NAME_MAX_LEN, "BPHY:%s", argv[1]);
	} else {
		printf("BPHY application requires argument in BDF (XX:XX.X) format\n");
		rte_eal_cleanup();
		return -ENODEV;
	}

	dev_id = rte_rawdev_get_dev_id(dev_name);

	ret = rte_rawdev_start(dev_id);
	if (ret) {
		printf("BPHY failed to start device\n");
		rte_eal_cleanup();
		return -ENODEV;
	}

	ret = rte_pmd_bphy_intr_init(dev_id);
	if (ret) {
		printf("BPHY interrupt initialization failed\n");
		goto err_init;
	}

	for (i = 0; i < RTE_DIM(irqs_9k); i++) {
		test.test_data = i;
		test.irq_num = i;
		test.handler = bphy_test_handler_fn;
		test.data = &test.test_data;
		test.handled = false;
		test.handled_data = -1;
		test.handled_irq = -1;
		fail = false;

		ret = rte_pmd_bphy_intr_register(dev_id, test.irq_num,
						 test.handler, test.data, 0);
		if (ret == -ENOTSUP) {
			/* If some of the interrupts are not supported by given
			 * platform we just continue - it is not an error.
			 */
			continue;
		}

		if (ret) {
			printf("BPHY intr register failed for irq = %d\n", test.irq_num);
			fail = true;
			continue;
		}

		ret = bphy_trigger_intr(i);
		if (ret) {
			printf("BPHY failed to trigger irq = %d\n", test.irq_num);
			fail = true;
			goto unregister;
		}

		if (!test.handled) {
			printf("BPHY irq %d not handled\n", test.irq_num);
			fail = true;
			goto unregister;
		}

		if (test.handled_data != test.test_data) {
			printf("BPHY irq %d has wrong handler\n", test.irq_num);
			fail = true;
			goto unregister;
		}

		if (test.handled_irq != test.irq_num) {
			printf("BPHY wrong irq: wanted %d but handled %d\n",
			       test.irq_num, test.handled_irq);
			fail = true;
			goto unregister;
		}

unregister:
		rte_pmd_bphy_intr_unregister(dev_id, i);
	}

	rte_pmd_bphy_intr_fini(dev_id);

err_init:
	rte_rawdev_stop(dev_id);
	rte_eal_cleanup();

	return fail ? 1 : 0;
}
