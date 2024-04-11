/* Copyright (c) 2020 Marvell.
 * SPDX-License-Identifier: GPL-2.0
 */

#include "cavium_sysdep.h"
#include "octeon_hw.h"
#include "cn83xx_vf_device.h"
#include "octeon_macros.h"
#include "octeon-pci.h"

void cn83xx_dump_vf_iq_regs(octeon_device_t * oct)
{

}

void cn83xx_dump_vf_initialized_regs(octeon_device_t * oct)
{
}

static int cn83xx_vf_soft_reset(octeon_device_t * oct)
{
	return 0;
}

void cn83xx_dump_regs(octeon_device_t * oct, int qno)
{
//	printk("R[%d]_IN_INSTR_DBELL: 0x%016llx\n", qno, octeon_read_csr64(oct,
//			   CN83XX_SDP_EPF_R_IN_INSTR_DBELL(oct->epf_num, qno)));

}


/* Check if these function not for VF */
void cn83xx_enable_vf_error_reporting(octeon_device_t * oct)
{
	uint32_t regval;

	OCTEON_READ_PCI_CONFIG(oct, CN83XX_CONFIG_PCIE_DEVCTL, &regval);
	if (regval & 0x000f0000) {
		cavium_error("PCI-E Link error detected: 0x%08x\n",
			     regval & 0x000f0000);
	}

	regval |= 0xf;		/* Enable Link error reporting */

	cavium_print_msg("OCTEON[%d]: Enabling PCI-E error reporting.\n",
			 oct->octeon_id);
	OCTEON_WRITE_PCI_CONFIG(oct, CN83XX_CONFIG_PCIE_DEVCTL, regval);
}

int cn83xx_vf_reset_iq(octeon_device_t * oct, int q_no)
{
	volatile uint64_t d64 = 0ULL;
	uint64_t loop = CAVIUM_TICKS_PER_SEC;

	/* There is no RST for a ring. 
	 * Clear all registers one by one after disabling the ring
	 */

	octeon_write_csr64(oct,
			   CN83XX_VF_SDP_EPF_R_IN_ENABLE(oct->epf_num, q_no),
			   d64);

	octeon_write_csr64(oct,
			   CN83XX_VF_SDP_EPF_R_IN_INSTR_BADDR(oct->epf_num,
							      q_no), d64);

	octeon_write_csr64(oct,
			   CN83XX_VF_SDP_EPF_R_IN_INSTR_RSIZE(oct->epf_num,
							      q_no), d64);

	d64 = 0xFFFFFFFF;
	octeon_write_csr64(oct,
			   CN83XX_VF_SDP_EPF_R_IN_INSTR_DBELL(oct->epf_num,
							      q_no), d64);
	d64 =
	    octeon_read_csr64(oct,
			      CN83XX_VF_SDP_EPF_R_IN_INSTR_DBELL(oct->epf_num,
								 q_no));
	while ((d64 != 0) && loop--) {

		octeon_write_csr64(oct,
				   CN83XX_VF_SDP_EPF_R_IN_INSTR_DBELL
				   (oct->epf_num, q_no), d64);
		cavium_sleep_timeout(1);
		d64 = octeon_read_csr64(oct,
					CN83XX_VF_SDP_EPF_R_IN_INSTR_DBELL
					(oct->epf_num, q_no));
	}

	d64 =
	    octeon_read_csr64(oct,
			      CN83XX_VF_SDP_EPF_R_IN_CNTS(oct->epf_num, q_no));

	loop = CAVIUM_TICKS_PER_SEC;

	while ((d64 != 0) && loop--) {
		octeon_write_csr64(oct,
				   CN83XX_VF_SDP_EPF_R_IN_CNTS(oct->epf_num,
							       q_no), d64);
		cavium_sleep_timeout(1);
		d64 = octeon_read_csr64(oct,
					CN83XX_VF_SDP_EPF_R_IN_CNTS
					(oct->epf_num, q_no));
	}
	d64 = 0;
	octeon_write_csr64(oct,
			   CN83XX_VF_SDP_EPF_R_IN_INT_LEVELS(oct->epf_num,
							     q_no), d64);

	octeon_write_csr64(oct,
			   CN83XX_VF_SDP_EPF_R_IN_PKT_CNT(oct->epf_num, q_no),
			   d64);

	octeon_write_csr64(oct,
			   CN83XX_VF_SDP_EPF_R_IN_BYTE_CNT(oct->epf_num, q_no),
			   d64);

	return 0;
}

int cn83xx_vf_reset_oq(octeon_device_t * oct, int q_no)
{
	volatile uint64_t d64 = 0ULL;
	uint64_t loop = CAVIUM_TICKS_PER_SEC;

	octeon_write_csr64(oct,
			   CN83XX_VF_SDP_EPF_R_OUT_ENABLE(oct->epf_num, q_no),
			   d64);

	octeon_write_csr64(oct,
			   CN83XX_VF_SDP_EPF_R_OUT_SLIST_BADDR(oct->epf_num,
							       q_no), d64);

	octeon_write_csr64(oct,
			   CN83XX_VF_SDP_EPF_R_OUT_SLIST_RSIZE(oct->epf_num,
							       q_no), d64);

	d64 = 0xFFFFFFFF;
	octeon_write_csr64(oct,
			   CN83XX_VF_SDP_EPF_R_OUT_SLIST_DBELL(oct->epf_num,
							       q_no), d64);
	d64 =
	    octeon_read_csr64(oct,
			      CN83XX_VF_SDP_EPF_R_OUT_SLIST_DBELL(oct->epf_num,
								  q_no));

	while ((d64 != 0) && loop--) {

		octeon_write_csr64(oct,
				   CN83XX_VF_SDP_EPF_R_OUT_SLIST_DBELL
				   (oct->epf_num, q_no), d64);
		cavium_sleep_timeout(1);
		d64 = octeon_read_csr64(oct,
					CN83XX_VF_SDP_EPF_R_OUT_SLIST_DBELL
					(oct->epf_num, q_no));
	}

	d64 =
	    octeon_read_csr64(oct,
			      CN83XX_VF_SDP_EPF_R_OUT_CNTS(oct->epf_num, q_no));

	loop = CAVIUM_TICKS_PER_SEC;

	while ((d64 != 0) && (loop--)) {
		octeon_write_csr64(oct,
				   CN83XX_VF_SDP_EPF_R_OUT_CNTS(oct->epf_num,
								q_no), d64);
		cavium_sleep_timeout(1);
		d64 = octeon_read_csr64(oct,
					CN83XX_VF_SDP_EPF_R_OUT_CNTS
					(oct->epf_num, q_no));
	}

	d64 = 0;
	octeon_write_csr64(oct,
			   CN83XX_VF_SDP_EPF_R_OUT_INT_LEVELS(oct->epf_num,
							      q_no), d64);

	octeon_write_csr64(oct,
			   CN83XX_VF_SDP_EPF_R_OUT_PKT_CNT(oct->epf_num, q_no),
			   d64);

	octeon_write_csr64(oct,
			   CN83XX_VF_SDP_EPF_R_OUT_BYTE_CNT(oct->epf_num, q_no),
			   d64);

	return 0;
}

static void cn83xx_vf_setup_global_iq_reg(octeon_device_t * oct, int q_no)
{
	volatile uint64_t reg_val = 0ULL;

	/* Select ES, RO, NS, RDSIZE,DPTR Fomat#0 for IQs 
	 * IS_64B is by default enabled.
	 */
	reg_val =
	    octeon_read_csr64(oct,
			      CN83XX_VF_SDP_EPF_R_IN_CONTROL(oct->epf_num,
							     q_no));
	reg_val |= CN83XX_R_IN_CTL_RDSIZE;
	reg_val |= CN83XX_R_IN_CTL_IS_64B;
	reg_val |= CN83XX_R_IN_CTL_ESR;


	octeon_write_csr64(oct,
			   CN83XX_VF_SDP_EPF_R_IN_CONTROL(oct->epf_num, q_no),
			   reg_val);
}

static void cn83xx_vf_setup_global_oq_reg(octeon_device_t * oct, int q_no)
{
	volatile uint64_t reg_val = 0ULL;
	reg_val =
	    octeon_read_csr64(oct,
			      CN83XX_VF_SDP_EPF_R_OUT_CONTROL(oct->epf_num,
							      q_no));

	reg_val &= ~(CN83XX_R_OUT_CTL_IMODE);
	reg_val &= ~(CN83XX_R_OUT_CTL_ROR_P);
	reg_val &= ~(CN83XX_R_OUT_CTL_NSR_P);
	reg_val &= ~(CN83XX_R_OUT_CTL_ROR_I);
	reg_val &= ~(CN83XX_R_OUT_CTL_NSR_I);
	reg_val &= ~(CN83XX_R_OUT_CTL_ES_I);
	reg_val &= ~(CN83XX_R_OUT_CTL_ROR_D);
	reg_val &= ~(CN83XX_R_OUT_CTL_NSR_D);
	reg_val &= ~(CN83XX_R_OUT_CTL_ES_D);

    /* INFO/DATA ptr swap is requires on 83xx ??? */
	reg_val |= (CN83XX_R_OUT_CTL_ES_P);


	octeon_write_csr64(oct,
			   CN83XX_VF_SDP_EPF_R_OUT_CONTROL(oct->epf_num, q_no),
			   reg_val);
}

uint32_t cn83xx_get_oq_ticks(octeon_device_t * oct, uint32_t time_intr_in_us)
{
	/* This gives the SLI clock per microsec */
	uint32_t oqticks_per_us =
	    CFG_GET_COPROC_TICS_PER_US(CHIP_FIELD(oct, cn83xx_vf, conf));

	/* core clock per us / oq ticks will be fractional. TO avoid that
	 * we use the method below. 
	 */

	/* This gives the clock cycles per millisecond */
	oqticks_per_us *= 1000;

	/* This gives the oq ticks (1024 core clock cycles) per millisecond */
	oqticks_per_us /= 1024;

	/* time_intr is in microseconds. The next 2 steps gives the oq ticks
	 *  corressponding to time_intr. 
	 */
	oqticks_per_us *= time_intr_in_us;
	oqticks_per_us /= 1000;

	return oqticks_per_us;
}

int cn83xx_vf_reset_input_queues(octeon_device_t * oct)
{
	int q_no = 0;
	cavium_print(PRINT_DEBUG, " %s : OCTEON_CN83XX PF\n", __FUNCTION__);

	for (q_no = 0; q_no < oct->sriov_info.rings_per_vf; q_no++) {
		cn83xx_vf_reset_iq(oct, q_no);
	}
	return 0;
}

int cn83xx_vf_reset_output_queues(octeon_device_t * oct)
{
	uint64_t q_no = 0ULL;
	cavium_print(PRINT_DEBUG, " %s : OCTEON_CN83XX PF\n", __FUNCTION__);

	for (q_no = 0; q_no < oct->sriov_info.rings_per_vf; q_no++) {
		cn83xx_vf_reset_oq(oct, q_no);
	}
	return 0;
}

static void cn83xx_vf_setup_global_input_regs(octeon_device_t * oct)
{
	uint64_t q_no = 0ULL;

	/* Select ES, RO, NS, RDSIZE,DPTR Fomat#0 for 
	 * the Input Queues 
	 */
	cn83xx_vf_reset_input_queues(oct);
	for (q_no = 0; q_no < (oct->rings_per_vf); q_no++) {
		cn83xx_vf_setup_global_iq_reg(oct, q_no);
	}
}

void cn83xx_vf_setup_global_output_regs(octeon_device_t * oct)
{
	uint32_t q_no;

	cn83xx_vf_reset_output_queues(oct);
	for (q_no = 0; q_no < (oct->rings_per_vf); q_no++) {
		cn83xx_vf_setup_global_oq_reg(oct, q_no);
	}
}

static int cn83xx_setup_vf_device_regs(octeon_device_t * oct)
{
	cn83xx_vf_setup_global_input_regs(oct);
	cn83xx_vf_setup_global_output_regs(oct);

	return 0;
}

static void cn83xx_setup_vf_iq_regs(octeon_device_t * oct, int iq_no)
{
	volatile uint64_t reg_val = 0ULL;
	octeon_instr_queue_t *iq = oct->instr_queue[iq_no];
	octeon_cn83xx_vf_t *cn83xx = (octeon_cn83xx_vf_t *) oct->chip;

	reg_val =
	    octeon_read_csr64(oct,
			      CN83XX_VF_SDP_EPF_R_IN_CONTROL(oct->epf_num,
							     iq_no));

	/* wait for IDLE to set to 1, as cannot configure BADDR as long as IDLE is 0 */
	if (!(reg_val & CN83XX_R_IN_CTL_IDLE)) {
		do {
			reg_val =
			    octeon_read_csr64(oct,
					      CN83XX_VF_SDP_EPF_R_IN_CONTROL
					      (oct->epf_num, iq_no));
		}
		while (!(reg_val & CN83XX_R_IN_CTL_IDLE));
	}

	/* Write the start of the input queue's ring and its size  */
	octeon_write_csr64(oct,
			   CN83XX_VF_SDP_EPF_R_IN_INSTR_BADDR(oct->epf_num,
							      iq_no),
			   iq->base_addr_dma);
	octeon_write_csr64(oct,
			   CN83XX_VF_SDP_EPF_R_IN_INSTR_RSIZE(oct->epf_num,
							      iq_no),
			   iq->max_count);

	/* Remember the doorbell & instruction count register addr 
	 * for this queue 
	 */
	iq->doorbell_reg = (uint8_t *) oct->mmio[0].hw_addr
	    + CN83XX_VF_SDP_EPF_R_IN_INSTR_DBELL(oct->epf_num, iq_no);
	iq->inst_cnt_reg = (uint8_t *) oct->mmio[0].hw_addr
	    + CN83XX_VF_SDP_EPF_R_IN_CNTS(oct->epf_num, iq_no);
	iq->intr_lvl_reg = (uint8_t *) oct->mmio[0].hw_addr
	    + CN83XX_VF_SDP_EPF_R_IN_INT_LEVELS(oct->epf_num, iq_no);

	cavium_print(PRINT_DEBUG,
		     "InstQ[%d]:dbell reg @ 0x%p instcnt_reg @ 0x%p\n", iq_no,
		     iq->doorbell_reg, iq->inst_cnt_reg);

	/* Store the current instruction counter (used in flush_iq calculation) */
	iq->reset_instr_cnt = OCTEON_READ32(iq->inst_cnt_reg);

	/*
	 * Set IQ interrupt threshold to packets based on config.
	 */
	reg_val = (CFG_GET_IQ_INTR_THRESHOLD(cn83xx->conf) & 0xffffffff);
	octeon_write_csr64(oct,
			   CN83XX_VF_SDP_EPF_R_IN_INT_LEVELS(oct->epf_num, iq_no),
			   reg_val);
}

static void cn83xx_setup_vf_oq_regs(octeon_device_t * oct, int oq_no)
{
	volatile uint64_t reg_val = 0ULL;
	uint64_t time_threshold = 0ULL, oq_ctl = 0ULL;
	uint64_t loop = CAVIUM_TICKS_PER_SEC;
	octeon_droq_t *droq = oct->droq[oq_no];
	octeon_cn83xx_vf_t *cn83xx = (octeon_cn83xx_vf_t *) oct->chip;

	reg_val =
	    octeon_read_csr64(oct,
			      CN83XX_VF_SDP_EPF_R_OUT_CONTROL(oct->epf_num,
							     oq_no));

	/* wait for IDLE to set to 1, as cannot configure BADDR as long as IDLE is 0 */
	if (!(reg_val & CN83XX_R_OUT_CTL_IDLE)) {
		do {
			reg_val =
			    octeon_read_csr64(oct,
					      CN83XX_VF_SDP_EPF_R_OUT_CONTROL
					      (oct->epf_num, oq_no));
		}
		while (!(reg_val & CN83XX_R_OUT_CTL_IDLE));
	}

	octeon_write_csr64(oct,
			   CN83XX_VF_SDP_EPF_R_OUT_SLIST_BADDR(oct->epf_num,
							       oq_no),
			   droq->desc_ring_dma);
	octeon_write_csr64(oct,
			   CN83XX_VF_SDP_EPF_R_OUT_SLIST_RSIZE(oct->epf_num,
							       oq_no),
			   droq->max_count);

	oq_ctl =
	    octeon_read_csr64(oct,
			      CN83XX_VF_SDP_EPF_R_OUT_CONTROL(oct->epf_num,
							      oq_no));
	oq_ctl &= ~0x7fffffULL;	//clear the ISIZE and BSIZE (22-0)
	oq_ctl |= (droq->buffer_size & 0xffff);	//populate the BSIZE (15-0)
	octeon_write_csr64(oct,
			   CN83XX_VF_SDP_EPF_R_OUT_CONTROL(oct->epf_num, oq_no),
			   oq_ctl);

	/* Get the mapped address of the pkt_sent and pkts_credit regs */
	droq->pkts_sent_reg = (uint8_t *) oct->mmio[0].hw_addr +
	    CN83XX_VF_SDP_EPF_R_OUT_CNTS(oct->epf_num, oq_no);
	droq->pkts_credit_reg = (uint8_t *) oct->mmio[0].hw_addr +
	    CN83XX_VF_SDP_EPF_R_OUT_SLIST_DBELL(oct->epf_num, oq_no);

	reg_val =
	    octeon_read_csr64(oct,
			      CN83XX_VF_SDP_EPF_R_OUT_INT_LEVELS(oct->epf_num,
								 oq_no));
	time_threshold = cn83xx_get_oq_ticks(oct, (uint32_t)
						CFG_GET_OQ_INTR_TIME
						(cn83xx->conf));

	/*TODO: commented to avoid compilation error. need to resolve */
    reg_val = ( ((time_threshold & 0x3fffff) << CN83XX_R_OUT_INT_LEVELS_TIMET ) |
                CFG_GET_OQ_INTR_PKT(cn83xx->conf) );

	octeon_write_csr64(oct,
			   CN83XX_VF_SDP_EPF_R_OUT_INT_LEVELS(oct->epf_num,
							      oq_no), reg_val);

	/* Reset the oq doorbell register during setup as well to handle abrupt
	   guest reboot, IOQ reset does not reset doorbell registers */
	OCTEON_WRITE32(droq->pkts_credit_reg, 0xFFFFFFFF);
	while ((OCTEON_READ32(droq->pkts_credit_reg) != 0ULL) && loop--) {
		OCTEON_WRITE32(droq->pkts_credit_reg, 0xFFFFFFFF);
		cavium_sleep_timeout(1);
	}

	loop = CAVIUM_TICKS_PER_SEC;

	reg_val = OCTEON_READ32(droq->pkts_sent_reg);
	OCTEON_WRITE32(droq->pkts_sent_reg, reg_val);
	while (((OCTEON_READ32(droq->pkts_sent_reg)) != 0ULL)
	       && loop--) {
		reg_val = OCTEON_READ32(droq->pkts_sent_reg);
		OCTEON_WRITE32(droq->pkts_sent_reg, reg_val);
		cavium_sleep_timeout(1);
	}
}

static void cn83xx_setup_vf_mbox_regs(octeon_device_t * oct, int q_no)
{
	octeon_mbox_t *mbox = oct->mbox[q_no];

	mbox->q_no = q_no;

	/* PF mbox interrupt reg */
	mbox->mbox_int_reg = (uint8_t *) oct->mmio[0].hw_addr +
	    CN83XX_VF_SDP_EPF_R_MBOX_PF_VF_INT(oct->epf_num, q_no);

	/* PF to VF DATA reg. PF writes into this reg */
	mbox->mbox_write_reg = (uint8_t *) oct->mmio[0].hw_addr +
	    CN83XX_VF_SDP_EPF_R_MBOX_VF_PF_DATA(oct->epf_num, q_no);
	/* VF to PF DATA reg. PF reads from this reg */
	mbox->mbox_read_reg = (uint8_t *) oct->mmio[0].hw_addr +
	    CN83XX_VF_SDP_EPF_R_MBOX_PF_VF_DATA(oct->epf_num, q_no);

}

static void cn83xx_enable_vf_input_queue(octeon_device_t * oct, int q_no)
{
	volatile uint64_t reg_val = 0ULL;
	uint64_t loop = CAVIUM_TICKS_PER_SEC;

	/* Resetting doorbells during IQ enabling also to handle abrupt guest reboot.
	 * IQ reset does not clear the doorbells.*/
	octeon_write_csr64(oct,
			   CN83XX_VF_SDP_EPF_R_IN_INSTR_DBELL(oct->epf_num,
							      q_no),
			   0xFFFFFFFF);

	while (((octeon_read_csr64(oct,
				   CN83XX_VF_SDP_EPF_R_IN_INSTR_DBELL
				   (oct->epf_num, q_no))) != 0ULL)
	       && loop--) {
		cavium_sleep_timeout(1);
	}
	reg_val = octeon_read_csr64(oct,
				    CN83XX_VF_SDP_EPF_R_IN_ENABLE(oct->epf_num,
								  q_no));
	reg_val |= 0x1ULL;

	octeon_write_csr64(oct,
			   CN83XX_VF_SDP_EPF_R_IN_ENABLE(oct->epf_num, q_no),
			   reg_val);

}

static void cn83xx_enable_vf_output_queue(octeon_device_t * oct, int q_no)
{
	volatile uint64_t reg_val = 0ULL;
	octeon_write_csr64(oct,
			   CN83XX_VF_SDP_EPF_R_OUT_SLIST_DBELL(oct->epf_num,
							      q_no),
			   0xFFFFFFFF);

	reg_val = octeon_read_csr64(oct,
				    CN83XX_VF_SDP_EPF_R_OUT_ENABLE(oct->epf_num,
								   q_no));
	reg_val |= 0x1ULL;

	octeon_write_csr64(oct,
			   CN83XX_VF_SDP_EPF_R_OUT_ENABLE(oct->epf_num, q_no),
			   reg_val);

}

static void cn83xx_enable_vf_io_queues(octeon_device_t * oct)
{
	int q_no = 0;

	for (q_no = 0; q_no < oct->num_iqs; q_no++) {
		cn83xx_enable_vf_input_queue(oct, q_no);
		cn83xx_enable_vf_output_queue(oct, q_no);
	}
}

static void cn83xx_disable_vf_input_queue(octeon_device_t * oct, int q_no)
{
	uint64_t loop = CAVIUM_TICKS_PER_SEC;
	volatile uint64_t reg_val = 0ULL;

	loop = CAVIUM_TICKS_PER_SEC;

	/* Reset the doorbell register for this Input Queue. */
	reg_val = octeon_read_csr64(oct,
				    CN83XX_VF_SDP_EPF_R_IN_ENABLE(oct->epf_num,
								  q_no));
	reg_val &= ~0x1ULL;

	octeon_write_csr64(oct,
			   CN83XX_VF_SDP_EPF_R_IN_ENABLE(oct->epf_num, q_no),
			   reg_val);
}

static void cn83xx_disable_vf_output_queue(octeon_device_t * oct, int q_no)
{
	volatile uint64_t reg_val = 0ULL;

	reg_val = octeon_read_csr64(oct,
				    CN83XX_VF_SDP_EPF_R_OUT_ENABLE(oct->epf_num,
								   q_no));
	reg_val &= ~0x1ULL;

	octeon_write_csr64(oct,
			   CN83XX_VF_SDP_EPF_R_OUT_ENABLE(oct->epf_num, q_no),
			   reg_val);

}

static void cn83xx_disable_vf_io_queues(octeon_device_t * oct)
{
	int q_no = 0;

	/*** Disable Input Queues. ***/
	for (q_no = 0; q_no < oct->num_iqs; q_no++) {
		cn83xx_disable_vf_input_queue(oct, q_no);
		cn83xx_disable_vf_output_queue(oct, q_no);
	}
}

void cn83xx_handle_vf_mbox_intr(octeon_ioq_vector_t * ioq_vector)
{
	OCTEON_WRITE64(ioq_vector->mbox->mbox_int_reg,
		       OCTEON_READ64(ioq_vector->mbox->mbox_int_reg));
}

// *INDENT-OFF*
cvm_intr_return_t
cn83xx_vf_msix_interrupt_handler(void  *dev)
{
	octeon_ioq_vector_t *ioq_vector = (octeon_ioq_vector_t *) dev;
	octeon_droq_t *droq = ioq_vector->droq;

	droq->ops.napi_fun((void *)droq);
	return CVM_INTR_HANDLED;
}
// *INDENT-ON*

static void cn83xx_reinit_regs(octeon_device_t * oct)
{
	uint32_t i;

	cavium_print_msg("-- %s =--\n", __CVM_FUNCTION__);

	for (i = 0; i < (oct->rings_per_vf); i++) {
		if (!(oct->io_qmask.iq & (1UL << i)))
			continue;
		oct->fn_list.setup_iq_regs(oct, i);
	}

	for (i = 0; i < (oct->rings_per_vf); i++) {
		if (!(oct->io_qmask.oq & (1UL << i)))
			continue;
		oct->fn_list.setup_oq_regs(oct, i);
	}

	oct->fn_list.setup_device_regs(oct);

	oct->fn_list.enable_interrupt(oct->chip, OCTEON_ALL_INTR);

	oct->fn_list.enable_io_queues(oct);

	for (i = 0; i < (oct->rings_per_vf); i++) {
		if (!(oct->io_qmask.oq & (1UL << i)))
			continue;
		OCTEON_WRITE32(oct->droq[i]->pkts_credit_reg,
			       oct->droq[i]->max_count);
	}
}

static uint32_t cn83xx_update_read_index(octeon_instr_queue_t * iq)
{
	uint32_t new_idx = OCTEON_READ32(iq->inst_cnt_reg);

	/* The new instr cnt reg is a 32-bit counter that can roll over.
	 * We have noted the counter's initial value at init time into
	 * reset_instr_cnt
	 */
	if (iq->reset_instr_cnt < new_idx)
		new_idx -= iq->reset_instr_cnt;
	else
		new_idx += (0xffffffff - iq->reset_instr_cnt) + 1;

	/* Modulo of the new index with the IQ size will give us
	 * the new index.
	 */
	new_idx %= iq->max_count;

	return new_idx;
}

static void cn83xx_enable_vf_interrupt(void *chip, uint8_t intr_flag)
{
	octeon_cn83xx_vf_t *cn83xx = (octeon_cn83xx_vf_t *) chip;
	octeon_device_t *oct = (octeon_device_t *) cn83xx->oct;
	uint32_t q_no;

	for (q_no = 0; q_no < oct->rings_per_vf; q_no++) {
		octeon_write_csr64(oct,
				   CN83XX_VF_SDP_EPF_R_MBOX_PF_VF_INT
				   (oct->epf_num, q_no), 0x2ULL);
	}
	cavium_print_msg(" MBOX interrupts enabled.\n");
}

static void cn83xx_disable_vf_interrupt(void *chip, uint8_t intr_flag)
{
	volatile uint64_t reg_val = 0ULL;
	octeon_cn83xx_vf_t *cn83xx = (octeon_cn83xx_vf_t *) chip;
	octeon_device_t *oct = (octeon_device_t *) cn83xx->oct;
	uint32_t q_no;

	for (q_no = 0; q_no < oct->rings_per_vf; q_no++) {
		reg_val =
		    octeon_read_csr64(oct,
				      CN83XX_VF_SDP_EPF_R_MBOX_PF_VF_INT
				      (oct->epf_num, q_no));
		reg_val &= ~(0x2ULL);
		octeon_write_csr64(oct,
				   CN83XX_VF_SDP_EPF_R_MBOX_PF_VF_INT
				   (oct->epf_num, q_no), reg_val);
	}
	cavium_print_msg(" MBOX interrupts enabled.\n");
}

void cn83xx_force_vf_io_queues_off(octeon_device_t * oct)
{
	uint64_t d64 = 0ULL, q_no = 0ULL;
	cavium_print_msg(" %s : OCTEON_CN83XX VF \n", __FUNCTION__);

	for (q_no = 0; q_no < oct->rings_per_vf; q_no++) {
		/* Reset the Enable bit for all the 64 IQs  */
		d64 = 0;
		octeon_write_csr64(oct,
				   CN83XX_VF_SDP_EPF_R_IN_ENABLE
				   (oct->epf_num, q_no), d64);
		octeon_write_csr64(oct,
				   CN83XX_VF_SDP_EPF_R_OUT_ENABLE
				   (oct->epf_num, q_no), d64);
	}
}
int setup_cn83xx_octeon_vf_device(octeon_device_t * oct)
{
	uint64_t reg_val = 0ULL;
	octeon_cn83xx_vf_t *cn83xx = (octeon_cn83xx_vf_t *) oct->chip;

	//Should always be 0
	oct->epf_num = 0;
	//oct->pcie_port = 2; //for pem2 

	cn83xx->oct = oct;

	if (octeon_map_pci_barx(oct, 0, 0))
		return -1;

	cn83xx->conf = (cn83xx_vf_config_t *) oct_get_config_info(oct);
	if (cn83xx->conf == NULL) {
		cavium_error("%s No Config found for CN83XX\n", __FUNCTION__);
		octeon_unmap_pci_barx(oct, 0);
		return -1;
	}

	/**  INPUT_CONTROL[RPVF] gives the VF IOq count  **/
	reg_val =
	    octeon_read_csr64(oct,
			      CN83XX_VF_SDP_EPF_R_IN_CONTROL(oct->epf_num, 0));

	oct->rings_per_vf = ((reg_val >> CN83XX_R_IN_CTL_RPVF_POS) &
			     CN83XX_R_IN_CTL_RPVF_MASK);

	cavium_print_msg("RINGS PER VF ARE:::%d\n", oct->rings_per_vf);

	oct->drv_flags |= OCTEON_MSIX_CAPABLE;
	oct->drv_flags |= OCTEON_MBOX_CAPABLE;
	oct->drv_flags |= OCTEON_MSIX_AFFINITY_CAPABLE;

	oct->fn_list.setup_iq_regs = cn83xx_setup_vf_iq_regs;
	oct->fn_list.setup_oq_regs = cn83xx_setup_vf_oq_regs;
	oct->fn_list.setup_mbox_regs = cn83xx_setup_vf_mbox_regs;

	oct->fn_list.msix_interrupt_handler = cn83xx_vf_msix_interrupt_handler;

	oct->fn_list.soft_reset = cn83xx_vf_soft_reset;
	oct->fn_list.setup_device_regs = cn83xx_setup_vf_device_regs;
	oct->fn_list.reinit_regs = cn83xx_reinit_regs;
	oct->fn_list.update_iq_read_idx = cn83xx_update_read_index;

	oct->fn_list.enable_interrupt = cn83xx_enable_vf_interrupt;
	oct->fn_list.disable_interrupt = cn83xx_disable_vf_interrupt;

	oct->fn_list.enable_io_queues = cn83xx_enable_vf_io_queues;
	oct->fn_list.disable_io_queues = cn83xx_disable_vf_io_queues;

	oct->fn_list.enable_input_queue = cn83xx_enable_vf_input_queue;
	oct->fn_list.enable_output_queue = cn83xx_enable_vf_output_queue;

	oct->fn_list.disable_input_queue = cn83xx_disable_vf_input_queue;
	oct->fn_list.disable_output_queue = cn83xx_disable_vf_output_queue;

	oct->fn_list.force_io_queues_off = cn83xx_force_vf_io_queues_off;

	oct->fn_list.dump_registers = cn83xx_dump_vf_initialized_regs;

	return 0;
}

int validate_cn83xx_vf_config_info(cn83xx_vf_config_t * conf83xx)
{
	uint64_t total_instrs = 0ULL;

	if (CFG_GET_IQ_MAX_Q(conf83xx) > CN83XX_MAX_INPUT_QUEUES) {
		cavium_error("%s: Num IQ (%d) exceeds Max (%d)\n",
			     __CVM_FUNCTION__, CFG_GET_IQ_MAX_Q(conf83xx),
			     CN83XX_MAX_INPUT_QUEUES);
		return 1;
	}

	if (CFG_GET_OQ_MAX_Q(conf83xx) > CN83XX_MAX_OUTPUT_QUEUES) {
		cavium_error("%s: Num OQ (%d) exceeds Max (%d)\n",
			     __CVM_FUNCTION__, CFG_GET_OQ_MAX_Q(conf83xx),
			     CN83XX_MAX_OUTPUT_QUEUES);
		return 1;
	}

	if (CFG_GET_IQ_INSTR_TYPE(conf83xx) != OCTEON_32BYTE_INSTR &&
	    CFG_GET_IQ_INSTR_TYPE(conf83xx) != OCTEON_64BYTE_INSTR) {
		cavium_error("%s: Invalid instr type for IQ\n",
			     __CVM_FUNCTION__);
		return 1;
	}

	if (!(CFG_GET_IQ_NUM_DESC(conf83xx)) || !(CFG_GET_IQ_DB_MIN(conf83xx))
	    || !(CFG_GET_IQ_DB_TIMEOUT(conf83xx))) {
		cavium_error("%s: Invalid parameter for IQ\n",
			     __CVM_FUNCTION__);
		return 1;
	}

	total_instrs =
	    CFG_GET_IQ_NUM_DESC(conf83xx) * CFG_GET_IQ_MAX_Q(conf83xx);

	if (CFG_GET_IQ_PENDING_LIST_SIZE(conf83xx) < total_instrs) {
		cavium_error
		    ("%s Pending list size (%d) should be >= total instructions queue size (%d)\n",
		     __CVM_FUNCTION__, CFG_GET_IQ_PENDING_LIST_SIZE(conf83xx),
		     (int)total_instrs);
		return 1;
	}

	if (!(CFG_GET_OQ_INFO_PTR(conf83xx)) ||
	    !(CFG_GET_OQ_PKTS_PER_INTR(conf83xx)) ||
	    !(CFG_GET_OQ_NUM_DESC(conf83xx)) ||
	    !(CFG_GET_OQ_REFILL_THRESHOLD(conf83xx)) ||
	    !(CFG_GET_OQ_BUF_SIZE(conf83xx))) {
		cavium_error("%s: Invalid parameter for OQ\n",
			     __CVM_FUNCTION__);
		return 1;
	}

	if (!(CFG_GET_OQ_INTR_TIME(conf83xx))) {
		cavium_error("%s: Invalid parameter for OQ\n",
			     __CVM_FUNCTION__);
		return 1;
	}

	return 0;
}

/* $Id$ */
