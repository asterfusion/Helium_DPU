/* Copyright (c) 2020 Marvell.
 * SPDX-License-Identifier: GPL-2.0
 */

#include "cavium_sysdep.h"
#include "octeon_hw.h"
#include "cn83xx_pf_device.h"
#include "octeon_macros.h"
#include "octeon-pci.h"

extern void mv_facility_irq_handler(octeon_device_t *oct, uint64_t event_word);


void cn83xx_dump_iq_regs(octeon_device_t * oct)
{

}

void cn83xx_dump_pf_initialized_regs(octeon_device_t * oct)
{

}

void cn83xx_dump_regs(octeon_device_t * oct, int qno)
{
	printk("R[%d]_IN_INSTR_DBELL: 0x%016llx\n", qno, octeon_read_csr64(oct,
			   CN83XX_SDP_EPF_R_IN_INSTR_DBELL(oct->epf_num, qno)));

}

static int cn83xx_pf_soft_reset(octeon_device_t * oct)
{

    /* Soft Reset not required with BDK. Skip it */
#if 1
	octeon_write_csr64(oct, CN83XX_SLI_WIN_WR_MASK_REG(oct->epf_num), 0xFF);

	cavium_print_msg
	    ("OCTEON[%d]: BIST enabled for CN83XX soft reset\n",
	     oct->octeon_id);

	/* Initiate chip-wide soft reset */
	OCTEON_PCI_WIN_READ(oct, CN83XX_RST_SOFT_RST);
	OCTEON_PCI_WIN_WRITE(oct, CN83XX_RST_SOFT_RST, 1);

	/* Wait for 100ms as Octeon resets. */
	cavium_mdelay(100);

	cavium_print_msg("OCTEON[%d]: Reset completed\n", oct->octeon_id);

	/* restore the  reset value */
	octeon_write_csr64(oct, CN83XX_SLI_WIN_WR_MASK_REG(oct->epf_num), 0xFF);
	octeon_write_csr64(oct, CN83XX_SDP_SCRATCH(0), 0x0ULL);
#endif
	return 0;
}

void cn83xx_enable_error_reporting(octeon_device_t * oct)
{
	uint32_t regval;

	OCTEON_READ_PCI_CONFIG(oct, CN83XX_CONFIG_PCIE_DEVCTL, &regval);
	/* clear any old link error bits */
	OCTEON_WRITE_PCI_CONFIG(oct, CN83XX_CONFIG_PCIE_DEVCTL, regval);

	/* read again to see if new bits are set */
	msleep(1);
	OCTEON_READ_PCI_CONFIG(oct, CN83XX_CONFIG_PCIE_DEVCTL, &regval);
	if (regval & 0x000f0000) {
		cavium_error("PCI-E Link error detected: 0x%08x\n",
			     regval & 0x000f0000);
	}

	regval |= 0xf;		/* Enable Link error reporting */

	cavium_print(PRINT_DEBUG,
		     "OCTEON[%d]: Enabling PCI-E error reporting.\n",
		     oct->octeon_id);
	OCTEON_WRITE_PCI_CONFIG(oct, CN83XX_CONFIG_PCIE_DEVCTL, regval);
}

static uint32_t cn83xx_coprocessor_clock(octeon_device_t * oct)
{
	/* Bits 29:24 of RST_BOOT[PNR_MUL] holds the ref.clock MULTIPLIER
	 * for SLI. 
	 */

	/* as no handshake */ 
	return CFG_GET_COPROC_TICS_PER_US(CHIP_FIELD(oct, cn83xx_pf, conf));
}

uint32_t cn83xx_get_oq_ticks(octeon_device_t * oct, uint32_t time_intr_in_us)
{
	/* This gives the SLI clock per microsec */
	uint32_t oqticks_per_us = cn83xx_coprocessor_clock(oct);	//0x384; //0x2bc;  

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

int cn83xx_reset_iq(octeon_device_t * oct, int q_no)
{
	volatile uint64_t d64 = 0ULL;
	q_no += oct->sriov_info.pf_srn;
	/* There is no RST for a ring. 
	 * Clear all registers one by one after disabling the ring
	 */
	octeon_write_csr64(oct, CN83XX_SDP_EPF_R_IN_ENABLE(oct->epf_num, q_no),
			   d64);

	octeon_write_csr64(oct,
			   CN83XX_SDP_EPF_R_IN_INSTR_BADDR(oct->epf_num, q_no),
			   d64);

	octeon_write_csr64(oct,
			   CN83XX_SDP_EPF_R_IN_INSTR_RSIZE(oct->epf_num, q_no),
			   d64);

	d64 = 0xFFFFFFFF;
	octeon_write_csr64(oct,
			   CN83XX_SDP_EPF_R_IN_INSTR_DBELL(oct->epf_num, q_no),
			   d64);

	d64 = 0;
	octeon_write_csr64(oct, CN83XX_SDP_EPF_R_IN_CNTS(oct->epf_num, q_no),
			   d64);

	octeon_write_csr64(oct,
			   CN83XX_SDP_EPF_R_IN_INT_LEVELS(oct->epf_num, q_no),
			   d64);

	octeon_write_csr64(oct, CN83XX_SDP_EPF_R_IN_PKT_CNT(oct->epf_num, q_no),
			   d64);

	octeon_write_csr64(oct,
			   CN83XX_SDP_EPF_R_IN_BYTE_CNT(oct->epf_num, q_no),
			   d64);

	return 0;
}

int cn83xx_reset_oq(octeon_device_t * oct, int q_no)
{
	volatile uint64_t d64 = 0ULL;
	q_no += oct->sriov_info.pf_srn;

	octeon_write_csr64(oct, CN83XX_SDP_EPF_R_OUT_ENABLE(oct->epf_num, q_no),
			   d64);

	octeon_write_csr64(oct,
			   CN83XX_SDP_EPF_R_OUT_SLIST_BADDR(oct->epf_num, q_no),
			   d64);

	octeon_write_csr64(oct,
			   CN83XX_SDP_EPF_R_OUT_SLIST_RSIZE(oct->epf_num, q_no),
			   d64);

	d64 = 0xFFFFFFFF;
	octeon_write_csr64(oct,
			   CN83XX_SDP_EPF_R_OUT_SLIST_DBELL(oct->epf_num, q_no),
			   d64);

	d64 = 0;
	octeon_write_csr64(oct, CN83XX_SDP_EPF_R_OUT_CNTS(oct->epf_num, q_no),
			   d64);

	octeon_write_csr64(oct,
			   CN83XX_SDP_EPF_R_OUT_INT_LEVELS(oct->epf_num, q_no),
			   d64);

	octeon_write_csr64(oct,
			   CN83XX_SDP_EPF_R_OUT_PKT_CNT(oct->epf_num, q_no),
			   d64);

	octeon_write_csr64(oct,
			   CN83XX_SDP_EPF_R_OUT_BYTE_CNT(oct->epf_num, q_no),
			   d64);

	return 0;
}

int cn83xx_pf_setup_global_iq_reg(octeon_device_t * oct, int q_no)
{
	volatile uint64_t reg_val = 0ULL;

	q_no += oct->sriov_info.pf_srn;

	/* Select ES, RO, NS, RDSIZE,DPTR Fomat#0 for IQs 
	 * IS_64B is by default enabled.
	 */
	reg_val =
	    octeon_read_csr64(oct,
			      CN83XX_SDP_EPF_R_IN_CONTROL(oct->epf_num, q_no));
	reg_val |= CN83XX_R_IN_CTL_RDSIZE;
	reg_val |= CN83XX_R_IN_CTL_IS_64B;
//    reg_val |= CN83XX_R_IN_CTL_D_ESR;
	reg_val |= CN83XX_R_IN_CTL_ESR;


	octeon_write_csr64(oct, CN83XX_SDP_EPF_R_IN_CONTROL(oct->epf_num, q_no),
			   reg_val);
	return 0;
}

int cn83xx_pf_setup_global_oq_reg(octeon_device_t * oct, int q_no)
{
	volatile uint64_t reg_val = 0ULL;
	q_no += oct->sriov_info.pf_srn;
	reg_val =
	    octeon_read_csr64(oct,
			    CN83XX_SDP_EPF_R_OUT_CONTROL(oct->epf_num, q_no));

	reg_val &= ~(CN83XX_R_OUT_CTL_IMODE);

	/* ROR: Relaxed ordering
	 * NSR: No SNOOP
	 * ES: Endian Swap
	 * _P: for buff/info pairs read operation. 
	 * _I: for info buffer write operations. 
	 * _D: for data buffer write operations. 
	 */
	reg_val &= ~(CN83XX_R_OUT_CTL_ROR_P);
	reg_val &= ~(CN83XX_R_OUT_CTL_NSR_P);
	reg_val &= ~(CN83XX_R_OUT_CTL_ROR_I);
	reg_val &= ~(CN83XX_R_OUT_CTL_NSR_I);
	reg_val &= ~(CN83XX_R_OUT_CTL_ES_I);
	reg_val &= ~(CN83XX_R_OUT_CTL_ROR_D);
	reg_val &= ~(CN83XX_R_OUT_CTL_NSR_D);
	reg_val &= ~(CN83XX_R_OUT_CTL_ES_D);

    
    /* INFO/DATA ptr swap is required on 83xx  */
	reg_val |= (CN83XX_R_OUT_CTL_ES_P);


	printk("%s: epf-%u q-%d OUT_CONTROL=0x%llx\n", __func__, oct->epf_num, q_no, reg_val);
	/* write all the selected settings */
	octeon_write_csr64(oct, CN83XX_SDP_EPF_R_OUT_CONTROL(oct->epf_num, q_no),
			 reg_val);

	return 0;
}

int cn83xx_reset_input_queues(octeon_device_t * oct)
{
	int q_no = 0;
	cavium_print(PRINT_DEBUG, " %s : OCTEON_CN83XX PF\n", __FUNCTION__);

	for (q_no = 0; q_no < oct->sriov_info.rings_per_pf; q_no++) {
		cn83xx_reset_iq(oct, q_no);
	}
	return 0;
}

int cn83xx_reset_output_queues(octeon_device_t * oct)
{
	uint64_t q_no = 0ULL;
	cavium_print(PRINT_DEBUG, " %s : OCTEON_CN83XX PF\n", __FUNCTION__);

	for (q_no = 0; q_no < oct->sriov_info.rings_per_pf; q_no++) {
		cn83xx_reset_oq(oct, q_no);
	}
	return 0;
}

int cn83xx_pf_setup_global_input_regs(octeon_device_t * oct)
{
	uint64_t q_no = 0ULL;
	int ret = 0;

	ret = cn83xx_reset_input_queues(oct);
	cavium_print(PRINT_DEBUG, "Reset IQ Done: %d\n", ret);

	for (q_no = 0; q_no < oct->sriov_info.rings_per_pf; q_no++) {
		cn83xx_pf_setup_global_iq_reg(oct, q_no);
	}
	return 0;
}

void cn83xx_pf_setup_global_output_regs(octeon_device_t * oct)
{
	uint64_t q_no = 0ULL;
	int ret = 0;

	ret = cn83xx_reset_output_queues(oct);
	cavium_print(PRINT_DEBUG, "Reset OQ Done: %d\n", ret);

	for (q_no = 0; q_no < oct->sriov_info.rings_per_pf; q_no++) {
		cn83xx_pf_setup_global_oq_reg(oct, q_no);
	}

	/** 
     * NOTE: OUT_WMARK, GBL_CTL, BP_W1S, MAC_CREDIT are not accessible 
     * from Host in 83XX.
     */
}

int cn83xx_setup_global_mac_regs(octeon_device_t * oct)
{
	volatile uint64_t reg_val = 0ULL;
	uint64_t rings_per_vf = 0, num_vfs = 0;
	int i = 0, srn = 0, trs = 0, vf_num = 1;

    cavium_print_msg(" %s : uisng pcie_port: %d \n", __FUNCTION__,
                     oct->pcie_port);

	rings_per_vf = oct->sriov_info.rings_per_vf;
	num_vfs = oct->sriov_info.num_vfs;

	reg_val = octeon_read_csr64(oct, CN83XX_SDP_EPF_RINFO(oct->epf_num));

	srn =
	    (reg_val & CN83XX_SDP_EPF_RINFO_SRN) >>
	    CN83XX_SDP_EPF_RINFO_SRN_BIT_POS;
	trs =
	    (reg_val & CN83XX_SDP_EPF_RINFO_TRS) >>
	    CN83XX_SDP_EPF_RINFO_TRS_BIT_POS;

        srn = srn & 0x3f;

	/* setting RPVF <39:32> */
	reg_val |= ((rings_per_vf << CN83XX_SDP_EPF_RINFO_RPVF_BIT_POS) |
		    (num_vfs << CN83XX_SDP_EPF_RINFO_NVFS_BIT_POS));

	/* write these settings to MAC register */
	octeon_write_csr64(oct, CN83XX_SDP_EPF_RINFO(oct->epf_num), reg_val);

	reg_val = octeon_read_csr64(oct, CN83XX_SDP_EPF_RINFO(oct->epf_num));
	cavium_print(PRINT_DEBUG,"SDP_EPF[%d]_RINFO:  : 0x%016llx \n",
			 oct->epf_num, reg_val);

	/* Configure the VF_NUM Register. */
	for (i = 0; i < trs; i++) {

		/* Move to next vf after rings_per_vf iterations. */
		if (i == vf_num * rings_per_vf)
			vf_num++;

		/* Exit the loop if ring belongs to pf */
		if (i == num_vfs * rings_per_vf)
			break;

		reg_val = octeon_read_csr64(oct,
					    CN83XX_SDP_EPF_R_VF_NUM
					    (oct->epf_num, (i + srn)));
		reg_val |= (vf_num & 0x7f);
		octeon_write_csr64(oct,
				   CN83XX_SDP_EPF_R_VF_NUM(oct->epf_num,
							   (i + srn)), reg_val);
	}

	return 0;
}

static int cn83xx_setup_pf_device_regs(octeon_device_t * oct)
{

	cn83xx_enable_error_reporting(oct);

	cn83xx_setup_global_mac_regs(oct);

	cn83xx_pf_setup_global_input_regs(oct);

	cn83xx_pf_setup_global_output_regs(oct);

	/* TOTE: NO WINDOW CTL register in 83XX */
	return 0;
}

static void cn83xx_setup_iq_regs(octeon_device_t * oct, int iq_no)
{
	volatile uint64_t reg_val = 0ULL;
	octeon_instr_queue_t *iq = oct->instr_queue[iq_no];
	octeon_cn83xx_pf_t *cn83xx = (octeon_cn83xx_pf_t *) oct->chip;

	iq_no += oct->sriov_info.pf_srn;

	reg_val =
	    octeon_read_csr64(oct,
			      CN83XX_SDP_EPF_R_IN_CONTROL(oct->epf_num, iq_no));

	/* wait for IDLE to set to 1, as cannot configure BADDR as long as IDLE is 0 */
	if (!(reg_val & CN83XX_R_IN_CTL_IDLE)) {
		do {
			reg_val =
			    octeon_read_csr64(oct,
					      CN83XX_SDP_EPF_R_IN_CONTROL
					      (oct->epf_num, iq_no));
		}
		while (!(reg_val & CN83XX_R_IN_CTL_IDLE));
	}

	/* Write the start of the input queue's ring and its size  */
	octeon_write_csr64(oct,
			   CN83XX_SDP_EPF_R_IN_INSTR_BADDR(oct->epf_num, iq_no),
			   iq->base_addr_dma);
	octeon_write_csr64(oct,
			   CN83XX_SDP_EPF_R_IN_INSTR_RSIZE(oct->epf_num, iq_no),
			   iq->max_count);

	/* Remember the doorbell & instruction count register addr 
	 * for this queue 
	 */
	iq->doorbell_reg = (uint8_t *) oct->mmio[0].hw_addr
	    + CN83XX_SDP_EPF_R_IN_INSTR_DBELL(oct->epf_num, iq_no);
	iq->inst_cnt_reg = (uint8_t *) oct->mmio[0].hw_addr
	    + CN83XX_SDP_EPF_R_IN_CNTS(oct->epf_num, iq_no);
	iq->intr_lvl_reg = (uint8_t *) oct->mmio[0].hw_addr
	    + CN83XX_SDP_EPF_R_IN_INT_LEVELS(oct->epf_num, iq_no);

	cavium_print(PRINT_DEBUG,
		     "InstQ[%d]:dbell reg @ 0x%p instcnt_reg @ 0x%p\n", iq_no,
		     iq->doorbell_reg, iq->inst_cnt_reg);

	/* Store the current instruction counter (used in flush_iq calculation) */
	iq->reset_instr_cnt = OCTEON_READ32(iq->inst_cnt_reg);
	OCTEON_WRITE32(iq->inst_cnt_reg, iq->reset_instr_cnt);
	iq->reset_instr_cnt = OCTEON_READ32(iq->inst_cnt_reg);

	/*
	 * Set IQ interrupt threshold to packets based config.
	 */
	reg_val = (CFG_GET_IQ_INTR_THRESHOLD(cn83xx->conf) & 0xffffffff);
	octeon_write_csr64(oct,
			   CN83XX_SDP_EPF_R_IN_INT_LEVELS(oct->epf_num, iq_no),
			   reg_val);
}

static void cn83xx_setup_oq_regs(octeon_device_t * oct, int oq_no)
{
	volatile uint64_t reg_val = 0ULL;
	uint64_t oq_ctl = 0ULL;
	uint32_t time_threshold = 0;
	octeon_droq_t *droq = oct->droq[oq_no];
	octeon_cn83xx_pf_t *cn83xx = (octeon_cn83xx_pf_t *) oct->chip;

	oq_no += oct->sriov_info.pf_srn;

	reg_val =
	    octeon_read_csr64(oct,
			      CN83XX_SDP_EPF_R_OUT_CONTROL(oct->epf_num, oq_no));

	/* wait for IDLE to set to 1, as cannot configure BADDR as long as IDLE is 0 */
	if (!(reg_val & CN83XX_R_OUT_CTL_IDLE)) {
		do {
			reg_val =
			    octeon_read_csr64(oct,
					      CN83XX_SDP_EPF_R_OUT_CONTROL
					      (oct->epf_num, oq_no));
		}
		while (!(reg_val & CN83XX_R_OUT_CTL_IDLE));
	}

	octeon_write_csr64(oct,
			   CN83XX_SDP_EPF_R_OUT_SLIST_BADDR(oct->epf_num,
							    oq_no),
			   droq->desc_ring_dma);
	octeon_write_csr64(oct,
			   CN83XX_SDP_EPF_R_OUT_SLIST_RSIZE(oct->epf_num,
							    oq_no),
			   droq->max_count);

	oq_ctl =
	    octeon_read_csr64(oct,
			    CN83XX_SDP_EPF_R_OUT_CONTROL(oct->epf_num, oq_no));
	oq_ctl &= ~0x7fffffULL;	//clear the ISIZE and BSIZE (22-0)
	oq_ctl |= (droq->buffer_size & 0xffff);	//populate the BSIZE (15-0)
	octeon_write_csr64(oct, CN83XX_SDP_EPF_R_OUT_CONTROL(oct->epf_num, oq_no),
			 oq_ctl);


	/* Get the mapped address of the pkt_sent and pkts_credit regs */
	droq->pkts_sent_reg = (uint8_t *) oct->mmio[0].hw_addr +
	    CN83XX_SDP_EPF_R_OUT_CNTS(oct->epf_num, oq_no);
	droq->pkts_credit_reg = (uint8_t *) oct->mmio[0].hw_addr +
	    CN83XX_SDP_EPF_R_OUT_SLIST_DBELL(oct->epf_num, oq_no);

	reg_val =
	    octeon_read_csr64(oct,
			      CN83XX_SDP_EPF_R_OUT_INT_LEVELS(oct->epf_num,
							      oq_no));
	time_threshold = cn83xx_get_oq_ticks(oct, (uint32_t)
					     CFG_GET_OQ_INTR_TIME
					     (cn83xx->conf));


    reg_val =  ((uint64_t)time_threshold << 32 ) | CFG_GET_OQ_INTR_PKT(cn83xx->conf); 

	octeon_write_csr64(oct,
			   CN83XX_SDP_EPF_R_OUT_INT_LEVELS(oct->epf_num, oq_no),
			   reg_val);
}

/* Mail Box Commminucation is to be verified */ 
static void cn83xx_setup_pf_mbox_regs(octeon_device_t * oct, int q_no)
{
	octeon_mbox_t *mbox = oct->mbox[q_no];

	/* PF to VF DATA reg. PF writes into this reg */
	mbox->pf_vf_data_reg = (uint64_t *)((uint8_t *) oct->mmio[0].hw_addr +
			     CN83XX_SDP_EPF_R_MBOX_PF_VF_DATA(oct->epf_num, q_no));

	/* VF to PF DATA reg. PF reads from this reg */
	mbox->vf_pf_data_reg = (uint64_t *) ((uint8_t *)oct->mmio[0].hw_addr +
	CN83XX_SDP_EPF_R_MBOX_VF_PF_DATA(oct->epf_num, q_no));

}

static void cn83xx_enable_input_queue(octeon_device_t * oct, int iq_no)
{
	volatile uint64_t reg_val = 0ULL;
	uint64_t loop = CAVIUM_TICKS_PER_SEC;

	iq_no += oct->sriov_info.pf_srn;

	octeon_write_csr64(oct,
			   CN83XX_SDP_EPF_R_IN_INSTR_DBELL(oct->epf_num,
							      iq_no),
			   0xFFFFFFFF);

	while (((octeon_read_csr64(oct,
				   CN83XX_SDP_EPF_R_IN_INSTR_DBELL
				   (oct->epf_num, iq_no))) != 0ULL)
	       && loop--) {
		cavium_sleep_timeout(1);
	}
	/* Can directly enable as, waiting for IDLE while configuring BADDR */
	reg_val = octeon_read_csr64(oct,
				    CN83XX_SDP_EPF_R_IN_ENABLE(oct->epf_num,
							       iq_no));
	reg_val |= 0x1ULL;

	octeon_write_csr64(oct, CN83XX_SDP_EPF_R_IN_ENABLE(oct->epf_num, iq_no),
			   reg_val);
}

static void cn83xx_enable_output_queue(octeon_device_t * oct, int oq_no)
{
	volatile uint64_t reg_val = 0ULL;

	oq_no += oct->sriov_info.pf_srn;

	octeon_write_csr64(oct,
			   CN83XX_SDP_EPF_R_OUT_SLIST_DBELL(oct->epf_num,
							      oq_no),
			   0xFFFFFFFF);

	reg_val = octeon_read_csr64(oct,
				    CN83XX_SDP_EPF_R_OUT_ENABLE(oct->epf_num,
								oq_no));
	reg_val |= 0x1ULL;

	octeon_write_csr64(oct,
			   CN83XX_SDP_EPF_R_OUT_ENABLE(oct->epf_num, oq_no),
			   reg_val);
}

static void cn83xx_disable_input_queue(octeon_device_t * oct, int iq_no)
{
	volatile uint64_t reg_val = 0ULL;

	iq_no += oct->sriov_info.pf_srn;

	reg_val = octeon_read_csr64(oct,
				    CN83XX_SDP_EPF_R_IN_ENABLE(oct->epf_num,
							       iq_no));
	reg_val &= ~0x1ULL;

	octeon_write_csr64(oct, CN83XX_SDP_EPF_R_IN_ENABLE(oct->epf_num, iq_no),
			   reg_val);
}

static void cn83xx_disable_output_queue(octeon_device_t * oct, int oq_no)
{
	volatile uint64_t reg_val = 0ULL;

	oq_no += oct->sriov_info.pf_srn;
	/* Can directly enable as, waiting for IDLE while configuring BADDR */
	reg_val = octeon_read_csr64(oct,
				    CN83XX_SDP_EPF_R_OUT_ENABLE(oct->epf_num,
								oq_no));
	reg_val &= ~0x1ULL;

	octeon_write_csr64(oct,
			   CN83XX_SDP_EPF_R_OUT_ENABLE(oct->epf_num, oq_no),
			   reg_val);
}

static void cn83xx_enable_io_queues(octeon_device_t * oct)
{

	uint64_t q_no = 0;

	for (q_no = 0; q_no < oct->sriov_info.rings_per_pf; q_no++) {
		cn83xx_enable_input_queue(oct, q_no);
		cn83xx_enable_output_queue(oct, q_no);
	}
}

static void cn83xx_disable_io_queues(octeon_device_t * oct)
{
	int q_no = 0;

	for (q_no = 0; q_no < oct->sriov_info.rings_per_pf; q_no++) {
		cn83xx_disable_input_queue(oct, q_no);
		cn83xx_disable_output_queue(oct, q_no);
	}
}

void cn83xx_handle_pcie_error_intr(octeon_device_t * oct, uint64_t intr64)
{
	cavium_error("OCTEON[%d]: Error Intr: 0x%016llx\n",
		     oct->octeon_id, CVM_CAST64(intr64));

}

void cn83xx_force_io_queues_off(octeon_device_t * oct)
{
	uint64_t reg_val = 0ULL, q_no = 0ULL, srn = 0ULL, ern = 0ULL;

	cavium_print_msg(" %s : OCTEON_CN83XX PF\n", __FUNCTION__);

	srn = oct->sriov_info.pf_srn;
	ern = srn + oct->sriov_info.rings_per_pf;

	for (q_no = srn; q_no < ern; q_no++) {

		reg_val = octeon_read_csr64(oct,
					    CN83XX_SDP_EPF_R_IN_ENABLE
					    (oct->epf_num, q_no));
		reg_val &= ~0x1ULL;
		octeon_write_csr64(oct,
				   CN83XX_SDP_EPF_R_IN_ENABLE
				   (oct->epf_num, q_no), reg_val);

		reg_val = octeon_read_csr64(oct,
					    CN83XX_SDP_EPF_R_OUT_ENABLE
					    (oct->epf_num, q_no));
		reg_val &= ~0x1ULL;
		octeon_write_csr64(oct,
				   CN83XX_SDP_EPF_R_OUT_ENABLE
				   (oct->epf_num, q_no), reg_val);
	}
}

/* MailBox Interrupts */
void cn83xx_handle_pf_mbox_intr(octeon_device_t * oct, uint64_t reg_val)
{
	int qno = 0;

	for (qno = 0; qno < 64; qno++) {
		if (reg_val & (0x1UL << qno)) {
			if (oct->mbox[qno] != NULL) {
				cavium_print_msg("CN83XX MBOX interrupt received on PF qno %d\n",
						qno);
				schedule_work(&oct->mbox[qno]->wk.work);
			} else {
				cavium_print_msg("bad mbox qno %d\n", qno);
			}
		}
	}
}

cvm_intr_return_t cn83xx_pf_msix_interrupt_handler(void *dev)
{
	octeon_ioq_vector_t *ioq_vector = (octeon_ioq_vector_t *) dev;
	octeon_droq_t *droq = ioq_vector->droq;

	droq->ops.napi_fun((void *)droq);
	return CVM_INTR_HANDLED;
}

cvm_intr_return_t cn83xx_interrupt_handler(void *dev)
{
	uint64_t reg_val = 0;
    int i =0;
	octeon_device_t *oct = (octeon_device_t *) dev;

	/* Check for IRERR INTR */
	reg_val = octeon_read_csr64(oct,
				    CN83XX_SDP_EPF_IRERR_RINT(oct->epf_num));
	if (reg_val) {
		cavium_print_msg("received IRERR_RINT intr: 0x%016llx\n",
				 reg_val);
		octeon_write_csr64(oct, CN83XX_SDP_EPF_IRERR_RINT(oct->epf_num),
				   reg_val);

        for(i =0 ; i < 64; i++) {
        	reg_val = octeon_read_csr64(oct,
		    		    CN83XX_SDP_EPF_R_ERR_TYPE(oct->epf_num, i));
            if(reg_val) {
        		cavium_print_msg("received err type on input ring [%d]: 0x%016llx\n", i, reg_val);
        	    octeon_write_csr64(oct, CN83XX_SDP_EPF_R_ERR_TYPE(oct->epf_num, i), reg_val);
            }
        }
		goto irq_handled;
	}

	/* Check for ORERR INTR */
	reg_val = octeon_read_csr64(oct,
				    CN83XX_SDP_EPF_ORERR_RINT(oct->epf_num));
	if (reg_val) {
		cavium_print_msg("received ORERR_RINT intr: 0x%016llx\n",
				 reg_val);
		octeon_write_csr64(oct, CN83XX_SDP_EPF_ORERR_RINT(oct->epf_num),
				   reg_val);
		for (i = 0 ; i < 64; i++) {
			reg_val = octeon_read_csr64(oct,
					CN83XX_SDP_EPF_R_ERR_TYPE(oct->epf_num, i));
			if(reg_val) {
				cavium_print_msg("received err type on output ring [%d]: 0x%016llx\n", i, reg_val);
				octeon_write_csr64(oct, CN83XX_SDP_EPF_R_ERR_TYPE(oct->epf_num, i), reg_val);
			}
		}
		goto irq_handled;
	}

	/* Check for MBOX INTR */
	reg_val = octeon_read_csr64(oct,
				    CN83XX_SDP_EPF_MBOX_RINT(oct->epf_num));
	if (reg_val) {
		cavium_print_msg("received MBOX_RINT intr: 0x%016llx\n",
				 reg_val);
		cn83xx_handle_pf_mbox_intr(oct, reg_val);
		octeon_write_csr64(oct, CN83XX_SDP_EPF_MBOX_RINT(oct->epf_num), reg_val);
		goto irq_handled;
	}

	/* Check for OEI INTR */
	reg_val = octeon_read_csr64(oct, CN83XX_SDP_EPF_OEI_RINT(oct->epf_num));
	if (reg_val) {
		octeon_write_csr64(oct, CN83XX_SDP_EPF_OEI_RINT(oct->epf_num),
				   reg_val);
		/* used by facility */
		mv_facility_irq_handler(oct, reg_val);
		goto irq_handled;
	}

	/* Check for DMA INTR */
	reg_val = octeon_read_csr64(oct, CN83XX_SLI_EPF_DMA_RINT(oct->epf_num));
	if (reg_val) {
		octeon_write_csr64(oct, CN83XX_SLI_EPF_DMA_RINT(oct->epf_num),
				   reg_val);
		goto irq_handled;
	}

	/* Check for MISC INTR */
	reg_val = octeon_read_csr64(oct,
				    CN83XX_SLI_EPF_MISC_RINT(oct->epf_num));
	if (reg_val) {
		cavium_print_msg("received MISC_RINT intr: 0x%016llx\n",
				 reg_val);
		octeon_write_csr64(oct, CN83XX_SLI_EPF_MISC_RINT(oct->epf_num),
				   reg_val);
		goto irq_handled;
	}

	/* Check for PPVF INTR */
	reg_val = octeon_read_csr64(oct,
				    CN83XX_SLI_EPF_PP_VF_RINT(oct->epf_num));
	if (reg_val) {
		cavium_print_msg("received PP_VF_RINT intr: 0x%016llx\n",
				 reg_val);
		octeon_write_csr64(oct, CN83XX_SLI_EPF_PP_VF_RINT(oct->epf_num),
				   reg_val);
		goto irq_handled;
	}

	/* Check for DMA VF INTR */
	reg_val = octeon_read_csr64(oct,
				    CN83XX_SLI_EPF_DMA_VF_RINT(oct->epf_num));
	if (reg_val) {
		cavium_print_msg("received DMA_VF_RINT intr: 0x%016llx\n",
				 reg_val);
		octeon_write_csr64(oct,
				   CN83XX_SLI_EPF_DMA_VF_RINT(oct->epf_num),
				   reg_val);
		goto irq_handled;
	}
	cavium_print_msg("IGNORE. RSVD INTRS raised\n");
irq_handled:
	return CVM_INTR_HANDLED;
}

static void cn83xx_reinit_regs(octeon_device_t * oct)
{
	uint32_t i;

	oct->fn_list.setup_device_regs(oct);

	for (i = 0; i < MAX_OCTEON_INSTR_QUEUES; i++) {
		if (!(oct->io_qmask.iq & (1UL << i)))
			continue;
		oct->fn_list.setup_iq_regs(oct, i);
	}

	for (i = 0; i < MAX_OCTEON_OUTPUT_QUEUES; i++) {
		if (!(oct->io_qmask.oq & (1UL << i)))
			continue;
		oct->fn_list.setup_oq_regs(oct, i);
	}

	oct->fn_list.enable_interrupt(oct->chip, OCTEON_ALL_INTR);

	oct->fn_list.enable_io_queues(oct);

	/* for (i = 0; i < oct->num_oqs; i++) { */
	for (i = 0; i < MAX_OCTEON_OUTPUT_QUEUES; i++) {
		if (!(oct->io_qmask.oq & (1UL << i)))
			continue;
		OCTEON_WRITE32(oct->droq[i]->pkts_credit_reg,
			       oct->droq[i]->max_count);
	}
}

static void
cn83xx_bar1_idx_setup(octeon_device_t * oct,
		      uint64_t core_addr, int idx, int valid)
{
	volatile uint64_t bar1;

	if (valid == 0) {
		bar1 = OCTEON_PCI_WIN_READ(oct,
					   CN83XX_PEM_BAR1_INDEX_REG
					   (oct->pcie_port, idx));
		OCTEON_PCI_WIN_WRITE(oct,
				     CN83XX_PEM_BAR1_INDEX_REG(oct->pcie_port,
							       idx),
				     (bar1 & 0xFFFFFFFEULL));
		bar1 =
		    OCTEON_PCI_WIN_READ(oct,
					CN83XX_PEM_BAR1_INDEX_REG
					(oct->pcie_port, idx));
		return;
	}

	/*  The PEM(0..3)_BAR1_INDEX(0..15)[ADDR_IDX]<23:4> stores 
	 *  bits <41:22> of the Core Addr 
	 */
	OCTEON_PCI_WIN_WRITE(oct,
			     CN83XX_PEM_BAR1_INDEX_REG(oct->pcie_port, idx),
			     (((core_addr >> 22) << 4) | PCI_BAR1_MASK));

	bar1 = OCTEON_PCI_WIN_READ(oct,
				   CN83XX_PEM_BAR1_INDEX_REG(oct->pcie_port,
							     idx));
}

static void cn83xx_bar1_idx_write(octeon_device_t * oct, int idx, uint32_t mask)
{
	OCTEON_PCI_WIN_WRITE(oct,
			     CN83XX_PEM_BAR1_INDEX_REG(oct->pcie_port, idx),
			     mask);
}

static uint32_t cn83xx_bar1_idx_read(octeon_device_t * oct, int idx)
{
	return OCTEON_PCI_WIN_READ(oct,
				   CN83XX_PEM_BAR1_INDEX_REG(oct->pcie_port,
							     idx));
}

static uint32_t cn83xx_update_read_index(octeon_instr_queue_t * iq)
{
	u32 new_idx;
	u32 last_done;
	u32 pkt_in_done = OCTEON_READ32(iq->inst_cnt_reg);

	if (pkt_in_done == 0xFFFFFFFF) {
		last_done = 0;
		printk("PF detected PCIe read error F's in %s \n",__func__);
	}
	else {
		last_done = pkt_in_done - iq->pkt_in_done;
		iq->pkt_in_done = pkt_in_done;
	}

#define OCTEON_PKT_IN_DONE_CNT_MASK (0x00000000FFFFFFFFULL)
	new_idx = (iq->octeon_read_index +
		   (u32)(last_done & OCTEON_PKT_IN_DONE_CNT_MASK)) %
		  iq->max_count;

	return new_idx;
}

static void cn83xx_enable_pf_interrupt(void *chip, uint8_t intr_flag)
{
	volatile uint64_t reg_val = 0ULL;
	uint64_t intr_mask = 0ULL;
	int srn = 0, trs = 0, i;
	octeon_cn83xx_pf_t *cn83xx = (octeon_cn83xx_pf_t *) chip;
	octeon_device_t *oct = (octeon_device_t *) cn83xx->oct;

	reg_val = octeon_read_csr64(oct, CN83XX_SDP_EPF_RINFO(oct->epf_num));

	srn = reg_val & CN83XX_SDP_EPF_RINFO_SRN;
	trs =
	    (reg_val & CN83XX_SDP_EPF_RINFO_TRS) >>
	    CN83XX_SDP_EPF_RINFO_TRS_BIT_POS;

        srn = srn & 0x3f;

	for (i = 0; i < trs; i++)
		intr_mask |= (0x1ULL << (srn + i));

	octeon_write_csr64(oct,
			   CN83XX_SDP_EPF_IRERR_RINT_ENA_W1S(oct->epf_num),
			   intr_mask);
	octeon_write_csr64(oct, CN83XX_SDP_EPF_ORERR_RINT_ENA_W1S(oct->epf_num),
			   intr_mask);

	octeon_write_csr64(oct, CN83XX_SDP_EPF_OEI_RINT_ENA_W1S(oct->epf_num), -1ULL);
	octeon_write_csr64(oct, CN83XX_SDP_EPF_MBOX_RINT_ENA_W1S(oct->epf_num), -1ULL);
	octeon_write_csr64(oct, CN83XX_SLI_EPF_MISC_RINT_ENA_W1S(oct->epf_num),
			   intr_mask);
	octeon_write_csr64(oct, CN83XX_SLI_EPF_PP_VF_RINT_ENA_W1S(oct->epf_num),
			   intr_mask);
	octeon_write_csr64(oct,
			   CN83XX_SLI_EPF_DMA_VF_RINT_ENA_W1S(oct->epf_num),
			   intr_mask);
	octeon_write_csr64(oct, CN83XX_SLI_EPF_DMA_RINT_ENA_W1S(oct->epf_num),
			   intr_mask);
}

static void cn83xx_disable_pf_interrupt(void *chip, uint8_t intr_flag)
{
	volatile uint64_t reg_val = 0ULL;
	uint64_t intr_mask = 0ULL;
	int srn = 0, trs = 0, i;
	octeon_cn83xx_pf_t *cn83xx = (octeon_cn83xx_pf_t *) chip;
	octeon_device_t *oct = (octeon_device_t *) cn83xx->oct;

	reg_val = octeon_read_csr64(oct, CN83XX_SDP_EPF_RINFO(oct->epf_num));

	srn = reg_val & CN83XX_SDP_EPF_RINFO_SRN;
	trs =
	    (reg_val & CN83XX_SDP_EPF_RINFO_TRS) >>
	    CN83XX_SDP_EPF_RINFO_TRS_BIT_POS;

        srn = srn & 0x3f;

	for (i = 0; i < trs; i++)
		intr_mask |= (0x1ULL << (srn + i));

	octeon_write_csr64(oct,
			   CN83XX_SDP_EPF_IRERR_RINT_ENA_W1C(oct->epf_num),
			   intr_mask);
	octeon_write_csr64(oct, CN83XX_SDP_EPF_ORERR_RINT_ENA_W1C(oct->epf_num),
			   intr_mask);
	octeon_write_csr64(oct, CN83XX_SDP_EPF_OEI_RINT_ENA_W1C(oct->epf_num), -1ULL);
	octeon_write_csr64(oct, CN83XX_SLI_EPF_MISC_RINT_ENA_W1C(oct->epf_num),
			   intr_mask);
	octeon_write_csr64(oct, CN83XX_SLI_EPF_PP_VF_RINT_ENA_W1C(oct->epf_num),
			   intr_mask);
	octeon_write_csr64(oct,
			   CN83XX_SLI_EPF_DMA_VF_RINT_ENA_W1C(oct->epf_num),
			   intr_mask);
	octeon_write_csr64(oct, CN83XX_SLI_EPF_DMA_RINT_ENA_W1C(oct->epf_num),
			   intr_mask);
}

static int cn83xx_get_pcie_qlmport(octeon_device_t * oct)
{
	/* there are 4 MAC_NUMBER registers. which one to read to get the pcie_port?
	 * The value should come from LMAC_CONST[pcie_port].epf
	 */ 

    /* EPF num should always be 0. */ 
	oct->epf_num = 0;
	oct->pcie_port = (octeon_read_csr64(oct, CN83XX_SLI_MAC_NUMBER(oct->epf_num))) & 0xff;

	cavium_print_msg("OCTEON[%d]: CN83xx uses PCIE Port %d\n",
			 oct->octeon_id, oct->pcie_port);

	/* If port is 0xff, PCIe read failed, return error */
	return (oct->pcie_port == 0xff);
}

static int cn83xx_setup_reg_address(octeon_device_t * oct)
{
	uint8_t cavium_iomem *bar0_pciaddr = oct->mmio[0].hw_addr;
	int epf_num = 0;

	oct->reg_list.pci_win_wr_addr_hi =
	    (uint32_t cavium_iomem *) (bar0_pciaddr +
				       CN83XX_SLI_WIN_WR_ADDR_HI(epf_num));
	oct->reg_list.pci_win_wr_addr_lo =
	    (uint32_t cavium_iomem *) (bar0_pciaddr +
				       CN83XX_SLI_WIN_WR_ADDR_LO(epf_num));
	oct->reg_list.pci_win_wr_addr =
	    (uint64_t cavium_iomem *) (bar0_pciaddr +
				       CN83XX_SLI_WIN_WR_ADDR64(epf_num));

	oct->reg_list.pci_win_rd_addr_hi =
	    (uint32_t cavium_iomem *) (bar0_pciaddr +
				       CN83XX_SLI_WIN_RD_ADDR_HI(epf_num));
	oct->reg_list.pci_win_rd_addr_lo =
	    (uint32_t cavium_iomem *) (bar0_pciaddr +
				       CN83XX_SLI_WIN_RD_ADDR_LO(epf_num));
	oct->reg_list.pci_win_rd_addr =
	    (uint64_t cavium_iomem *) (bar0_pciaddr +
				       CN83XX_SLI_WIN_RD_ADDR64(epf_num));

	oct->reg_list.pci_win_wr_data_hi =
	    (uint32_t cavium_iomem *) (bar0_pciaddr +
				       CN83XX_SLI_WIN_WR_DATA_HI(epf_num));
	oct->reg_list.pci_win_wr_data_lo =
	    (uint32_t cavium_iomem *) (bar0_pciaddr +
				       CN83XX_SLI_WIN_WR_DATA_LO(epf_num));
	oct->reg_list.pci_win_wr_data =
	    (uint64_t cavium_iomem *) (bar0_pciaddr +
				       CN83XX_SLI_WIN_WR_DATA64(epf_num));

	oct->reg_list.pci_win_rd_data_hi =
	    (uint32_t cavium_iomem *) (bar0_pciaddr +
				       CN83XX_SLI_WIN_RD_DATA_HI(epf_num));
	oct->reg_list.pci_win_rd_data_lo =
	    (uint32_t cavium_iomem *) (bar0_pciaddr +
				       CN83XX_SLI_WIN_RD_DATA_LO(epf_num));
	oct->reg_list.pci_win_rd_data =
	    (uint64_t cavium_iomem *) (bar0_pciaddr +
				       CN83XX_SLI_WIN_RD_DATA64(epf_num));

	return cn83xx_get_pcie_qlmport(oct);
}

static inline int lowerpow2roundup(int x)
{
	x = x | (x >> 1);
	x = x | (x >> 2);
	x = x | (x >> 4);
	x = x | (x >> 8);
	x = x | (x >> 16);

	return x - (x >> 1);
}

#define CN83XX_MAX_VF 15
int
setup_cn83xx_octeon_pf_device(octeon_device_t * oct)
{
	uint64_t epf_rinfo = 0;
	int epf_trs = 0, epf_srn = 0;
	octeon_cn83xx_pf_t *cn83xx = (octeon_cn83xx_pf_t *) oct->chip;
	int vf_rings = 0;

	cn83xx->oct = oct;

	if (octeon_map_pci_barx(oct, 0, 0))
		return -1;

	if (octeon_map_pci_barx(oct, 1, MAX_BAR1_IOREMAP_SIZE)) {
		cavium_error("%s CN83XX BAR1 map failed\n", __FUNCTION__);
		octeon_unmap_pci_barx(oct, 0);
		return -1;
	}

	cn83xx->conf = (cn83xx_pf_config_t *) oct_get_config_info(oct);
	if (cn83xx->conf == NULL) {
		cavium_error("%s No Config found for CN83XX\n", __FUNCTION__);
		octeon_unmap_pci_barx(oct, 0);
		octeon_unmap_pci_barx(oct, 1);
		return -1;
	}
	oct->fn_list.setup_iq_regs = cn83xx_setup_iq_regs;
	oct->fn_list.setup_oq_regs = cn83xx_setup_oq_regs;
	oct->fn_list.setup_mbox_regs = cn83xx_setup_pf_mbox_regs;

	oct->fn_list.interrupt_handler = cn83xx_interrupt_handler;
	oct->fn_list.msix_interrupt_handler = cn83xx_pf_msix_interrupt_handler;

	oct->fn_list.soft_reset = cn83xx_pf_soft_reset;
	oct->fn_list.setup_device_regs = cn83xx_setup_pf_device_regs;
	oct->fn_list.reinit_regs = cn83xx_reinit_regs;
	oct->fn_list.update_iq_read_idx = cn83xx_update_read_index;

	oct->fn_list.bar1_idx_setup = cn83xx_bar1_idx_setup;
	oct->fn_list.bar1_idx_write = cn83xx_bar1_idx_write;
	oct->fn_list.bar1_idx_read = cn83xx_bar1_idx_read;

	oct->fn_list.enable_interrupt = cn83xx_enable_pf_interrupt;
	oct->fn_list.disable_interrupt = cn83xx_disable_pf_interrupt;

	oct->fn_list.enable_io_queues = cn83xx_enable_io_queues;
	oct->fn_list.disable_io_queues = cn83xx_disable_io_queues;

	oct->fn_list.enable_input_queue = cn83xx_enable_input_queue;
	oct->fn_list.enable_output_queue = cn83xx_enable_output_queue;

	oct->fn_list.disable_input_queue = cn83xx_disable_input_queue;
	oct->fn_list.disable_output_queue = cn83xx_disable_output_queue;
	
	oct->fn_list.force_io_queues_off = cn83xx_force_io_queues_off;

	oct->fn_list.dump_registers = cn83xx_dump_pf_initialized_regs;

	if (cn83xx_setup_reg_address(oct))
		goto free_barx;

	/* Get the TRS and SRN from RINFO */
	epf_rinfo = octeon_read_csr64(oct, CN83XX_SDP_EPF_RINFO(oct->epf_num));

	epf_srn = epf_rinfo & 0x3f;
	epf_trs = (epf_rinfo >> 16) & 0xff;

	if (!oct->sriov_info.num_vfs) {
		oct->drv_flags |= OCTEON_NON_SRIOV_MODE;

		cavium_print_msg(" num_vfs is zero, SRIOV is not enabled.\n");
		vf_rings = 0;
	} else {

		oct->drv_flags |= OCTEON_SRIOV_MODE;
		oct->drv_flags |= OCTEON_MBOX_CAPABLE;

		if (oct->sriov_info.num_vfs >= epf_trs) {
			cavium_error
			    ("OCTEON: Cann't create %d VFs, Invalid numvfs \n",
			     oct->sriov_info.num_vfs);
			goto free_barx;
		}
		if (oct->sriov_info.num_vfs > CN83XX_MAX_VF) {
			cavium_error("OTX kernel supports upto %d VFs\n",
					CN83XX_MAX_VF);
			oct->sriov_info.num_vfs = CN83XX_MAX_VF;
		}

		vf_rings = 8;

		/** VF can support MAX up to 8 IOQs */
		if (vf_rings > CN83XX_MAX_RINGS_PER_VF)
			vf_rings = CN83XX_MAX_RINGS_PER_VF;

		do {
			/** RPVF should be a power of 2, supported values are 0,1,2,4,8 */
			if (vf_rings & (vf_rings - 1)) {
				vf_rings = lowerpow2roundup(vf_rings);
			}

			if ((vf_rings * oct->sriov_info.num_vfs) >
			    (epf_trs - 8)) {
				cavium_error
				    ("%s Required queue number exceeds total rings\n",
				     __FUNCTION__);
				vf_rings -= 1;
				continue;
			}
			break;
		} while (1);
	}

	oct->sriov_info.rings_per_vf = vf_rings;
	/** All the remaining queues are handled by Physical Function */
	oct->sriov_info.pf_srn = epf_srn + (vf_rings * oct->sriov_info.num_vfs);
	oct->sriov_info.rings_per_pf = 8;

	oct->sriov_info.sriov_enabled = 0;

	/** Over Write the config values with the calculated ones */
	CFG_GET_NUM_VFS(cn83xx->conf, oct->pf_num) = oct->sriov_info.num_vfs;
	CFG_GET_RINGS_PER_VF(cn83xx->conf, oct->pf_num) =
	    oct->sriov_info.rings_per_vf;
	CFG_GET_TOTAL_PF_RINGS(cn83xx->conf, oct->pf_num) = epf_trs;
	CFG_GET_IQ_MAX_BASE_Q(CHIP_FIELD(oct, cn83xx_pf, conf)) =
	    oct->sriov_info.rings_per_pf;
	CFG_GET_OQ_MAX_BASE_Q(CHIP_FIELD(oct, cn83xx_pf, conf)) =
	    oct->sriov_info.rings_per_pf;

	cavium_print_msg(" OCTEON PF[%d] IOQ CONFIGURATION \n", oct->pf_num);
	cavium_print_msg(" PF[%d] TOTAL NUMBER OF RINGS:%u \n", oct->pf_num,
			 CFG_GET_TOTAL_PF_RINGS(cn83xx->conf, oct->pf_num));
	cavium_print_msg(" PF[%d] RINGS PER PF:%u \n", oct->pf_num,
			 oct->sriov_info.rings_per_pf);
	cavium_print_msg(" PF[%d] STARTING RING NUMBER:%u \n", oct->pf_num,
			 oct->sriov_info.pf_srn);
	cavium_print_msg(" PF[%d] TOTAL NUMBER OF VFs:%u \n", oct->pf_num,
			 oct->sriov_info.num_vfs);
	cavium_print_msg(" PF[%d] RINGS PER VF:%u \n", oct->pf_num,
			 oct->sriov_info.rings_per_vf);

	return 0;

free_barx:
	octeon_unmap_pci_barx(oct, 0);
	octeon_unmap_pci_barx(oct, 1);
	return -1;

}

int validate_cn83xx_pf_config_info(cn83xx_pf_config_t * conf83xx)
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
