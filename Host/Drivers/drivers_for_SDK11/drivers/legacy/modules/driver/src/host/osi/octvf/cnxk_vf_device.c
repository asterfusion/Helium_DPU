/* Copyright (c) 2020 Marvell.
 * SPDX-License-Identifier: GPL-2.0
 */

#include "cavium_sysdep.h"
#include "octeon_hw.h"
#include "cnxk_vf_device.h"
#include "octeon_macros.h"
#include "octeon-pci.h"


#define FW_TO_HOST 0x2
#define HOST_TO_FW 0x1
//int g_app_mode[2] = {CVM_DRV_APP_START, CVM_DRV_APP_START};
enum info_exhg_state {
	/* State where F/W isn't posted anything */
	NO_EXHG,
	/* State where Host posts its ring info */
	RINFO_HOST,
	/* State where F/W acks the host ring info */
	RINFO_FW_ACK
};

struct fw_handshake_wrk {
	octeon_device_t *oct;
	enum info_exhg_state exhg_state;
};


void cnxk_dump_vf_iq_regs(octeon_device_t * oct)
{

}

void cnxk_dump_vf_initialized_regs(octeon_device_t * oct)
{
}

static int cnxk_vf_soft_reset(octeon_device_t * oct)
{
	return 0;
}

static int
cnxk_vf_send_mbox_cmd_nolock(octeon_device_t *oct_dev, union otx_vf_mbox_word cmd,
			       union otx_vf_mbox_word *rsp)
{
	volatile uint64_t reg_val = 0ull;
	volatile u8 __iomem *vf_pf_data_reg;
	int count = 0;
	long timeout = OTX_VF_MBOX_WRITE_WAIT_TIME;
	octeon_mbox_t *mbox = oct_dev->mbox[0];

	cmd.s.type = OTX_VF_MBOX_TYPE_CMD;
	vf_pf_data_reg = mbox->mbox_write_reg;

	OCTEON_WRITE64(vf_pf_data_reg, cmd.u64);
	for (count = 0; count < OTX_VF_MBOX_TIMEOUT_MS; count++) {
		schedule_timeout_uninterruptible(timeout);
		reg_val = OCTEON_READ64(vf_pf_data_reg);
		if (reg_val != cmd.u64) {
			rsp->u64 = reg_val;
			break;
		}
	}
	if (count == OTX_VF_MBOX_TIMEOUT_MS) {
		cavium_error("Mbox cmd Timeout\n");
		return -ETIMEDOUT;
	}
	rsp->u64 = reg_val;
	return 0;
}

static int
cnxk_vf_send_mbox_cmd(octeon_device_t *oct_dev, union otx_vf_mbox_word cmd,
			union otx_vf_mbox_word *rsp)
{
	volatile uint64_t reg_val = 0ull;
	volatile u8 __iomem *vf_pf_data_reg;
	unsigned long flags;
	int count = 0;
	long timeout = OTX_VF_MBOX_WRITE_WAIT_TIME;
	octeon_mbox_t *mbox = oct_dev->mbox[0];

	cavium_spin_lock_irqsave(&oct_dev->vf_mbox_lock, flags);
	if (mbox->state == OTX_VF_MBOX_STATE_BUSY) {
		spin_unlock_irqrestore(&oct_dev->vf_mbox_lock, flags);
		cavium_error("%s VF Mbox is in Busy state\n", __func__);
		return OTX_VF_MBOX_STATUS_BUSY;
	}
	mbox->state = OTX_VF_MBOX_STATE_BUSY;
	cavium_spin_unlock_irqrestore(&oct_dev->vf_mbox_lock, flags);

	cmd.s.type = OTX_VF_MBOX_TYPE_CMD;

	vf_pf_data_reg = mbox->mbox_write_reg;
	OCTEON_WRITE64(vf_pf_data_reg, cmd.u64);
	for (count = 0; count < OTX_VF_MBOX_TIMEOUT_MS; count++) {
		schedule_timeout_uninterruptible(timeout);
		reg_val = OCTEON_READ64(vf_pf_data_reg);
		if (reg_val != cmd.u64) {
			rsp->u64 = reg_val;
			break;
		}
		count++;
	}
	cavium_spin_lock_irqsave(&oct_dev->vf_mbox_lock, flags);
	if (count == OTX_VF_MBOX_TIMEOUT_MS) {
		mbox->state = OTX_VF_MBOX_STATE_IDLE;
		cavium_error("Mbox cmd Timeout\n");
		spin_unlock_irqrestore(&oct_dev->vf_mbox_lock, flags);
		return -ETIMEDOUT;
	}
	mbox->state = OTX_VF_MBOX_STATE_IDLE;
	spin_unlock_irqrestore(&oct_dev->vf_mbox_lock, flags);

	rsp->u64 = reg_val;
	return 0;
}

void cnxk_dump_regs(octeon_device_t * oct, int qno)
{
	printk("VF IQ register dump\n");
	printk("R[%d]_IN_INSTR_DBELL[0x%llx]: 0x%016llx\n", qno,
		CNXK_VF_SDP_R_IN_INSTR_DBELL(qno), octeon_read_csr64(oct,
		CNXK_VF_SDP_R_IN_INSTR_DBELL(qno)));
	printk("R[%d]_IN_CONTROL[0x%llx]: 0x%016llx\n", qno,
		CNXK_VF_SDP_R_IN_CONTROL(qno), octeon_read_csr64(oct,
		CNXK_VF_SDP_R_IN_CONTROL(qno)));
	printk("R[%d]_IN_ENABLE[0x%llx]: 0x%016llx\n", qno,
		CNXK_VF_SDP_R_IN_ENABLE(qno), octeon_read_csr64(oct,
		CNXK_VF_SDP_R_IN_ENABLE(qno)));
	printk("R[%d]_IN_INSTR_BADDR[0x%llx]: 0x%016llx\n", qno,
		CNXK_VF_SDP_R_IN_INSTR_BADDR(qno), octeon_read_csr64(oct,
		CNXK_VF_SDP_R_IN_INSTR_BADDR(qno)));
	printk("R[%d]_IN_INSTR_RSIZE[0x%llx]: 0x%016llx\n", qno,
		CNXK_VF_SDP_R_IN_INSTR_RSIZE(qno), octeon_read_csr64(oct,
		CNXK_VF_SDP_R_IN_INSTR_RSIZE(qno)));
	printk("R[%d]_IN_CNTS[0x%llx]: 0x%016llx\n", qno,
		CNXK_VF_SDP_R_IN_CNTS(qno), octeon_read_csr64(oct,
		CNXK_VF_SDP_R_IN_CNTS(qno)));
	printk("R[%d]_IN_INT_LEVELS[0x%llx]: 0x%016llx\n", qno,
		CNXK_VF_SDP_R_IN_INT_LEVELS(qno), octeon_read_csr64(oct,
		CNXK_VF_SDP_R_IN_INT_LEVELS(qno)));
	printk("R[%d]_IN_PKT_CNT[0x%llx]: 0x%016llx\n", qno,
		CNXK_VF_SDP_R_IN_PKT_CNT(qno), octeon_read_csr64(oct,
		CNXK_VF_SDP_R_IN_PKT_CNT(qno)));
	printk("R[%d]_IN_BYTE_CNT[0x%llx]: 0x%016llx\n", qno,
		CNXK_VF_SDP_R_IN_BYTE_CNT(qno), octeon_read_csr64(oct,
		CNXK_VF_SDP_R_IN_BYTE_CNT(qno)));

	printk("VF OQ register dump\n");
	printk("R[%d]_OUT_SLIST_DBELL[0x%llx]: 0x%016llx\n", qno,
		CNXK_VF_SDP_R_OUT_SLIST_DBELL(qno), octeon_read_csr64(oct,
		CNXK_VF_SDP_R_OUT_SLIST_DBELL(qno)));
	printk("R[%d]_OUT_CONTROL[0x%llx]: 0x%016llx\n", qno,
		CNXK_VF_SDP_R_OUT_CONTROL(qno), octeon_read_csr64(oct,
		CNXK_VF_SDP_R_OUT_CONTROL(qno)));
	printk("R[%d]_OUT_ENABLE[0x%llx]: 0x%016llx\n", qno,
		CNXK_VF_SDP_R_OUT_ENABLE(qno), octeon_read_csr64(oct,
		CNXK_VF_SDP_R_OUT_ENABLE(qno)));
	printk("R[%d]_OUT_SLIST_BADDR[0x%llx]: 0x%016llx\n", qno,
		CNXK_VF_SDP_R_OUT_SLIST_BADDR(qno), octeon_read_csr64(oct,
		CNXK_VF_SDP_R_OUT_SLIST_BADDR(qno)));
	printk("R[%d]_OUT_SLIST_RSIZE[0x%llx]: 0x%016llx\n", qno,
		CNXK_VF_SDP_R_OUT_SLIST_RSIZE(qno), octeon_read_csr64(oct,
		CNXK_VF_SDP_R_OUT_SLIST_RSIZE(qno)));
	printk("R[%d]_OUT_CNTS[0x%llx]: 0x%016llx\n", qno,
		CNXK_VF_SDP_R_OUT_CNTS(qno), octeon_read_csr64(oct,
		CNXK_VF_SDP_R_OUT_CNTS(qno)));
	printk("R[%d]_OUT_INT_LEVELS[0x%llx]: 0x%016llx\n", qno,
		CNXK_VF_SDP_R_OUT_INT_LEVELS(qno), octeon_read_csr64(oct,
		CNXK_VF_SDP_R_OUT_INT_LEVELS(qno)));
	printk("R[%d]_OUT_PKT_CNT[0x%llx]: 0x%016llx\n", qno,
		CNXK_VF_SDP_R_OUT_PKT_CNT(qno), octeon_read_csr64(oct,
		CNXK_VF_SDP_R_OUT_PKT_CNT(qno)));
	printk("R[%d]_OUT_BYTE_CNT[0x%llx]: 0x%016llx\n", qno,
		CNXK_VF_SDP_R_OUT_BYTE_CNT(qno), octeon_read_csr64(oct,
		CNXK_VF_SDP_R_OUT_BYTE_CNT(qno)));
}

/* VSR: removed cnxk_enable_vf_error_reporting(), unused, incorrect and not needed */

int cnxk_vf_reset_iq(octeon_device_t * oct, int q_no)
{
	volatile uint64_t d64 = 0ULL;
	uint64_t loop = CAVIUM_TICKS_PER_SEC;

	/* There is no RST for a ring. 
	 * Clear all registers one by one after disabling the ring
	 */

	octeon_write_csr64(oct, CNXK_VF_SDP_R_IN_ENABLE(q_no), d64);

	octeon_write_csr64(oct, CNXK_VF_SDP_R_IN_INSTR_BADDR(q_no), d64);

	octeon_write_csr64(oct, CNXK_VF_SDP_R_IN_INSTR_RSIZE(q_no), d64);

	d64 = 0xFFFFFFFF;
	octeon_write_csr64(oct, CNXK_VF_SDP_R_IN_INSTR_DBELL(q_no), d64);
	d64 =
	    octeon_read_csr64(oct, CNXK_VF_SDP_R_IN_INSTR_DBELL(q_no));
	while ((d64 != 0) && loop--) {

		octeon_write_csr64(oct,
				   CNXK_VF_SDP_R_IN_INSTR_DBELL(q_no), d64);
		cavium_sleep_timeout(1);
		d64 = octeon_read_csr64(oct,
					CNXK_VF_SDP_R_IN_INSTR_DBELL(q_no));
	}

	d64 =
	    octeon_read_csr64(oct, CNXK_VF_SDP_R_IN_CNTS(q_no));

	loop = CAVIUM_TICKS_PER_SEC;

	while ((d64 != 0) && loop--) {
		octeon_write_csr64(oct, CNXK_VF_SDP_R_IN_CNTS(q_no), d64);
		cavium_sleep_timeout(1);
		d64 = octeon_read_csr64(oct, CNXK_VF_SDP_R_IN_CNTS(q_no));
	}
	d64 = 0;
	octeon_write_csr64(oct,
			   CNXK_VF_SDP_R_IN_INT_LEVELS(q_no), d64);

	octeon_write_csr64(oct,
			   CNXK_VF_SDP_R_IN_PKT_CNT(q_no), d64);

	octeon_write_csr64(oct,
			   CNXK_VF_SDP_R_IN_BYTE_CNT(q_no), d64);

	return 0;
}

int cnxk_vf_reset_oq(octeon_device_t * oct, int q_no)
{
	volatile uint64_t d64 = 0ULL;
	uint64_t loop = CAVIUM_TICKS_PER_SEC;

	octeon_write_csr64(oct,
			   CNXK_VF_SDP_R_OUT_ENABLE(q_no), d64);

	octeon_write_csr64(oct,
			   CNXK_VF_SDP_R_OUT_SLIST_BADDR(q_no), d64);

	octeon_write_csr64(oct,
			   CNXK_VF_SDP_R_OUT_SLIST_RSIZE(q_no), d64);

	d64 = 0xFFFFFFFF;
	octeon_write_csr64(oct,
			   CNXK_VF_SDP_R_OUT_SLIST_DBELL(q_no), d64);
	d64 =
	    octeon_read_csr64(oct,
			      CNXK_VF_SDP_R_OUT_SLIST_DBELL(q_no));

	while ((d64 != 0) && loop--) {

		octeon_write_csr64(oct,
				   CNXK_VF_SDP_R_OUT_SLIST_DBELL(q_no), d64);
		cavium_sleep_timeout(1);
		d64 = octeon_read_csr64(oct,
					CNXK_VF_SDP_R_OUT_SLIST_DBELL(q_no));
	}

	d64 =
	    octeon_read_csr64(oct,
			      CNXK_VF_SDP_R_OUT_CNTS(q_no));

	loop = CAVIUM_TICKS_PER_SEC;

	while ((d64 != 0) && (loop--)) {
		octeon_write_csr64(oct,
				   CNXK_VF_SDP_R_OUT_CNTS(q_no), d64);
		cavium_sleep_timeout(1);
		d64 = octeon_read_csr64(oct,
					CNXK_VF_SDP_R_OUT_CNTS(q_no));
	}

	d64 = 0;
	octeon_write_csr64(oct,
			   CNXK_VF_SDP_R_OUT_INT_LEVELS(q_no), d64);

	octeon_write_csr64(oct,
			   CNXK_VF_SDP_R_OUT_PKT_CNT(q_no), d64);

	octeon_write_csr64(oct,
			   CNXK_VF_SDP_R_OUT_BYTE_CNT(q_no), d64);

	return 0;
}

static void cnxk_vf_setup_global_iq_reg(octeon_device_t * oct, int q_no)
{
	volatile uint64_t reg_val = 0ULL;

	/* Select ES, RO, NS, RDSIZE,DPTR Fomat#0 for IQs 
	 * IS_64B is by default enabled.
	 */
	reg_val =
	    octeon_read_csr64(oct,
			      CNXK_VF_SDP_R_IN_CONTROL(q_no));

	reg_val |= CNXK_R_IN_CTL_RDSIZE;
	reg_val |= CNXK_R_IN_CTL_IS_64B;
	reg_val |= CNXK_R_IN_CTL_ESR;


	octeon_write_csr64(oct,
			   CNXK_VF_SDP_R_IN_CONTROL(q_no), reg_val);
	reg_val = octeon_read_csr64(oct, CNXK_VF_SDP_R_IN_CONTROL(q_no));

	if (!(reg_val & CNXK_R_IN_CTL_IDLE)) {
		do {
			reg_val =
			    octeon_read_csr64(oct,
					      CNXK_VF_SDP_R_IN_CONTROL(q_no));
		} while (!(reg_val & CNXK_R_IN_CTL_IDLE));
	}
}

static void cnxk_vf_setup_global_oq_reg(octeon_device_t * oct, int q_no)
{
	volatile uint64_t reg_val = 0ULL;
	reg_val =
	    octeon_read_csr64(oct,
			      CNXK_VF_SDP_R_OUT_CONTROL(q_no));

	reg_val &= ~(CNXK_R_OUT_CTL_IMODE);
	reg_val &= ~(CNXK_R_OUT_CTL_ROR_P);
	reg_val &= ~(CNXK_R_OUT_CTL_ES_I | CNXK_R_OUT_CTL_ES_D);
	reg_val &= ~(CNXK_R_OUT_CTL_NSR_P);
	reg_val &= ~(CNXK_R_OUT_CTL_ROR_I);
	reg_val &= ~(CNXK_R_OUT_CTL_NSR_I);
	reg_val &= ~(CNXK_R_OUT_CTL_ROR_D);
	reg_val &= ~(CNXK_R_OUT_CTL_NSR_D);


	/* INFO/DATA ptr swap is required on cn10k  */
	reg_val |= (CNXK_R_OUT_CTL_ES_P);

	octeon_write_csr64(oct,
			   CNXK_VF_SDP_R_OUT_CONTROL(q_no), reg_val);
}

uint32_t cnxk_get_oq_ticks(octeon_device_t * oct, uint32_t time_intr_in_us)
{
	/* This gives the SLI clock per microsec */
	uint32_t oqticks_per_us =
	    CFG_GET_COPROC_TICS_PER_US(CHIP_FIELD(oct, cnxk_vf, conf));

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

int cnxk_vf_reset_input_queues(octeon_device_t * oct)
{
	int q_no = 0;
	cavium_print(PRINT_DEBUG, " %s : OCTEON_CNXK VF\n", __FUNCTION__);

	for (q_no = 0; q_no < oct->sriov_info.rings_per_vf; q_no++) {
		cnxk_vf_reset_iq(oct, q_no);
	}
	return 0;
}

int cnxk_vf_reset_output_queues(octeon_device_t * oct)
{
	uint64_t q_no = 0ULL;
	cavium_print(PRINT_DEBUG, " %s : OCTEON_CNXK PF\n", __FUNCTION__);

	for (q_no = 0; q_no < oct->sriov_info.rings_per_vf; q_no++) {
		cnxk_vf_reset_oq(oct, q_no);
	}
	return 0;
}

static void cnxk_vf_setup_global_input_regs(octeon_device_t * oct)
{
	uint64_t q_no = 0ULL;

	/* Select ES, RO, NS, RDSIZE,DPTR Fomat#0 for 
	 * the Input Queues 
	 */
	cnxk_vf_reset_input_queues(oct);
	for (q_no = 0; q_no < (oct->rings_per_vf); q_no++) {
		cnxk_vf_setup_global_iq_reg(oct, q_no);
	}
}

void cnxk_vf_setup_global_output_regs(octeon_device_t * oct)
{
	uint32_t q_no;

	cnxk_vf_reset_output_queues(oct);
	for (q_no = 0; q_no < (oct->rings_per_vf); q_no++) {
		cnxk_vf_setup_global_oq_reg(oct, q_no);
	}
}

static int cnxk_setup_vf_device_regs(octeon_device_t * oct)
{
	cnxk_vf_setup_global_input_regs(oct);
	cnxk_vf_setup_global_output_regs(oct);

	return 0;
}

static void cnxk_setup_vf_iq_regs(octeon_device_t * oct, int iq_no)
{
	volatile uint64_t reg_val = 0ULL;
	octeon_instr_queue_t *iq = oct->instr_queue[iq_no];
	octeon_cnxk_vf_t *cnxk = (octeon_cnxk_vf_t *) oct->chip;

	reg_val =
	    octeon_read_csr64(oct,
			      CNXK_VF_SDP_R_IN_CONTROL(iq_no));

	/* wait for IDLE to set to 1, as cannot configure BADDR as long as IDLE is 0 */
	if (!(reg_val & CNXK_R_IN_CTL_IDLE)) {
		do {
			reg_val =
			    octeon_read_csr64(oct,
					      CNXK_VF_SDP_R_IN_CONTROL(iq_no));
		}
		while (!(reg_val & CNXK_R_IN_CTL_IDLE));
	}

	/* Write the start of the input queue's ring and its size  */
	octeon_write_csr64(oct,
			   CNXK_VF_SDP_R_IN_INSTR_BADDR(iq_no),
			   iq->base_addr_dma);
	octeon_write_csr64(oct,
			   CNXK_VF_SDP_R_IN_INSTR_RSIZE(iq_no),
			   iq->max_count);

	/* Remember the doorbell & instruction count register addr 
	 * for this queue 
	 */
	iq->doorbell_reg = (uint8_t *) oct->mmio[0].hw_addr
	    + CNXK_VF_SDP_R_IN_INSTR_DBELL(iq_no);
	iq->inst_cnt_reg = (uint8_t *) oct->mmio[0].hw_addr
	    + CNXK_VF_SDP_R_IN_CNTS(iq_no);
	iq->intr_lvl_reg = (uint8_t *) oct->mmio[0].hw_addr
	   + CNXK_VF_SDP_R_IN_INT_LEVELS(iq_no);

	cavium_print(PRINT_DEBUG,
		     "InstQ[%d]:dbell reg @ 0x%p instcnt_reg @ 0x%p\n", iq_no,
		     iq->doorbell_reg, iq->inst_cnt_reg);

	/* Store the current instruction counter (used in flush_iq calculation) */
	do {
		iq->reset_instr_cnt = OCTEON_READ32(iq->inst_cnt_reg);
		OCTEON_WRITE32(iq->inst_cnt_reg, iq->reset_instr_cnt);
	} while (iq->reset_instr_cnt !=  0);

	/*
	 * Set IQ interrupt threshold to 10usec wait, or packets based
	 * on config.
	 */
	reg_val = (CFG_GET_IQ_INTR_THRESHOLD(cnxk->conf) & 0xffffffff)
		  | (10UL << 32);
	octeon_write_csr64(oct, CNXK_VF_SDP_R_IN_INT_LEVELS(iq_no), reg_val);

	if(OCT_IQ_ISM) {
		octeon_write_csr64(oct, CNXK_SDP_R_IN_CNTS_ISM(iq_no), (iq->ism.pkt_cnt_dma)|0x1ULL);
		iq->in_cnts_ism = (uint8_t *) oct->mmio[0].hw_addr
		    + CNXK_SDP_R_IN_CNTS_ISM(iq_no);
	}
}

static void cnxk_setup_vf_oq_regs(octeon_device_t * oct, int oq_no)
{
	volatile uint64_t reg_val = 0ULL;
	uint64_t time_threshold = 0ULL, oq_ctl = 0ULL;
	//uint64_t loop = CAVIUM_TICKS_PER_SEC;
	octeon_droq_t *droq = oct->droq[oq_no];
	octeon_cnxk_vf_t *cnxk = (octeon_cnxk_vf_t *) oct->chip;

	reg_val =
	    octeon_read_csr64(oct,
			      CNXK_VF_SDP_R_OUT_CONTROL(oq_no));

	/* wait for IDLE to set to 1, as cannot configure BADDR as long as IDLE is 0 */
	if (!(reg_val & CNXK_R_OUT_CTL_IDLE)) {
		do {
			reg_val =
			    octeon_read_csr64(oct,
					      CNXK_VF_SDP_R_OUT_CONTROL(oq_no));
		}
		while (!(reg_val & CNXK_R_OUT_CTL_IDLE));
	}

	octeon_write_csr64(oct,
			   CNXK_VF_SDP_R_OUT_SLIST_BADDR(oq_no),
			   droq->desc_ring_dma);
	octeon_write_csr64(oct,
			   CNXK_VF_SDP_R_OUT_SLIST_RSIZE(oq_no),
			   droq->max_count);

	oq_ctl =
	    octeon_read_csr64(oct,
			      CNXK_VF_SDP_R_OUT_CONTROL(oq_no));
	oq_ctl &= ~0x7fffffULL;	//clear the ISIZE and BSIZE (22-0)
	oq_ctl |= (droq->buffer_size & 0xffff);	//populate the BSIZE (15-0)
	octeon_write_csr64(oct,
			   CNXK_VF_SDP_R_OUT_CONTROL(oq_no), oq_ctl);

	/* Get the mapped address of the pkt_sent and pkts_credit regs */
	droq->pkts_sent_reg = (uint8_t *) oct->mmio[0].hw_addr +
	    CNXK_VF_SDP_R_OUT_CNTS(oq_no);
	droq->pkts_credit_reg = (uint8_t *) oct->mmio[0].hw_addr +
	    CNXK_VF_SDP_R_OUT_SLIST_DBELL(oq_no);

	reg_val =
	    octeon_read_csr64(oct,
			      CNXK_VF_SDP_R_OUT_INT_LEVELS(oq_no));
	/* VSR: TODO: this line does not make sense;
	 * it is overwritten in next line
	 */
#if 0
	time_threshold = cnxk_get_oq_ticks(oct, (uint32_t)
						CFG_GET_OQ_INTR_TIME
						(cnxk->conf));
#endif
	time_threshold = CFG_GET_OQ_INTR_TIME(cnxk->conf);
	printk("OQ Interrupt Thresholds: Timer:0x%X Counter:0x%X\n",
			CFG_GET_OQ_INTR_TIME(cnxk->conf), CFG_GET_OQ_INTR_PKT(cnxk->conf));
	/*TODO: commented to avoid compilation error. need to resolve */
	reg_val = ((time_threshold & 0x3fffff) <<
		   CNXK_R_OUT_INT_LEVELS_TIMET) |
		  CFG_GET_OQ_INTR_PKT(cnxk->conf);

	octeon_write_csr64(oct,
			   CNXK_VF_SDP_R_OUT_INT_LEVELS(oq_no), reg_val);
	reg_val =
	    octeon_read_csr64(oct,
			      CNXK_VF_SDP_R_OUT_INT_LEVELS(oq_no));
	printk("SDP_R[%d]_OUT_INT_LEVELS:%llx\n", oq_no, reg_val);

	if (OCT_DROQ_ISM)
	{
		droq->out_cnts_ism = (uint8_t *) oct->mmio[0].hw_addr +
		    CNXK_SDP_R_OUT_CNTS_ISM(oq_no);
		octeon_write_csr64(oct, CNXK_SDP_R_OUT_CNTS_ISM(oq_no), (droq->ism.pkt_cnt_dma) | 0x1ULL);
	}

#if 0 // ??? Disabled for 93xx, not sure why
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
#endif
}

static void cnxk_setup_vf_mbox_regs(octeon_device_t * oct, int q_no)
{
	octeon_mbox_t *mbox = oct->mbox[q_no];

	mbox->q_no = q_no;
	mbox->state = OTX_VF_MBOX_STATE_IDLE;

	/* PF mbox interrupt reg */
	mbox->mbox_int_reg = (uint8_t *) oct->mmio[0].hw_addr +
	    CNXK_VF_SDP_R_MBOX_PF_VF_INT(q_no);

	/* PF to VF DATA reg. PF writes into this reg */
	mbox->mbox_write_reg = (uint8_t *) oct->mmio[0].hw_addr +
	    CNXK_VF_SDP_R_MBOX_VF_PF_DATA(q_no);

	/* VF to PF DATA reg. PF reads from this reg */
	mbox->mbox_read_reg = (uint8_t *) oct->mmio[0].hw_addr +
	    CNXK_VF_SDP_R_MBOX_PF_VF_DATA(q_no);

}

static void cnxk_enable_vf_input_queue(octeon_device_t * oct, int q_no)
{
	volatile uint64_t reg_val = 0ULL;
	uint64_t loop = CAVIUM_TICKS_PER_SEC;

	/* Resetting doorbells during IQ enabling also to handle abrupt guest reboot.
	 * IQ reset does not clear the doorbells.*/
	octeon_write_csr64(oct,
			   CNXK_VF_SDP_R_IN_INSTR_DBELL(q_no),
			   0xFFFFFFFF);

	while (((octeon_read_csr64(oct,
				   CNXK_VF_SDP_R_IN_INSTR_DBELL(q_no))) != 0ULL)
	       && loop--) {
		cavium_sleep_timeout(1);
	}

	reg_val = octeon_read_csr64(oct,  CNXK_SDP_R_IN_INT_LEVELS(q_no));
	reg_val |= (0x1ULL << 62);
	octeon_write_csr64(oct, CNXK_SDP_R_IN_INT_LEVELS(q_no), reg_val);

	reg_val = octeon_read_csr64(oct,
				    CNXK_VF_SDP_R_IN_ENABLE(q_no));
	reg_val |= 0x1ULL;

	octeon_write_csr64(oct,
			   CNXK_VF_SDP_R_IN_ENABLE(q_no),
			   reg_val);

}

static void cnxk_enable_vf_output_queue(octeon_device_t * oct, int q_no)
{
	volatile uint64_t reg_val = 0ULL;

	reg_val = octeon_read_csr64(oct, CNXK_VF_SDP_R_OUT_INT_LEVELS(q_no));
	reg_val |= (0x1ULL << 62);
	octeon_write_csr64(oct, CNXK_VF_SDP_R_OUT_INT_LEVELS(q_no), reg_val);
	 
	octeon_write_csr64(oct,
			   CNXK_VF_SDP_R_OUT_SLIST_DBELL(q_no),
			   0xFFFFFFFF);

	reg_val = octeon_read_csr64(oct,
				    CNXK_VF_SDP_R_OUT_ENABLE(q_no));
	reg_val |= 0x1ULL;

	octeon_write_csr64(oct,
			   CNXK_VF_SDP_R_OUT_ENABLE(q_no),
			   reg_val);
}

static void cnxk_enable_vf_io_queues(octeon_device_t * oct)
{
	int q_no = 0;

	for (q_no = 0; q_no < oct->num_iqs; q_no++) {
		cnxk_enable_vf_input_queue(oct, q_no);
		cnxk_enable_vf_output_queue(oct, q_no);
	}
}

static void cnxk_disable_vf_input_queue(octeon_device_t * oct, int q_no)
{
	uint64_t loop = CAVIUM_TICKS_PER_SEC;
	volatile uint64_t reg_val = 0ULL;

	loop = CAVIUM_TICKS_PER_SEC;

	/* Reset the doorbell register for this Input Queue. */
	reg_val = octeon_read_csr64(oct,
				    CNXK_VF_SDP_R_IN_ENABLE(q_no));
	reg_val &= ~0x1ULL;

	octeon_write_csr64(oct,
			   CNXK_VF_SDP_R_IN_ENABLE(q_no),
			   reg_val);
}

static void cnxk_disable_vf_output_queue(octeon_device_t * oct, int q_no)
{
	volatile uint64_t reg_val = 0ULL;

	reg_val = octeon_read_csr64(oct,
				    CNXK_VF_SDP_R_OUT_ENABLE(q_no));
	reg_val &= ~0x1ULL;

	octeon_write_csr64(oct,
			   CNXK_VF_SDP_R_OUT_ENABLE(q_no), reg_val);
}

static void cnxk_disable_vf_io_queues(octeon_device_t * oct)
{
	int q_no = 0;

	/*** Disable Input Queues. ***/
	for (q_no = 0; q_no < oct->num_iqs; q_no++) {
		cnxk_disable_vf_input_queue(oct, q_no);
		cnxk_disable_vf_output_queue(oct, q_no);
	}
}

void cnxk_handle_vf_mbox_intr(octeon_ioq_vector_t * ioq_vector)
{
	OCTEON_WRITE64(ioq_vector->mbox->mbox_int_reg,
		       OCTEON_READ64(ioq_vector->mbox->mbox_int_reg));
}

// *INDENT-OFF*
cvm_intr_return_t
cnxk_vf_msix_interrupt_handler(void  *dev)
{
	octeon_ioq_vector_t *ioq_vector = (octeon_ioq_vector_t *) dev;
	octeon_droq_t *droq = ioq_vector->droq;

	cavium_print(PRINT_FLOW, " In %s octeon_dev @ %p  \n",
		     __CVM_FUNCTION__, droq->oct_dev);

	droq->ops.napi_fun((void *)droq);
	return CVM_INTR_HANDLED;
}
// *INDENT-ON*

static void cnxk_reinit_regs(octeon_device_t * oct)
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

#if OCT_IQ_ISM
static uint32_t cnxk_update_read_index(octeon_instr_queue_t * iq)
{
	u32 new_idx;
	u32 last_done;
	u32 pkt_in_done = iq->ism.pkt_cnt_addr[iq->ism.index];

	/* Request new ISM write */
	OCTEON_WRITE64(iq->inst_cnt_reg, 1UL << 63);

	last_done = pkt_in_done - iq->pkt_in_done;
	iq->pkt_in_done = pkt_in_done;

#define OCTEON_PKT_IN_DONE_CNT_MASK (0x00000000FFFFFFFFULL)
	new_idx = (iq->octeon_read_index +
		   (u32)(last_done & OCTEON_PKT_IN_DONE_CNT_MASK)) %
		  iq->max_count;

	return new_idx;
}
#else
static uint32_t cnxk_update_read_index(octeon_instr_queue_t * iq)
{
	u32 new_idx;
	u32 last_done;
	u32 pkt_in_done = OCTEON_READ32(iq->inst_cnt_reg);

	/* When there is no response to PCI read */
	if (pkt_in_done == 0xFFFFFFFF) {
		last_done = 0;
		printk("VF detected PCIe read error F's in %s \n",__func__);
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
#endif

static void cnxk_enable_vf_interrupt(void *chip, uint8_t intr_flag)
{
	octeon_cnxk_vf_t *cnxk = (octeon_cnxk_vf_t *) chip;
	octeon_device_t *oct = (octeon_device_t *) cnxk->oct;
	uint32_t q_no;

	for (q_no = 0; q_no < oct->rings_per_vf; q_no++) {
		octeon_write_csr64(oct,
				   CNXK_VF_SDP_R_MBOX_PF_VF_INT(q_no), 0x2ULL);
	}
	cavium_print_msg("VF MBOX interrupts enabled.\n");
}

static void cnxk_disable_vf_interrupt(void *chip, uint8_t intr_flag)
{
	volatile uint64_t reg_val = 0ULL;
	octeon_cnxk_vf_t *cnxk = (octeon_cnxk_vf_t *) chip;
	octeon_device_t *oct = (octeon_device_t *) cnxk->oct;
	uint32_t q_no;

	for (q_no = 0; q_no < oct->rings_per_vf; q_no++) {
		reg_val =
		    octeon_read_csr64(oct,
				      CNXK_VF_SDP_R_MBOX_PF_VF_INT(q_no));
		reg_val &= ~(0x2ULL);
		octeon_write_csr64(oct,
				   CNXK_VF_SDP_R_MBOX_PF_VF_INT(q_no), reg_val);
	}
	cavium_print_msg("VF MBOX interrupts disabled.\n");
}


void cnxk_force_io_queues_off(octeon_device_t * oct)
{
	uint64_t reg_val = 0ULL, q_no = 0ULL, srn = 0ULL, ern = 0ULL;

	cavium_print_msg(" %s : OCTEON_CNXK VF\n", __FUNCTION__);

	srn = oct->sriov_info.pf_srn;
	ern = srn + oct->sriov_info.rings_per_vf;

	for (q_no = srn; q_no < ern; q_no++) {

		reg_val = octeon_read_csr64(oct,
					    CNXK_SDP_R_IN_ENABLE(q_no));
		reg_val &= ~0x1ULL;
		octeon_write_csr64(oct,
				   CNXK_SDP_R_IN_ENABLE(q_no), reg_val);

		reg_val = octeon_read_csr64(oct,
					    CNXK_SDP_R_OUT_ENABLE(q_no));
		reg_val &= ~0x1ULL;
		octeon_write_csr64(oct,
				   CNXK_SDP_R_OUT_ENABLE(q_no), reg_val);
	}
}

int setup_cnxk_octeon_vf_device(octeon_device_t * oct)
{
	uint64_t reg_val = 0ULL;
	octeon_cnxk_vf_t *cnxk = (octeon_cnxk_vf_t *) oct->chip;
	//Should always be 0
	oct->epf_num = 0;
	//oct->pcie_port = 2; //for pem2 

	cnxk->oct = oct;

	if (octeon_map_pci_barx(oct, 0, 0))
		return -1;

	cnxk->conf = (cnxk_vf_config_t *) oct_get_config_info(oct);
	if (cnxk->conf == NULL) {
		cavium_error("%s No Config found for CNXK\n", __FUNCTION__);
		octeon_unmap_pci_barx(oct, 0);
		return -1;
	}

	reg_val =
	    octeon_read_csr64(oct,
			      CNXK_VF_SDP_R_IN_CONTROL(0));
	oct->rings_per_vf = ((reg_val >> CNXK_R_IN_CTL_RPVF_POS) &
			     CNXK_R_IN_CTL_RPVF_MASK);

	/* Need to set this here, as on PF it is set as part of host/device
	 * handshake, and there is no handshake for the VF.
	 */
	oct->sriov_info.rings_per_vf = oct->rings_per_vf;

	cavium_print_msg("RINGS PER VF ARE:::%d\n", oct->rings_per_vf);

	oct->drv_flags |= OCTEON_MSIX_CAPABLE;
	oct->drv_flags |= OCTEON_MBOX_CAPABLE;
	oct->drv_flags |= OCTEON_MSIX_AFFINITY_CAPABLE;

	oct->fn_list.setup_iq_regs = cnxk_setup_vf_iq_regs;
	oct->fn_list.setup_oq_regs = cnxk_setup_vf_oq_regs;
	oct->fn_list.setup_mbox_regs = cnxk_setup_vf_mbox_regs;

	oct->fn_list.msix_interrupt_handler = cnxk_vf_msix_interrupt_handler;

	oct->fn_list.soft_reset = cnxk_vf_soft_reset;
	oct->fn_list.setup_device_regs = cnxk_setup_vf_device_regs;
	oct->fn_list.reinit_regs = cnxk_reinit_regs;
	oct->fn_list.update_iq_read_idx = cnxk_update_read_index;

	oct->fn_list.enable_interrupt = cnxk_enable_vf_interrupt;
	oct->fn_list.disable_interrupt = cnxk_disable_vf_interrupt;

	oct->fn_list.enable_io_queues = cnxk_enable_vf_io_queues;
	oct->fn_list.disable_io_queues = cnxk_disable_vf_io_queues;

	oct->fn_list.enable_input_queue = cnxk_enable_vf_input_queue;
	oct->fn_list.enable_output_queue = cnxk_enable_vf_output_queue;

	oct->fn_list.disable_input_queue = cnxk_disable_vf_input_queue;
	oct->fn_list.disable_output_queue = cnxk_disable_vf_output_queue;

	oct->fn_list.dump_registers = cnxk_dump_vf_initialized_regs;

	oct->fn_list.send_mbox_cmd = cnxk_vf_send_mbox_cmd;
	oct->fn_list.send_mbox_cmd_nolock = cnxk_vf_send_mbox_cmd_nolock;

	return 0;
}

int validate_cnxk_vf_config_info(cnxk_vf_config_t * conf_cnxk)
{
	uint64_t total_instrs = 0ULL;

	if (CFG_GET_IQ_MAX_Q(conf_cnxk) > CNXK_MAX_INPUT_QUEUES) {
		cavium_error("%s: Num IQ (%d) exceeds Max (%d)\n",
			     __CVM_FUNCTION__, CFG_GET_IQ_MAX_Q(conf_cnxk),
			     CNXK_MAX_INPUT_QUEUES);
		return 1;
	}

	if (CFG_GET_OQ_MAX_Q(conf_cnxk) > CNXK_MAX_OUTPUT_QUEUES) {
		cavium_error("%s: Num OQ (%d) exceeds Max (%d)\n",
			     __CVM_FUNCTION__, CFG_GET_OQ_MAX_Q(conf_cnxk),
			     CNXK_MAX_OUTPUT_QUEUES);
		return 1;
	}

	if (CFG_GET_IQ_INSTR_TYPE(conf_cnxk) != OCTEON_32BYTE_INSTR &&
	    CFG_GET_IQ_INSTR_TYPE(conf_cnxk) != OCTEON_64BYTE_INSTR) {
		cavium_error("%s: Invalid instr type for IQ\n",
			     __CVM_FUNCTION__);
		return 1;
	}

	if (!(CFG_GET_IQ_NUM_DESC(conf_cnxk)) || !(CFG_GET_IQ_DB_MIN(conf_cnxk))
	    || !(CFG_GET_IQ_DB_TIMEOUT(conf_cnxk))) {
		cavium_error("%s: Invalid parameter for IQ\n",
			     __CVM_FUNCTION__);
		return 1;
	}

	total_instrs =
	    CFG_GET_IQ_NUM_DESC(conf_cnxk) * CFG_GET_IQ_MAX_Q(conf_cnxk);

	if (CFG_GET_IQ_PENDING_LIST_SIZE(conf_cnxk) < total_instrs) {
		cavium_error
		    ("%s Pending list size (%d) should be >= total instructions queue size (%d)\n",
		     __CVM_FUNCTION__, CFG_GET_IQ_PENDING_LIST_SIZE(conf_cnxk),
		     (int)total_instrs);
		return 1;
	}

	if (!(CFG_GET_OQ_INFO_PTR(conf_cnxk)) ||
	    !(CFG_GET_OQ_PKTS_PER_INTR(conf_cnxk)) ||
	    !(CFG_GET_OQ_NUM_DESC(conf_cnxk)) ||
	    !(CFG_GET_OQ_REFILL_THRESHOLD(conf_cnxk)) ||
	    !(CFG_GET_OQ_BUF_SIZE(conf_cnxk))) {
		cavium_error("%s: Invalid parameter for OQ\n",
			     __CVM_FUNCTION__);
		return 1;
	}

	if (!(CFG_GET_OQ_INTR_TIME(conf_cnxk))) {
		cavium_error("%s: Invalid parameter for OQ\n",
			     __CVM_FUNCTION__);
		return 1;
	}

	return 0;
}

/* $Id$ */
