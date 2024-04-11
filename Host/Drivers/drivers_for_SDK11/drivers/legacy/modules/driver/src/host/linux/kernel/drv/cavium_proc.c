/* Copyright (c) 2020 Marvell.
 * SPDX-License-Identifier: GPL-2.0
 */

#include "octeon_main.h"
#include "octeon_macros.h"
#include "octeon_debug.h"
#include "cavium_proc.h"
#include "cvm_linux_types.h"
#include "octeon_hw.h"

#include "octeon_reg_defs.h"
#include "octeon_mem_ops.h"

#ifdef PCIE_AER
/* Enable this macro to generate pcie aer bus errors by writing to aer_gen_err 
 * proc entry */
//#define  GENERATE_PCIE_AER_MSG
#endif

#ifdef CAVIUM_DEBUG
static char debug_level_str[5][30] = { "only error messages",
	" register values ",
	"error & debug messages",
	"error, flow & debug messages",
	"all messages"
};
#endif

/* Buffer pool statistics maintained in another file. */
extern uint32_t buffer_stats[], alloc_buffer_stats[], fragment_buf_stats[];
extern uint32_t other_pools[];

uint64_t addr;

uint64_t  proc_iq_mask = 0xffffffffffffffffULL;

int cn83xx_pf_read_csrreg_buf(struct seq_file *s, octeon_device_t * oct);
int cn93xx_pf_read_csrreg_buf(struct seq_file *s, octeon_device_t * oct);
int cn83xx_pf_read_configreg_buf(struct seq_file *s, octeon_device_t * oct);
#ifdef GENERATE_PCIE_AER_MSG
extern pci_ers_result_t
octeon_pcie_error_detected(struct pci_dev *pdev, pci_channel_state_t state);
#endif

#define REGBUFSIZE (4096)

void print_stats(struct seq_file *s, octeon_device_t * oct_dev)
{
	int i;
	uint64_t total_diff_bytes = 0;
	uint64_t diff_bytes = 0;
	octeon_pending_list_t *plist;

	seq_printf(s, "Octeon (Status: %s)\n",
		   get_oct_state_string(&oct_dev->status));

#ifdef CAVIUM_DEBUG
	seq_printf(s, "Debug Level: %d\n", octeon_debug_level);
#endif

	seq_printf(s, "jiffies: %lu\n", jiffies);


	seq_printf(s, " IQ ");
	seq_printf(s, "\t Instr processed   ");
	seq_printf(s, "\t Instr dropped     ");
	seq_printf(s, "\t Bytes Sent        ");
	seq_printf(s, "\t sgentry_sent      ");
	seq_printf(s, "\t Inst Cnt reg      ");
	seq_printf(s, "\t Bytes since last  ");


// *INDENT-OFF*
   for(i = 0; i < oct_dev->num_iqs; i++) {
       seq_printf(s,"\n %d ", i);

       seq_printf(s,"\t %8llu             ",
                CVM_CAST64(oct_dev->instr_queue[i]->stats.instr_processed));

       seq_printf(s,"\t %8llu            ",
                CVM_CAST64(oct_dev->instr_queue[i]->stats.instr_dropped));

       diff_bytes = oct_dev->instr_queue[i]->stats.bytes_sent
                     - oct_dev->instr_queue[i]->stats.lastbytes_sent;
       seq_printf(s,"\t %8llu            ",
                  CVM_CAST64(oct_dev->instr_queue[i]->stats.bytes_sent));

       seq_printf(s,"\t %8llu            ",
                  CVM_CAST64(oct_dev->instr_queue[i]->stats.sgentry_sent));

       seq_printf(s,"\t %8x              ",
                  OCTEON_READ32(oct_dev->instr_queue[i]->inst_cnt_reg));

       seq_printf(s,"\t %8llu            ", CVM_CAST64(diff_bytes));

       total_diff_bytes += diff_bytes;
}
// *INDENT-ON*
	seq_printf(s, "\n Total Bytes since last:");
	seq_printf(s, " %8llu  ", CVM_CAST64(total_diff_bytes));

	seq_printf(s,
		   "\n____________________________________________________________________\n");

	seq_printf(s, " DROQ ");
	seq_printf(s, "\t Pkts Received         ");
	seq_printf(s, "\t Bytes Received        ");
	seq_printf(s, "\t Bytes since last      ");
	seq_printf(s, "\t Pkts dropped ( No Dispatch + No Memory )");
	total_diff_bytes = 0;
// *INDENT-OFF*
   for(i = 0; i < oct_dev->num_oqs; i++) {

       seq_printf(s,"\n %d ", i);
       seq_printf(s,"\t %8llu      ",
                  CVM_CAST64(oct_dev->droq[i]->stats.pkts_received));

       diff_bytes = oct_dev->droq[i]->stats.bytes_received
                       - oct_dev->droq[i]->stats.lastbytes_received;

       seq_printf(s,"\t\t %8llu      ",
                  CVM_CAST64(oct_dev->droq[i]->stats.bytes_received));
   
       seq_printf(s,"\t\t %8llu     ", CVM_CAST64(diff_bytes));

       seq_printf(s,"\t\t %8llu ",
                  CVM_CAST64(oct_dev->droq[i]->stats.dropped_nodispatch));

       seq_printf(s,"\t+ %8llu ",
                  CVM_CAST64(oct_dev->droq[i]->stats.dropped_nomem));
       
       total_diff_bytes += diff_bytes;

   }
// *INDENT-ON*

	seq_printf(s, "\n Total Bytes since last:");
	seq_printf(s, "%8llu  ", CVM_CAST64(total_diff_bytes));

	for (i = 0; i < oct_dev->num_iqs; i++) {
		plist =
		    (octeon_pending_list_t *) oct_dev->instr_queue[i]->plist;
		seq_printf(s, "\nInstr_queue: %d  Pending free index: %u", i,
			   (plist->free_index));
	}

	seq_printf(s,
		   "\n____________________________________________________________________\n");

	/*Output buffer count should be lower than page size allocated */
	if (s->count < s->size) {
		for (i = 0; i < oct_dev->num_iqs; i++)
			oct_dev->instr_queue[i]->stats.lastbytes_sent =
			    oct_dev->instr_queue[i]->stats.bytes_sent;
		for (i = 0; i < oct_dev->num_oqs; i++)
			oct_dev->droq[i]->stats.lastbytes_received =
			    oct_dev->droq[i]->stats.bytes_received;
	}

	return;
}

static void
fill_iq_status(octeon_device_t * oct, int iq_no, struct seq_file *str)
{
	octeon_instr_queue_t *iq = oct->instr_queue[iq_no];

	seq_printf(str, "\nIQ %d\n-----------\n", iq_no);

	seq_printf(str, ">> Configurations\n");

	seq_printf(str,
		   "Entries: %d Instr Size: %d DB Fill Threshold: %d Timeout: %lu\n",
		   iq->max_count,
		   (oct->io_qmask.iq64B & (1 << iq_no)) ? 64 : 32,
		   iq->fill_threshold, iq->db_timeout);

	seq_printf(str, ">> Status\n");

	seq_printf(str, "Instr Pending: %d Fill Count: %d Threshold: %d\n",
		   cavium_atomic_read(&iq->instr_pending), iq->fill_cnt,
		   iq->fill_threshold);

	seq_printf(str, "Index  Write: %d  Read: %d Flush: %d\n",
		   iq->host_write_index, iq->octeon_read_index,
		   iq->flush_index);

	seq_printf(str, "Registers InstrCnt: %d DoorBell: %d\n",
		   OCTEON_READ32(iq->inst_cnt_reg),
		   OCTEON_READ32(iq->doorbell_reg));

}

static void
fill_droq_status(octeon_device_t * oct, int oq_no, struct seq_file *str)
{
	octeon_droq_t *droq = oct->droq[oq_no];

	seq_printf(str, "\nDROQ %d\n--------------\n", oq_no);
	seq_printf(str, ">> Configuration\n");

	seq_printf(str,
		   "Entries: %d Buffer Size: %d Pkts_per_intr: %d Refill Threshold: %d\n",
		   droq->max_count, droq->buffer_size, droq->pkts_per_intr,
		   droq->refill_threshold);

	switch (oct->chip_id) {

	case OCTEON_CN83XX_ID_PF:
		seq_printf(str, "Intr Threshold Registers Pkt: %d Time: %d\n",
			   octeon_read_csr(oct,
					   CN83XX_SDP_EPF_R_OUT_INT_LEVELS(0, oq_no)),
			   octeon_read_csr(oct,
					   (CN83XX_SDP_EPF_R_OUT_INT_LEVELS
					   (0, oq_no) + 4)));
		break;
	}

	seq_printf(str, ">> Status\n");

	seq_printf(str, "Packets Pending: %u Refill Count: %u\n",
		   droq->pkts_pending, droq->refill_count);

	seq_printf(str, "Index  Read: %d Refill: %d\n",
		   droq->host_read_index, droq->host_refill_index);

	seq_printf(str, "Register PktsSent: %d PktsCredit: 0x%08x\n",
		   OCTEON_READ32(droq->pkts_sent_reg),
		   OCTEON_READ32(droq->pkts_credit_reg));

}

void print_status(struct seq_file *s, octeon_device_t * oct)
{
	int i;
	octeon_pending_list_t *plist;

	seq_printf(s, "\nChip Id: 0x%x  Status: %d (%s)\n", oct->chip_id,
		   cavium_atomic_read(&oct->status),
		   get_oct_state_string(&oct->status));
	switch (oct->chip_id) {

	case OCTEON_CN83XX_ID_PF:
		seq_printf(s, "Interrupt Mask: 0x%016llx  ",
			   CVM_CAST64(CHIP_FIELD(oct, cn83xx_pf, intr_mask64)));
		break;
	}

	seq_printf(s, "Interrupts: %u\n", cavium_atomic_read(&oct->interrupts));

#ifdef CAVIUM_DEBUG
	seq_printf(s, "Debug Level: %d\n", octeon_debug_level);
#endif

	for (i = 0; i < oct->num_iqs; i++) {
		plist = (octeon_pending_list_t *) oct->instr_queue[i]->plist;
		seq_printf(s,
			   "\nInstr_queue: %d Pending List Size: %d free_idx: %d pending: %d\n",
			   i, oct->instr_queue[i]->pend_list_size,
			   plist->free_index,
			   cavium_atomic_read(&plist->instr_count));
	}

	seq_printf(s, "Input Queues: %d Output Queues: %d\n\n",
		   oct->num_iqs, oct->num_oqs);

	for (i = 0; i < oct->num_iqs; i++)
		fill_iq_status(oct, i, s);

	for (i = 0; i < oct->num_oqs; i++)
		fill_droq_status(oct, i, s);
}

static int stats_show(struct seq_file *s, void *v UNUSED)
{
	octeon_device_t *oct = (octeon_device_t *) s->private;
	print_stats(s, oct);
	return 0;
}

static int status_show(struct seq_file *s, void *v UNUSED)
{
	octeon_device_t *oct = (octeon_device_t *) s->private;
	print_status(s, oct);
	return 0;
}

#define MAX_TEST_IQS   64
//#define MAX_TEST_SIZES 7
#define MAX_TEST_SIZES 6
static int tidx = 0;
//static uint32_t test_size[MAX_TEST_SIZES] = {64, 64, 64, 64, 64, 64, 64};
//static uint32_t test_size[MAX_TEST_SIZES] = {2048, 64, 128, 256, 360, 512, 1024};
static uint32_t test_size[MAX_TEST_SIZES] = { 64, 128, 256, 512, 1024, 2048 };


static inline uint32_t _get_next_data_size(void)
{
	tidx = (tidx + 1) % MAX_TEST_SIZES;
	return test_size[tidx];
}

void run_perf_test_83(octeon_device_t * oct)
{
	octeon_instr_queue_t *iq;
	uint8_t *data, *cdata;
	uint64_t iq_mask = proc_iq_mask;
	uint32_t iq_no = 0, wr_idx = 0;
	uint32_t curr_rd_cnt[MAX_TEST_IQS], last_rd_cnt[MAX_TEST_IQS],
	    datasize = 64, run_time = 20;
	unsigned long start_jiffies, end_jiffies, total_pkts = 0, total_bytes =
	    0;
	octeon_instr3_64B_t o3_cmd;
	octeon_instr_irh_t irh = {0};
	octeon_instr_pki_ih3_t pki_ih3;
    octeon_instr_ihx_t ihx;

	if (cavium_atomic_read(&oct->status) != OCT_DEV_RUNNING) {
		printk("%s: OCTEON device not in running state\n",
		       __FUNCTION__);
		return;
	}

	data = cavium_malloc_dma(4096, __CAVIUM_MEM_ATOMIC);
	if (data == NULL)
		return;

	/* revert these changes when oct-pci-csr works */
	datasize = _get_next_data_size();
	octeon_write_csr64(oct, CN83XX_SDP_SCRATCH(0), datasize);
	if (datasize == 64 || datasize == 128 || datasize == 256
	    || datasize == 512 || datasize == 1024 || datasize == 2048) {
		printk("%s: OCTEON ...proceeding with test for %d bytes\n",
		       __FUNCTION__, datasize);
	} else {
		datasize = 64;
		printk
		    ("%s: OCTEON ...proceeding with test for %d bytes scratch was %llu\n",
		     __FUNCTION__, datasize, octeon_read_csr64(oct,
							       CN83XX_SDP_SCRATCH(0)));
	}
	/* For bi-directional tests, the octeon application uses the size in
	   scratch register to determine the size, same as IQ perf. Host interrupt
	   handler does not look into pkt to determine size. We provide a hint here. */

    memset(&ihx, 0, sizeof(octeon_instr_ihx_t));
    memset(&pki_ih3, 0, sizeof(octeon_instr_pki_ih3_t));
	memset(&o3_cmd, 0, 64);
	memset(last_rd_cnt, 0, sizeof(uint32_t) * MAX_TEST_IQS);
	memset(curr_rd_cnt, 0, sizeof(uint32_t) * MAX_TEST_IQS);

	ihx.pkind = oct->pkind;
    ihx.gather = 0;
	ihx.fsz = 0x10;
	ihx.tlen = datasize + ihx.fsz;

	pki_ih3.w = 1;
	pki_ih3.raw = 1;
	pki_ih3.utag = 1;
	pki_ih3.uqpg = 1;
	pki_ih3.utt = 1;
	pki_ih3.tagtype = NULL_TAG;
	pki_ih3.qpg = 0x0;
	pki_ih3.pm = 0x7;
	pki_ih3.sl = 8;
	pki_ih3.tag = 0x11111100;

	irh.opcode = CVMCS_REQRESP_OP;

	o3_cmd.ih3 = *((uint64_t *) & ihx);
	o3_cmd.irh = *((uint64_t *) & irh);
    //assigned later
//	o3_cmd.pki_ih3 = *((uint64_t *) & pki_ih3);


	printk("%s: data buf @ %p\n", __FUNCTION__, data);
	printk("%s: ihx: 0x%016llx\n", __FUNCTION__, o3_cmd.ih3);
    printk("ihx.pknd: 0x%x, fsz: 0x%x, teln: 0x%x, gather: 0x%x\n", ihx.pkind, ihx.fsz, ihx.tlen, ihx.gather);
	printk("%s: pki_ih: 0x%016llx\n", __FUNCTION__, o3_cmd.pki_ih3);
	printk("%s: irh:  0x%016llx\n", __FUNCTION__, o3_cmd.irh);
    
    /* swapping FSZ here */
    octeon_swap_8B_data(&o3_cmd.irh, 1);

	while ((iq_no < 64) && (iq_mask & (1ULL << iq_no))) {
		iq = oct->instr_queue[iq_no];

		/* If a queue doesn't exist, turn off the mask bit for it. No more testing on that queue. */
		if (iq == NULL) {
			iq_mask &= ~(1ULL << iq_no);
			continue;
		}

		wr_idx = 0;
		last_rd_cnt[iq_no] = OCTEON_READ32(iq->inst_cnt_reg);
		printk
		    ("%s: OCTEON read_cnt: %d. Starting write to all %d descriptors for queue %d\n",
		     __FUNCTION__, last_rd_cnt[iq_no], iq->max_count, iq_no);
		while (wr_idx <  iq->max_count) {

			pki_ih3.tag = 0x11111100 + wr_idx + (iq_no << 12);
			pki_ih3.qpg = wr_idx % 4;	//0x0;
			o3_cmd.pki_ih3 = *((uint64_t *) & pki_ih3);
            octeon_swap_8B_data(&o3_cmd.pki_ih3, 1);

			cdata = data + ((datasize * wr_idx) % 4096);
			o3_cmd.dptr =
			    (uint64_t) octeon_pci_map_single(oct->pci_dev,
							     (void *)cdata,
							     datasize,
							     CAVIUM_PCI_DMA_TODEVICE);
#if 0                
	        printk("%s: data buf @ %p, dptr: 0x%016llx\n", __FUNCTION__, cdata, o3_cmd.dptr);
            {
                int i =0;
                for(i=0; i<8; i++)
                    printk("word[%d]: 0x%016llx\n", i, *( (uint64_t *)&o3_cmd + i));


            }
#endif            
//			cavium_memcpy(iq->base_addr + (64 * wr_idx), &o3_cmd, 64);
    		cavium_memcpy(iq->base_addr + (32 * wr_idx), &o3_cmd,
				      32);
			wr_idx++;
		}

		last_rd_cnt[iq_no] = OCTEON_READ32(iq->inst_cnt_reg);
		OCTEON_WRITE32(iq->doorbell_reg, wr_idx);
		printk
		    ("Posted %d instructions...waiting for OCTEON to fetch rd_cnt: %d\n",
		     wr_idx, last_rd_cnt[iq_no]);

		iq_no++;
	}

	/* Reset IQ number to 0. */
	iq_no = 0;

#define  fetched_pkt_cnt(iq_no)  (curr_rd_cnt[iq_no] - last_rd_cnt[iq_no])

	start_jiffies = jiffies;
	end_jiffies = jiffies + (run_time * HZ);

	while (jiffies < end_jiffies) {

		/* If this queue is not included in the mask, go to the next one. */
		if (!(iq_mask & (1ULL << iq_no))) {
			iq_no++;
			if (iq_no == MAX_TEST_IQS)
				iq_no = 0;

			cavium_schedule();
			continue;
		}

		if (iq_no >= 64) {
			//printk(">>>>Error iqno is %u\n", iq_no);
			iq_no = 0;
			continue;
		}

		iq = oct->instr_queue[iq_no];

		curr_rd_cnt[iq_no] = OCTEON_READ32(iq->inst_cnt_reg);
		if (fetched_pkt_cnt(iq_no)) {
//              cavium_schedule();
			total_pkts += fetched_pkt_cnt(iq_no);
			total_bytes += (fetched_pkt_cnt(iq_no) * datasize);
			OCTEON_WRITE32(iq->doorbell_reg,
				       fetched_pkt_cnt(iq_no));
//            printk("OCTEON fetched %u instructions from iq %d curr_rd_cnt: %u last_rd_cnt: %u db: %u\n", fetched_pkt_cnt(iq_no), iq_no, curr_rd_cnt[iq_no], last_rd_cnt[iq_no], OCTEON_READ32(iq->doorbell_reg));
			last_rd_cnt[iq_no] = curr_rd_cnt[iq_no];
		}

		iq_no++;
		cavium_schedule();
	}

	printk("OCTEON processed %lu pkts and %lu bytes in %lu jiffies\n",
	       total_pkts, total_bytes, (jiffies - start_jiffies));

	/* OCTEON may be fetching more of the last doorbell. We are not waiting
	   to count them but wait nevertheless before you free the buffer. */
	cavium_sleep_timeout(HZ);

	octeon_pci_unmap_single(oct->pci_dev, o3_cmd.dptr, datasize,
				CAVIUM_PCI_DMA_TODEVICE);
	cavium_free_dma(data);
}

static int iq_perf_show(struct seq_file *s, void *v UNUSED)
{
	octeon_device_t *oct = (octeon_device_t *) s->private;
	cavium_print_msg("check for iq mask %llx\n", proc_iq_mask);
	if (proc_iq_mask)
	    switch (oct->chip_id) {
            case OCTEON_CN83XX_ID_PF:
           		run_perf_test_83(oct);
                break;
       }
	cavium_print_msg("return from iq_perf_show\n");
	return 0;
}

static int csrreg_show(struct seq_file *s, void *v UNUSED)
{
	octeon_device_t *oct = (octeon_device_t *) s->private;

	switch (oct->chip_id) {

	case OCTEON_CN83XX_ID_PF:
		return cn83xx_pf_read_csrreg_buf(s, oct);
	case OCTEON_CN93XX_ID_PF:
	case OCTEON_CN98XX_ID_PF:
	case OCTEON_CN10KA_ID_PF:
		return cn93xx_pf_read_csrreg_buf(s, oct);
	}

	return 0;
}

static int configreg_show(struct seq_file *s, void *v UNUSED)
{
	octeon_device_t *oct = (octeon_device_t *) s->private;

	switch (oct->chip_id) {

	case OCTEON_CN83XX_ID_PF:
		return cn83xx_pf_read_configreg_buf(s, oct);
	}

	return 0;
}

static ssize_t
write_iq_mask(struct file *file, const char __user * buffer, size_t count,
	      loff_t * offp)
{
	char str[19];
	count = count > sizeof(str) ? sizeof(str) : count;

	CVM_MOD_INC_USE_COUNT;

	if (cavium_copy_in(str, buffer, count)) {
		cavium_error("cavium_copy_in failed\n");
		CVM_MOD_DEC_USE_COUNT;
		return -EFAULT;
	}
	if ((str[0] == '0') && (str[1] == 'x')) {
		str[18] = '\0';
		sscanf(str + 2, "%llx", &proc_iq_mask);
	} else {
		str[16] = '\0';
		sscanf(str, "%llx", &proc_iq_mask);
	}

	cavium_print_msg("proc iq mask::%llx\n", proc_iq_mask);

	CVM_MOD_DEC_USE_COUNT;

	return count;
}

static ssize_t
write_csr(struct file *file, const char __user * buffer, size_t count,
	  loff_t * offp)
{
	char str[19];
	count = count > sizeof(str) ? sizeof(str) : count;

	CVM_MOD_INC_USE_COUNT;

	if (cavium_copy_in(str, buffer, count)) {
		cavium_error("cavium_copy_in failed\n");
		CVM_MOD_DEC_USE_COUNT;
		return -EFAULT;
	}
	if ((str[0] == '0') && (str[1] == 'x')) {
		str[18] = '\0';
		sscanf(str + 2, "%llx", &addr);
	} else {
		str[16] = '\0';
		sscanf(str, "%llx", &addr);
	}

	CVM_MOD_DEC_USE_COUNT;

	return count;
}

#ifdef GENERATE_PCIE_AER_MSG
static ssize_t
proc_write_aer_gen_err(struct file *file, const char __user * buffer,
		       size_t count, loff_t * offp)
{
	char str[10], *strend;
	int val;
	struct seq_file *seq = file->private_data;
	void *data = seq->private;
	count = count > sizeof(str) ? sizeof(str) : count;

	CVM_MOD_INC_USE_COUNT;

	if (cavium_copy_in(str, buffer, count)) {
		cavium_error("cavium_copy_in failed\n");
		CVM_MOD_DEC_USE_COUNT;
		return -EFAULT;
	}
	str[count] = '\0';

	val = simple_strtoul(str, &strend, 0);

	if (val == 1)
		octeon_pcie_error_detected(((octeon_device_t *) data)->pci_dev,
					   pci_channel_io_normal);
	if (val == 2)
		octeon_pcie_error_detected(((octeon_device_t *) data)->pci_dev,
					   pci_channel_io_frozen);
	if (val == 3)
		octeon_pcie_error_detected(((octeon_device_t *) data)->pci_dev,
					   pci_channel_io_perm_failure);

	CVM_MOD_DEC_USE_COUNT;

	return count;
}

static int aer_gen_err_show(struct seq_file *s, void *v)
{
	return 0;
}

#endif
static int read_csr_show(struct seq_file *s, void *v)
{
	octeon_device_t *oct = (octeon_device_t *) s->private;

	seq_printf(s, "\n[0x%016llx] : 0x%016llx\n", addr,
		   octeon_read_csr64(oct, addr));
	return 0;
}

#ifdef CAVIUM_DEBUG
static ssize_t
proc_write_debug_level(struct file *file, const char __user * buffer,
		       size_t count, loff_t * offp)
{
	char str[10], *strend;
	int val;
	count = count > sizeof(str) ? sizeof(str) : count;

	CVM_MOD_INC_USE_COUNT;

	if (cavium_copy_in(str, buffer, count)) {
		cavium_error("cavium_copy_in failed\n");
		CVM_MOD_DEC_USE_COUNT;
		return -EFAULT;
	}
	str[count] = '\0';

	val = simple_strtoul(str, &strend, 0);
	octeon_debug_level = val;
	cavium_print(PRINT_MSG, "Octeon Debug Level set to print %s\n",
		     debug_level_str[octeon_debug_level]);

	CVM_MOD_DEC_USE_COUNT;

	return count;
}

static int print_debug_level(struct seq_file *s, void *v)
{
	CVM_MOD_INC_USE_COUNT;
	seq_printf(s, "Octeon debug level: %d [%s]\n", octeon_debug_level,
		   debug_level_str[octeon_debug_level]);
	CVM_MOD_DEC_USE_COUNT;
	return 0;
}

static int debug_level_show(struct seq_file *s, void *v)
{
	print_debug_level(s, NULL);
	return 0;
}
#endif

static void *proc_seq_start(struct seq_file *s UNUSED, loff_t * pos)
{

	/* beginning a new sequence ? */
	if (*pos == 0) {
		/* yes => return a non null value to begin the sequence */
		return SEQ_START_TOKEN;
	} else {
		/* no => it's the end of the sequence, return end to stop reading */
		return NULL;
	}
}

static void *proc_seq_next(struct seq_file *s UNUSED, void *v UNUSED,
			   loff_t * pos UNUSED)
{
	return NULL;		/* nothing to do */
}

static void proc_seq_stop(struct seq_file *s UNUSED, void *v UNUSED)
{
	/* nothing to do */
}

#ifdef CAVIUM_DEBUG
static struct seq_operations debug_level_seq_ops = {
	.start = proc_seq_start,
	.next = proc_seq_next,
	.stop = proc_seq_stop,
	.show = debug_level_show
};
#endif

#ifdef GENERATE_PCIE_AER_MSG
static struct seq_operations aer_gen_err_seq_ops = {
	.start = proc_seq_start,
	.next = proc_seq_next,
	.stop = proc_seq_stop,
	.show = aer_gen_err_show
};
#endif

static struct seq_operations stats_seq_ops = {
	.start = proc_seq_start,
	.next = proc_seq_next,
	.stop = proc_seq_stop,
	.show = stats_show
};

static struct seq_operations status_seq_ops = {
	.start = proc_seq_start,
	.next = proc_seq_next,
	.stop = proc_seq_stop,
	.show = status_show
};

static struct seq_operations iq_perf_seq_ops = {
	.start = proc_seq_start,
	.next = proc_seq_next,
	.stop = proc_seq_stop,
	.show = iq_perf_show
};

static struct seq_operations csrreg_seq_ops = {
	.start = proc_seq_start,
	.next = proc_seq_next,
	.stop = proc_seq_stop,
	.show = csrreg_show
};

static struct seq_operations configreg_seq_ops = {
	.start = proc_seq_start,
	.next = proc_seq_next,
	.stop = proc_seq_stop,
	.show = configreg_show
};

static struct seq_operations entry_seq_ops = {
	.start = proc_seq_start,
	.next = proc_seq_next,
	.stop = proc_seq_stop
};

static struct seq_operations read_csr_seq_ops = {
	.start = proc_seq_start,
	.next = proc_seq_next,
	.stop = proc_seq_stop,
	.show = read_csr_show
};

static int read_csr_open(struct inode *inode, struct file *file)
{
	int ret = seq_open(file, &read_csr_seq_ops);
	if (!ret) {
		struct seq_file *seq = file->private_data;
#if  LINUX_VERSION_CODE >= KERNEL_VERSION(3,10,0)
		seq->private = PDE_DATA(file_inode(file));
#else
		struct proc_dir_entry *proc = PDE(inode);
		seq->private = proc->data;
#endif
	}
	return ret;

}

#ifdef CAVIUM_DEBUG
static int debug_level_open(struct inode *inode, struct file *file)
{
	int ret = seq_open(file, &debug_level_seq_ops);
	if (!ret) {
		struct seq_file *seq = file->private_data;
#if  LINUX_VERSION_CODE >= KERNEL_VERSION(3,10,0)
		seq->private = PDE_DATA(file_inode(file));
#else
		struct proc_dir_entry *proc = PDE(inode);
		seq->private = proc->data;
#endif
	}
	return ret;

}
#endif

#ifdef GENERATE_PCIE_AER_MSG
static int aer_gen_err_open(struct inode *inode, struct file *file)
{
	int ret = seq_open(file, &aer_gen_err_seq_ops);
	if (!ret) {
		struct seq_file *seq = file->private_data;
#if  LINUX_VERSION_CODE >= KERNEL_VERSION(3,10,0)
		seq->private = PDE_DATA(file_inode(file));
#else
		struct proc_dir_entry *proc = PDE(inode);
		seq->private = proc->data;
#endif
	}
	return ret;

}
#endif

static int stats_open(struct inode *inode, struct file *file)
{
	int ret = seq_open(file, &stats_seq_ops);
	if (!ret) {
		struct seq_file *seq = file->private_data;
#if  LINUX_VERSION_CODE >= KERNEL_VERSION(3,10,0)
		seq->private = PDE_DATA(file_inode(file));
#else
		struct proc_dir_entry *proc = PDE(inode);
		seq->private = proc->data;
#endif
	}
	return ret;

}

static int status_open(struct inode *inode, struct file *file)
{
	int ret = seq_open(file, &status_seq_ops);
	if (!ret) {
		struct seq_file *seq = file->private_data;
#if  LINUX_VERSION_CODE >= KERNEL_VERSION(3,10,0)
		seq->private = PDE_DATA(file_inode(file));
#else
		struct proc_dir_entry *proc = PDE(inode);
		seq->private = proc->data;
#endif
	}
	return ret;

}

static int iq_perf_open(struct inode *inode, struct file *file)
{
	int ret = seq_open(file, &iq_perf_seq_ops);
	if (!ret) {
		struct seq_file *seq = file->private_data;
#if  LINUX_VERSION_CODE >= KERNEL_VERSION(3,10,0)
		seq->private = PDE_DATA(file_inode(file));
#else
		struct proc_dir_entry *proc = PDE(inode);
		seq->private = proc->data;
#endif
	}
	return ret;

}

static int csrreg_open(struct inode *inode, struct file *file)
{
	int ret = seq_open(file, &csrreg_seq_ops);
	if (!ret) {
		struct seq_file *seq = file->private_data;
#if  LINUX_VERSION_CODE >= KERNEL_VERSION(3,10,0)
		seq->private = PDE_DATA(file_inode(file));
#else
		struct proc_dir_entry *proc = PDE(inode);
		seq->private = proc->data;
#endif
	}
	return ret;

}

static int configreg_open(struct inode *inode, struct file *file)
{
	int ret = seq_open(file, &configreg_seq_ops);
	if (!ret) {
		struct seq_file *seq = file->private_data;
#if  LINUX_VERSION_CODE >= KERNEL_VERSION(3,10,0)
		seq->private = PDE_DATA(file_inode(file));
#else
		struct proc_dir_entry *proc = PDE(inode);
		seq->private = proc->data;
#endif
	}
	return ret;

}

static int entry_open(struct inode *inode, struct file *file)
{
	int ret = seq_open(file, &entry_seq_ops);
	if (!ret) {
		struct seq_file *seq = file->private_data;
#if  LINUX_VERSION_CODE >= KERNEL_VERSION(3,10,0)
		seq->private = PDE_DATA(file_inode(file));
#else
		struct proc_dir_entry *proc = PDE(inode);
		seq->private = proc->data;
#endif
	}
	return ret;

}

#ifdef CAVIUM_DEBUG
struct file_operations proc_debug_level_fops = {
open:	debug_level_open,
read:	seq_read,
write:	proc_write_debug_level
};
#endif

#ifdef GENERATE_PCIE_AER_MSG
struct file_operations proc_aer_gen_err_fops = {
open:	aer_gen_err_open,
read:	seq_read,
write:	proc_write_aer_gen_err
};
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(5,6,0)
struct file_operations proc_stats_fops = {
open:	stats_open,
read:	seq_read
#else
struct proc_ops proc_stats_fops = {
proc_open:	stats_open,
proc_read:	seq_read
#endif
};

#if LINUX_VERSION_CODE < KERNEL_VERSION(5,6,0)
struct file_operations proc_status_fops = {
open:	status_open,
read:	seq_read
#else
struct proc_ops proc_status_fops = {
proc_open:	status_open,
proc_read:	seq_read
#endif
};

#if LINUX_VERSION_CODE < KERNEL_VERSION(5,6,0)
struct file_operations proc_iq_perf_fops = {
open:	iq_perf_open,
read:	seq_read,
write:	write_iq_mask
#else
struct proc_ops proc_iq_perf_fops = {
proc_open:	iq_perf_open,
proc_read:	seq_read,
proc_write:	write_iq_mask
#endif
};

#if LINUX_VERSION_CODE < KERNEL_VERSION(5,6,0)
struct file_operations proc_csrregs_fops = {
open:	csrreg_open,
read:	seq_read,
#else
struct proc_ops proc_csrregs_fops = {
proc_open:	csrreg_open,
proc_read:	seq_read,
#endif
};

#if LINUX_VERSION_CODE < KERNEL_VERSION(5,6,0)
struct file_operations proc_configregs_fops = {
open:	configreg_open,
read:	seq_read
#else
struct proc_ops proc_configregs_fops = {
proc_open:	configreg_open,
proc_read:	seq_read
#endif
};

#if LINUX_VERSION_CODE < KERNEL_VERSION(5,6,0)
struct file_operations entry_fops = {
open:	entry_open,
read:	seq_read
#else
struct proc_ops entry_fops = {
proc_open:	entry_open,
proc_read:	seq_read
#endif
};

#if LINUX_VERSION_CODE < KERNEL_VERSION(5,6,0)
struct file_operations read_csr_fops = {
open:	read_csr_open,
read:	seq_read,
write:	write_csr
#else
struct proc_ops read_csr_fops = {
proc_open:	read_csr_open,
proc_read:	seq_read,
proc_write:	write_csr
#endif
};

int octeon_add_proc_entry(int oct_id, octeon_proc_entry_t * entry)
{
	octeon_device_t *octeon_dev = get_octeon_device(oct_id);
	struct proc_dir_entry *proc_entry;

	if (entry->type & OCTEON_PROC_READ) {
		entry_seq_ops.show = entry->proc_show;
	}

	if (entry->type & OCTEON_PROC_WRITE)
#if LINUX_VERSION_CODE < KERNEL_VERSION(5,6,0)
		entry_fops.write = entry->proc_write;
#else
		entry_fops.proc_write = entry->proc_write;
#endif

	if (octeon_dev == NULL) {
		cavium_error("OCTEON: %s: Invalid Octeon id %d \n",
			     __CVM_FUNCTION__, oct_id);
		return ENODEV;
	}

	proc_entry = cavium_proc_create_data(entry->name, entry->attributes,
					     octeon_dev->proc_root_dir,
					     &entry_fops, octeon_dev);
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,26)
	proc_entry->proc_fops = &entry_fops;
	proc_entry->data = octeon_dev;
#endif

	if (proc_entry == NULL) {
		cavium_error("OCTEON: Failed to add proc entry for %s\n",
			     entry->name);
		return ENOMEM;
	}
	SET_PROC_OWNER(proc_entry);

	return 0;
}

int octeon_delete_proc_entry(int oct_id, char *name)
{
	octeon_device_t *octeon_dev = get_octeon_device(oct_id);

	if (octeon_dev == NULL) {
		cavium_error
		    ("OCTEON: Invalid Octeon id %d in delete_proc_entry\n",
		     oct_id);
		return ENODEV;
	}
	remove_proc_entry(name, octeon_dev->proc_root_dir);
	return 0;
}

int cavium_init_proc(octeon_device_t * octeon_dev)
{
	int retval = -ENOMEM;
	struct proc_dir_entry *root, *node;

	/* create directory /proc/OcteonX */
	root = proc_mkdir(octeon_dev->device_name, NULL);
	if (root == NULL)
		goto proc_dir_fail;
	SET_PROC_OWNER(root);
	octeon_dev->proc_root_dir = (void *)root;

	node =
	    cavium_proc_create_data("read_csr", 0644, root, &read_csr_fops,
				    octeon_dev);
	if (node == NULL)
		goto proc_fail;
	SET_PROC_OWNER(node);
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,26)
	node->proc_fops = &read_csr_fops;
	node->data = octeon_dev;
#endif

#ifdef CAVIUM_DEBUG
	/* create debug_level */
	node =
	    cavium_proc_create_data("debug_level", 0644, root,
				    &proc_debug_level_fops, octeon_dev);
	if (node == NULL)
		goto proc_fail;
	SET_PROC_OWNER(node);
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,26)
	node->proc_fops = &proc_debug_level_fops;
	node->data = octeon_dev;
#endif
#endif

#ifdef GENERATE_PCIE_AER_MSG
	/* create debug_level */
	node =
	    cavium_proc_create_data("aer_gen_err", 0644, root,
				    &proc_aer_gen_err_fops, octeon_dev);
	if (node == NULL)
		goto proc_fail;
	SET_PROC_OWNER(node);
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,26)
	node->proc_fops = &proc_aer_gen_err_fops;
	node->data = octeon_dev;
#endif
#endif

	node =
	    cavium_proc_create_data("stats", 0444, root, &proc_stats_fops,
				    octeon_dev);
	if (node == NULL)
		goto proc_fail;
	SET_PROC_OWNER(node);
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,26)
	node->proc_fops = &proc_stats_fops;
	node->data = octeon_dev;
#endif

	node =
	    cavium_proc_create_data("configreg", 0444, root,
				    &proc_configregs_fops, octeon_dev);
	if (node == NULL)
		goto proc_fail;
	SET_PROC_OWNER(node);
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,26)
	node->proc_fops = &proc_configregs_fops;
	node->data = octeon_dev;
#endif

	node =
	    cavium_proc_create_data("iq_perf", 0644, root, &proc_iq_perf_fops,
				    octeon_dev);
	if (node == NULL)
		goto proc_fail;
	SET_PROC_OWNER(node);
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,26)
	node->proc_fops = &proc_iq_perf_fops;
	node->data = octeon_dev;
#endif

	node =
	    cavium_proc_create_data("csrreg", 0444, root, &proc_csrregs_fops,
				    octeon_dev);
	if (node == NULL)
		goto proc_fail;
	SET_PROC_OWNER(node);
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,26)
	node->proc_fops = &proc_csrregs_fops;
	node->data = octeon_dev;
#endif

	node =
	    cavium_proc_create_data("status", 0444, root, &proc_status_fops,
				    octeon_dev);
	if (node == NULL)
		goto proc_fail;
	SET_PROC_OWNER(node);
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,26)
	node->proc_fops = &proc_status_fops;
	node->data = octeon_dev;
#endif

	return 0;

proc_fail:
	cavium_delete_proc(octeon_dev);
proc_dir_fail:
	return retval;
}

void cavium_delete_proc(octeon_device_t * oct)
{
	struct proc_dir_entry *root =
	    (struct proc_dir_entry *)oct->proc_root_dir;
	if (!root)
		return;
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,10,0)
	remove_proc_entry("status", root);

	remove_proc_entry("iq_perf", root);
	remove_proc_entry("csrreg", root);
	remove_proc_entry("configreg", root);
	remove_proc_entry("read_csr", root);
	remove_proc_entry("stats", root);
#ifdef CAVIUM_DEBUG
	remove_proc_entry("debug_level", root);
#endif
#ifdef GENERATE_PCIE_AER_MSG
	remove_proc_entry("aer_gen_err", root);
#endif
	remove_proc_entry(oct->device_name, NULL);
#else
	proc_remove(root);
#endif

	return;
}

int cn83xx_pf_read_configreg_buf(struct seq_file *s, octeon_device_t * oct)
{
	int i;
	uint32_t val;

	/* PCI CONFIG Registers */

	seq_printf(s, "Octeon CN83XX PCI Config space Registers\n\n");

	for (i = 0; i <= 13; i++) {
		OCTEON_READ_PCI_CONFIG(oct, (i * 4), &val);
		seq_printf(s, "[0x%x] (Config[%d]): 0x%08x\n", (i * 4), i, val);
	}

	for (i = 30; i <= 34; i++) {
		OCTEON_READ_PCI_CONFIG(oct, (i * 4), &val);
		seq_printf(s, "[0x%x] (Config[%d]): 0x%08x\n", (i * 4), i, val);
	}

	return 0;
}

int cn83xx_pf_read_csrreg_buf(struct seq_file *s, octeon_device_t * oct)
{
	uint64_t addr = 0, tmp_addr = 0;
    int i =0;
    uint32_t offset[50] = {0x4000, 0x4008, 0x4010, 0x4018, 0x4040, 
                           0x4078, 0x4088, 0x4098, 0x40a0, 0x40c0, 
                           0x4100, 0x4120, 0x4140, 0x4160, 0x4168, 
                           0x4170, 0x4178, 0x4180, 0x4188, 0x4190, 
                           0x4198, 0x41a0, 0x41a8, 0x41b0, 0x41b8, 
                           0x41c0, 0x0};
    
    /* Reg dump of DPI registers */
    seq_printf(s, "\n############## DPI DMA ENGINES #############\n");
    for(i=0; i< 8; i++) {
        addr = 0x86e000000000 + i * (0x1ULL << 11);
        tmp_addr = 0x86e000000030 + i * (0x1ULL << 11);
        seq_printf(s, "\n\n************** DP_DMA[%d] **************\n", i);
	    for (; addr <= tmp_addr; addr += 0x8) {
        	seq_printf(s, "[0x%016llx] : 0x%016llx\n", addr,
                OCTEON_PCI_WIN_READ(oct, addr));
        }
    }

    seq_printf(s, "\n\n ***************** DPI Global registers ***********\n");
    for(i = 0 ; offset[i] !=0; i++) {
        addr = 0x86e000000000 + offset[i];
        seq_printf(s, "[0x%016llx] : 0x%016llx\n", addr,
                    OCTEON_PCI_WIN_READ(oct, addr));
    }

    for(i=0; i< 8; i++) {
        addr = 0x86e020000000 + i * (0x1ULL << 20);
        tmp_addr = 0x86e020000038 + i * (0x1ULL << 20);
        seq_printf(s, "\n\n************** DPI_VDMA[%d] **************\n", i);
	    for (; addr <= tmp_addr; addr += 0x8) {
        	seq_printf(s, "[0x%016llx] : 0x%016llx\n", addr,
                OCTEON_PCI_WIN_READ(oct, addr));
        }
        
        addr = 0x86e020000100 + i * (0x1ULL << 20);
        tmp_addr = 0x86e020000118 + i * (0x1ULL << 20);
        seq_printf(s, "\n\n************** DPI_VF[%d] **************\n", i);
	    for (; addr <= tmp_addr; addr += 0x8) {
        	seq_printf(s, "[0x%016llx] : 0x%016llx\n", addr,
                OCTEON_PCI_WIN_READ(oct, addr));
        }
    }
    /* Reg dump of IOQ registers */
    seq_printf(s, "\n\n\n############## IOQ RINGS #############\n");
	for (i = 0; i < 64; i++) {
		addr = 0x10000 + i * (0x1ULL << 17);
		tmp_addr = addr + 0x90;
        seq_printf(s, "\n\n*************** R[%d]_IN ************\n", i);
		for (; addr <= tmp_addr; addr += 0x10) {
			seq_printf(s, "[0x%016llx] : 0x%016llx\n", addr,
				   octeon_read_csr64(oct, addr));
		}
        
        addr = 0x10100 + i * (0x1ULL << 17);
		tmp_addr = addr + 0x90;
        seq_printf(s, "\n\n*************** R[%d]_OUT ************\n", i);
		for (; addr <= tmp_addr; addr += 0x10) {
			seq_printf(s, "[0x%016llx] : 0x%016llx\n", addr,
				   octeon_read_csr64(oct, addr));
		}

        addr = 0x10200 + i * (0x1ULL << 17);
		tmp_addr = addr + 0x30;
        seq_printf(s, "\n\n*************** R[%d]_MBOX ************\n", i);
		for (; addr <= tmp_addr; addr += 0x10) {
			seq_printf(s, "[0x%016llx] : 0x%016llx\n", addr,
				   octeon_read_csr64(oct, addr));
		}

        seq_printf(s, "\n\n*** R[%d]_ALL_INT, ERR_TYPE, VF_NUM ******\n", i);
        addr = 0x10300 + i * (0x1ULL << 17);
		seq_printf(s, "[0x%016llx] : 0x%016llx\n", addr,
				   octeon_read_csr64(oct, addr));
        addr = 0x10400 + i * (0x1ULL << 17);
		seq_printf(s, "[0x%016llx] : 0x%016llx\n", addr,
				   octeon_read_csr64(oct, addr));
        addr = 0x10500 + i * (0x1ULL << 17);
		seq_printf(s, "[0x%016llx] : 0x%016llx\n", addr,
				   octeon_read_csr64(oct, addr));
	}
    /* Reg Dump of INT Registers */
    seq_printf(s, "\n\n\n############## INT Registers (ignore 0x40 - 0x70 #############\n");
    addr = 0x20000;
    tmp_addr = addr + 0x200;
    for (; addr <= tmp_addr; addr += 0x10) {
			seq_printf(s, "[0x%016llx] : 0x%016llx\n", addr,
				   octeon_read_csr64(oct, addr));
		}

    addr = 0x28240;
    tmp_addr = 0x282f0;
    seq_printf(s, "Ignore 0x80 to 0xb0\n");
    for (; addr <= tmp_addr; addr += 0x10) {
			seq_printf(s, "[0x%016llx] : 0x%016llx\n", addr,
				   octeon_read_csr64(oct, addr));
		}

    addr = 0x28400;
    tmp_addr = 0x28430;
    for (; addr <= tmp_addr; addr += 0x10) {
			seq_printf(s, "[0x%016llx] : 0x%016llx\n", addr,
				   octeon_read_csr64(oct, addr));
		}

        addr = 0x28500;
		seq_printf(s, "[0x%016llx] : 0x%016llx\n", addr,
				   octeon_read_csr64(oct, addr));

        addr = 0x28510;
		seq_printf(s, "[0x%016llx] : 0x%016llx\n", addr,
				   octeon_read_csr64(oct, addr));

        addr = 0x28540;
		seq_printf(s, "[0x%016llx] : 0x%016llx\n", addr,
				   octeon_read_csr64(oct, addr));

        addr = 0x28550;
		seq_printf(s, "[0x%016llx] : 0x%016llx\n", addr,
				   octeon_read_csr64(oct, addr));

        addr = 0x28600;
		seq_printf(s, "[0x%016llx] : 0x%016llx\n", addr,
				   octeon_read_csr64(oct, addr));

        addr = 0x28680;
		seq_printf(s, "[0x%016llx] : 0x%016llx\n", addr,
				   octeon_read_csr64(oct, addr));

        addr = 0x28700;
		seq_printf(s, "[0x%016llx] : 0x%016llx\n", addr,
				   octeon_read_csr64(oct, addr));
	return 0;
}

int cn93xx_pf_read_csrreg_buf(struct seq_file *s, octeon_device_t * oct)
{
	uint64_t addr = 0, tmp_addr = 0;
    int i =0;
    int count=0, mac;
    uint32_t offset[] = {0x4000, 0x4010, 0x4018, 0x4040, 
	    		   (0x4040  | (1 << 3)), 
	    		   (0x4040  | (2 << 3)), 
	    		   (0x4040  | (3 << 3)), 
	    		   (0x4040  | (4 << 3)), 
	    		   (0x4040  | (5 << 3)), 
                           0x4078, 0x4088, 0x4098, 0x40a0, 
	    		   (0x40a0  | (1 << 3)), 
	    		   (0x40a0  | (2 << 3)), 
	    		   (0x40a0  | (3 << 3)), 
	    		   (0x40a0  | (4 << 3)), 
	    		   (0x40a0  | (5 << 3)), 
			   0x40c0, 
	    		   (0x40c0  | (1 << 3)), 
	    		   (0x40c0  | (2 << 3)), 
	    		   (0x40c0  | (3 << 3)), 
	    		   (0x40c0  | (4 << 3)), 
	    		   (0x40c0  | (5 << 3)), 
			   0x40f0, 
                           0x4100, 
	    		   (0x4100  | (1 << 3)), 
                           0x4180,
	    		   (0x4180  | (1 << 3)), 
			   0x4200,  
	    		   (0x4200  | (1 << 3)), 
			   0x4280,  
	    		   (0x4280  | (1 << 3)), 
			   0x4300, 
			   0x6600,
			   0x6600 | ( 1 << 3),
			   0x6600 | ( 2 << 3),
			   0x6600 | ( 3 << 3),
			   0x6600 | ( 4 << 3),
			   0x6600 | ( 5 << 3),
			   0x6600 | ( 6 << 3),
			   0x6600 | ( 7 << 3),
			   0x66c0,
			   0x66c0 | ( 1 << 3),
			   0x66c0 | ( 2 << 3),
			   0x66c0 | ( 3 << 3),
			   0x66c0 | ( 4 << 3),
			   0x66c0 | ( 5 << 3),
			   0x66c0 | ( 6 << 3),
			   0x66c0 | ( 7 << 3),
			   0x66c0,
			   0x66c0 | ( 1 << 3),
			   0x66c0 | ( 2 << 3),
			   0x66c0 | ( 3 << 3),
			   0x66c0 | ( 4 << 3),
			   0x66c0 | ( 5 << 3),
			   0x66c0 | ( 6 << 3),
			   0x66c0 | ( 7 << 3),
			   0x6800,
			   0x6800 | ( 1 << 5),
			   0x6800 | ( 1 << 5) | (1 << 4),
			   0x6800 | ( 2 << 5),
			   0x6800 | ( 2 << 5) | (1 << 4),
			   0x6800 | ( 3 << 5),
			   0x6800 | ( 3 << 5) | (1 << 4),
			   0x6800 | ( 4 << 5),
			   0x6800 | ( 4 << 5) | (1 << 4),
			   0x6800 | ( 5 << 5),
			   0x6800 | ( 5 << 5) | (1 << 4),
			   0x6800 | ( 6 << 5),
			   0x6800 | ( 6 << 5) | (1 << 4),
			   0x6800 | ( 7 << 5),
			   0x6800 | ( 7 << 5) | (1 << 4),
			   0x6800 | ( 8 << 5),
			   0x6800 | ( 8 << 5) | (1 << 4),
			   0x6800 | ( 9 << 5),
			   0x6800 | ( 9 << 5) | (1 << 4),
			   0x6800 | ( 10 << 5),
			   0x6800 | ( 10 << 5) | (1 << 4),
			   0x6800 | ( 11 << 5),
			   0x6800 | ( 11 << 5) | (1 << 4),
			   0x6800 | ( 12 << 5),
			   0x6800 | ( 12 << 5) | (1 << 4),
			   0x6800 | ( 13 << 5),
			   0x6800 | ( 13 << 5) | (1 << 4),
			   0x6800 | ( 14 << 5),
			   0x6800 | ( 14 << 5) | (1 << 4),
			   0x6800 | ( 15 << 5),
			   0x6800 | ( 15 << 5) | (1 << 4),
			   0x7000,
			   0x7000 | ( 1 << 5),
			   0x7000 | ( 1 << 5) | (1 << 4),
			   0x7000 | ( 2 << 5),
			   0x7000 | ( 2 << 5) | (1 << 4),
			   0x7000 | ( 3 << 5),
			   0x7000 | ( 3 << 5) | (1 << 4),
			   0x7000 | ( 4 << 5),
			   0x7000 | ( 4 << 5) | (1 << 4),
			   0x7000 | ( 5 << 5),
			   0x7000 | ( 5 << 5) | (1 << 4),
			   0x7000 | ( 6 << 5),
			   0x7000 | ( 6 << 5) | (1 << 4),
			   0x7000 | ( 7 << 5),
			   0x7000 | ( 7 << 5) | (1 << 4),
			   0x7000 | ( 8 << 5),
			   0x7000 | ( 8 << 5) | (1 << 4),
			   0x7000 | ( 9 << 5),
			   0x7000 | ( 9 << 5) | (1 << 4),
			   0x7000 | ( 10 << 5),
			   0x7000 | ( 10 << 5) | (1 << 4),
			   0x7000 | ( 11 << 5),
			   0x7000 | ( 11 << 5) | (1 << 4),
			   0x7000 | ( 12 << 5),
			   0x7000 | ( 12 << 5) | (1 << 4),
			   0x7000 | ( 13 << 5),
			   0x7000 | ( 13 << 5) | (1 << 4),
			   0x7000 | ( 14 << 5),
			   0x7000 | ( 14 << 5) | (1 << 4),
			   0x7000 | ( 15 << 5),
			   0x7000 | ( 15 << 5) | (1 << 4),
			   0x7200,
			   0x7200 | ( 1 << 5),
			   0x7200 | ( 1 << 5) | (1 << 4),
			   0x7200 | ( 2 << 5),
			   0x7200 | ( 2 << 5) | (1 << 4),
			   0x7200 | ( 3 << 5),
			   0x7200 | ( 3 << 5) | (1 << 4),
			   0x7200 | ( 4 << 5),
			   0x7200 | ( 4 << 5) | (1 << 4),
			   0x7200 | ( 5 << 5),
			   0x7200 | ( 5 << 5) | (1 << 4),
			   0x7200 | ( 6 << 5),
			   0x7200 | ( 6 << 5) | (1 << 4),
			   0x7200 | ( 7 << 5),
			   0x7200 | ( 7 << 5) | (1 << 4),
			   0x7200 | ( 8 << 5),
			   0x7200 | ( 8 << 5) | (1 << 4),
			   0x7200 | ( 9 << 5),
			   0x7200 | ( 9 << 5) | (1 << 4),
			   0x7200 | ( 10 << 5),
			   0x7200 | ( 10 << 5) | (1 << 4),
			   0x7200 | ( 11 << 5),
			   0x7200 | ( 11 << 5) | (1 << 4),
			   0x7200 | ( 12 << 5),
			   0x7200 | ( 12 << 5) | (1 << 4),
			   0x7200 | ( 13 << 5),
			   0x7200 | ( 13 << 5) | (1 << 4),
			   0x7200 | ( 14 << 5),
			   0x7200 | ( 14 << 5) | (1 << 4),
			   0x7200 | ( 15 << 5),
			   0x7200 | ( 15 << 5) | (1 << 4),
                           0x0};
    uint32_t offset2[] = {0x140, 0x200, 0x210, 0x310, 0x400,0x410,0x420,0x430,
   			  0x800,0x810,0x820,0x830, 
   			  0xc00,0xc10,0xc20,0xc30, 0}; 
    /* Reg dump of DPI registers */
    seq_printf(s, "\n############## DPI DMA ENGINES #############\n");
    for(i=0; i< 8; i++) {
        addr = 0x86e000000000 + i * (0x1ULL << 11);
        tmp_addr = 0x86e000000038 + i * (0x1ULL << 11);
        seq_printf(s, "\n\n************** DP_DMA[%d] **************\n", i);
	    for (; addr <= tmp_addr; addr += 0x8) {
        	seq_printf(s, "[0x%016llx] : 0x%016llx\n", addr,
                OCTEON_PCI_WIN_READ(oct, addr));
        }
    }

    seq_printf(s, "\n\n ***************** DPI Global registers ***********\n");
    for(i = 0 ; offset[i] !=0; i++) {
        addr = 0x86e000000000 + offset[i];
        seq_printf(s, "[0x%016llx] : 0x%016llx\n", addr,
                    OCTEON_PCI_WIN_READ(oct, addr));
    }

    for(i=0; i< 8; i++) {
        addr = 0x86e020000000 + i * (0x1ULL << 20);
        tmp_addr = 0x86e020000038 + i * (0x1ULL << 20);
        seq_printf(s, "\n\n************** DPI_VDMA[%d] **************\n", i);
	    for (; addr <= tmp_addr; addr += 0x8) {
        	seq_printf(s, "[0x%016llx] : 0x%016llx\n", addr,
                OCTEON_PCI_WIN_READ(oct, addr));
        }
        
        addr = 0x86e020000100 + i * (0x1ULL << 20);
        tmp_addr = 0x86e020000118 + i * (0x1ULL << 20);
        seq_printf(s, "\n\n************** DPI_VF[%d] **************\n", i);
	    for (; addr <= tmp_addr; addr += 0x8) {
        	seq_printf(s, "[0x%016llx] : 0x%016llx\n", addr,
                OCTEON_PCI_WIN_READ(oct, addr));
        }
    }

    mac = octeon_read_csr64(oct, 0x2c100) & 0xff ;
    if (OCTEON_CN93XX_PF(oct->chip_id))
	    count = octeon_read_csr64(oct, (0x2c000 | (mac << 4))) >> 16 ;
    else if (OCTEON_CN98XX_PF(oct->chip_id))
	    count = (octeon_read_csr64(oct, (0x2c000 | (mac << 4))) >> 32) & 0x3F;
    else if (OCTEON_CNXK_PF(oct->chip_id))
	    count = (octeon_read_csr64(oct, (0x2c000 | (mac << 4))) >> 16) & 0x3F;

    /* Reg dump of IOQ registers */
    seq_printf(s, "\n\n\n############## IOQ RINGS #############\n");
	for (i = 0; i < count; i++) {
		addr = 0x10000 + i * (0x1ULL << 17);
		tmp_addr = addr + 0x90;
        seq_printf(s, "\n\n*************** R[%d]_IN ************\n", i);
		for (; addr <= tmp_addr; addr += 0x10) {
			seq_printf(s, "[0x%016llx] : 0x%016llx\n", addr,
				   octeon_read_csr64(oct, addr));
		}
        
        addr = 0x10100 + i * (0x1ULL << 17);
		tmp_addr = addr + 0x90;
        seq_printf(s, "\n\n*************** R[%d]_OUT ************\n", i);
		for (; addr <= tmp_addr; addr += 0x10) {
			seq_printf(s, "[0x%016llx] : 0x%016llx\n", addr,
				   octeon_read_csr64(oct, addr));
		}

        addr = 0x10210 + i * (0x1ULL << 17);
		tmp_addr = addr + 0x30;
        seq_printf(s, "\n\n*************** R[%d]_MBOX ************\n", i);
		for (; addr <= tmp_addr; addr += 0x10) {
			seq_printf(s, "[0x%016llx] : 0x%016llx\n", addr,
				   octeon_read_csr64(oct, addr));
		}

        seq_printf(s, "\n\n*** R[%d]_ALL_INT, ERR_TYPE, VF_NUM ******\n", i);
        addr = 0x10400 + i * (0x1ULL << 17);
		seq_printf(s, "[0x%016llx] : 0x%016llx\n", addr,
				   octeon_read_csr64(oct, addr));
	}
    /* Reg Dump of INT Registers */
    seq_printf(s, "\n\n\n############## INT Registers  #############\n");
    addr = 0x20100;
    tmp_addr = addr + 0x10;
    	for (; addr <= tmp_addr; addr += 0x10) {
			seq_printf(s, "[0x%016llx] : 0x%016llx\n", addr,
				   octeon_read_csr64(oct, addr));
		}
    addr = 0x20180;
    tmp_addr = addr + 0x10;
    for (; addr <= tmp_addr; addr += 0x10) {
			seq_printf(s, "[0x%016llx] : 0x%016llx\n", addr,
				   octeon_read_csr64(oct, addr));
	}
    addr = 0x20200;
    seq_printf(s, "[0x%016llx] : 0x%016llx\n", addr,
				   octeon_read_csr64(oct, addr));
    addr = 0x20240;
    tmp_addr = addr + 0x10;
    for (; addr <= tmp_addr; addr += 0x10) {
			seq_printf(s, "[0x%016llx] : 0x%016llx\n", addr,
				   octeon_read_csr64(oct, addr));
	}
    addr = 0x20320;
    seq_printf(s, "[0x%016llx] : 0x%016llx\n", addr,
				   octeon_read_csr64(oct, addr));
    addr = 0x20400;
    seq_printf(s, "[0x%016llx] : 0x%016llx\n", addr,
				   octeon_read_csr64(oct, addr));
    addr = 0x204a0;
    seq_printf(s, "[0x%016llx] : 0x%016llx\n", addr,
				   octeon_read_csr64(oct, addr));
    addr = 0x204e0;
    tmp_addr = addr + 0x10;
    for (; addr <= tmp_addr; addr += 0x10) {
			seq_printf(s, "[0x%016llx] : 0x%016llx\n", addr,
				   octeon_read_csr64(oct, addr));
	}
    addr = 0x20560;
    tmp_addr = addr + 0x10;
    for (; addr <= tmp_addr; addr += 0x10) {
			seq_printf(s, "[0x%016llx] : 0x%016llx\n", addr,
				   octeon_read_csr64(oct, addr));
	}

    addr = 0x205f0;
    seq_printf(s, "[0x%016llx] : 0x%016llx\n", addr,
				   octeon_read_csr64(oct, addr));
    addr = 0x26000;
    seq_printf(s, "[0x%016llx] : 0x%016llx\n", addr,
				   octeon_read_csr64(oct, addr));
    addr = 0x2c000;
    tmp_addr = addr + 0x30;
    for (; addr <= tmp_addr; addr += 0x10) {
			seq_printf(s, "[0x%016llx] : 0x%016llx\n", addr,
				   octeon_read_csr64(oct, addr));
	}
    for(i = 0; i<4; i++) {
        addr = 0x86E08002C000 + (i << 4);
        seq_printf(s, "[0x%016llx] : 0x%016llx\n", addr,
                    OCTEON_PCI_WIN_READ(oct, addr));
    }
    addr = 0x2c100;
    seq_printf(s, "[0x%016llx] : 0x%016llx\n", addr,
				   octeon_read_csr64(oct, addr));

    for(i = 0 ; offset2[i] !=0; i++) {
        addr = 0x86E0C0080000 + offset2[i];
        seq_printf(s, "[0x%016llx] : 0x%016llx\n", addr,
                    OCTEON_PCI_WIN_READ(oct, addr));
    }
    return 0;
}
/* $Id: cavium_proc.c 163569 2017-07-25 15:58:46Z mchalla $ */
