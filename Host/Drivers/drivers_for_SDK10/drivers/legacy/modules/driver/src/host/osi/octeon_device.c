/*
 *
 * CNNIC SDK
 *
 * Copyright (c) 2018 Cavium Networks. All rights reserved.
 *
 * This file, which is part of the CNNIC SDK which also includes the
 * CNNIC SDK Package from Cavium Networks, contains proprietary and
 * confidential information of Cavium Networks and in some cases its
 * suppliers. 
 *
 * Any licensed reproduction, distribution, modification, or other use of
 * this file or the confidential information or patented inventions
 * embodied in this file is subject to your license agreement with Cavium
 * Networks. Unless you and Cavium Networks have agreed otherwise in
 * writing, the applicable license terms "OCTEON SDK License Type 5" can be
 * found under the directory: $CNNIC_ROOT/licenses/
 *
 * All other use and disclosure is prohibited.
 *
 * Contact Cavium Networks at info@caviumnetworks.com for more information.
 *
 */

#include "octeon_device.h"
#include "octeon_macros.h"
#include "octeon_mem_ops.h"
#include "oct_config_data.h"
#include "barmap.h"

extern int octeon_msix;
extern int cn83xx_pf_setup_global_oq_reg(octeon_device_t *, int);
extern int cn83xx_pf_setup_global_iq_reg(octeon_device_t *, int);
extern int g_app_mode[];

/* On 83xx this is called DPIx_SLI_PRTx_CFG but address is same */
#define DPI0_EBUS_PORTX_CFG(a) (0x86E000004100ULL | (a)<<3)
#define DPI1_EBUS_PORTX_CFG(a) (0x86F000004100ULL | (a)<<3)

char oct_dev_state_str[OCT_DEV_STATES + 1][32] = {
	"BEGIN", "PCI-MAP-DONE", "DISPATCH-INIT-DONE",
	"BUFPOOL-INIT-DONE", "RESPLIST-INIT-DONE", "HOST-READY",
	"CORE-READY", "INSTR-QUEUE-INIT-DONE", "DROQ-INIT-DONE",
	"RUNNING", "IN-RESET", "CLEANUP-DONE", "STOPPED",
	"INVALID",
};

char oct_dev_app_str[CVM_DRV_APP_COUNT + 1][32] =
    { "UNKNOWN", "BASE", "NIC", "ZLIB",	"UNKNOWN" };

octeon_device_t *octeon_device[MAX_OCTEON_DEVICES];
uint32_t octeon_device_count = 0;

octeon_module_handler_t octmodhandlers[OCTEON_MAX_MODULES];
cavium_spinlock_t octmodhandlers_lock;

octeon_core_setup_t core_setup[MAX_OCTEON_DEVICES];

oct_poll_fn_status_t oct_poll_module_starter(void *octptr, unsigned long arg);

void octeon_disable_msix_interrupts(octeon_device_t * oct_dev);

oct_poll_fn_status_t octeon_hostfw_handshake(void *octptr, unsigned long arg);

extern int octeon_enable_msix_interrupts(octeon_device_t * oct);

extern int octeon_init_mbox_thread(octeon_device_t *);
extern int octeon_delete_mbox_thread(octeon_device_t *);

//int oct7xxx_reset_ioq(octeon_device_t * oct, int q_no);

/*
   All Octeon devices use the default configuration in oct_config_data.h.
   To override the default:
   1.  The Octeon device Id must be known for customizing the octeon configuration.
   2.  Create a custom configuration based on CN3XXX or CN56XX config structure
       (see octeon_config.h) in oct_config_data.h.
   3.  Modify the config type of the octeon device in the structure below to
       specify CN56XX or CN3XXX configuration and replace the "custom" pointer
       to point to your custom configuration in oct_config_data.h
 */

static struct octeon_config_ptr {
	uint32_t conf_type;
	void *custom;
} oct_conf_info[MAX_OCTEON_DEVICES] = {
	{OCTEON_CONFIG_TYPE_DEFAULT, NULL},
	{OCTEON_CONFIG_TYPE_DEFAULT, NULL},
	{OCTEON_CONFIG_TYPE_DEFAULT, NULL},
	{OCTEON_CONFIG_TYPE_DEFAULT, NULL},
	{OCTEON_CONFIG_TYPE_DEFAULT, NULL},
	{OCTEON_CONFIG_TYPE_DEFAULT, NULL},
	{OCTEON_CONFIG_TYPE_DEFAULT, NULL},
	{OCTEON_CONFIG_TYPE_DEFAULT, NULL},
};

void octeon_init_device_list(void)
{
	cavium_memset(octeon_device, 0, (sizeof(void *) * MAX_OCTEON_DEVICES));
}

static void *__retrieve_octeon_config_info(octeon_device_t * oct)
{
	int oct_id = oct->octeon_id;

	if (oct_conf_info[oct_id].conf_type != OCTEON_CONFIG_TYPE_DEFAULT) {

		if (((oct->chip_id == OCTEON_CN83XX_PF) || 
		    (oct->chip_id == OCTEON_CN93XX_PF) ||
		    (oct->chip_id == OCTEON_CN98XX_PF)) &&
		    (oct_conf_info[oct_id].conf_type ==
		     OCTEON_CONFIG_TYPE_CUSTOM))
			return oct_conf_info[oct_id].custom;

		cavium_error
		    ("OCTEON[%d]: Incompatible config type (%d) for chip type %x\n",
		     oct_id, oct_conf_info[oct_id].conf_type, oct->chip_id);
		return NULL;
	}
	if (oct->chip_id == OCTEON_CN83XX_PF)
		return (void *)&default_cn83xx_pf_conf;
	else if (oct->chip_id == OCTEON_CN93XX_PF ||
		 oct->chip_id == OCTEON_CN98XX_PF)
		return (void *)&default_cn93xx_pf_conf;
	return NULL;
}

static int __verify_octeon_config_info(octeon_device_t * oct, void *conf)
{
	switch (oct->chip_id) {

	case OCTEON_CN83XX_PF:
		return validate_cn83xx_pf_config_info(conf);
	case OCTEON_CN93XX_PF:
	case OCTEON_CN98XX_PF:
		return validate_cn93xx_pf_config_info(conf);
	default:
		cavium_error("Chip config verification failed. Invalid chipid :%d\n",
				oct->chip_id);
		break;
	}
	return 1;
}

void *oct_get_config_info(octeon_device_t * oct)
{
	void *conf = NULL;

	conf = __retrieve_octeon_config_info(oct);
	if (conf == NULL)
		return NULL;

	if (__verify_octeon_config_info(oct, conf)) {
		cavium_error
		    ("\n Configuration verification failed for Octeon[%d]\n",
		     oct->octeon_id);
		return NULL;
	}

	return conf;
}

char *get_oct_state_string(cavium_atomic_t * state_ptr)
{
	int istate = (int)cavium_atomic_read(state_ptr);

	if (istate > OCT_DEV_STATES || istate < 0)
		return oct_dev_state_str[OCT_DEV_STATE_INVALID];
	return oct_dev_state_str[istate];
}

char *get_oct_app_string(int app_mode)
{
	if (app_mode >= CVM_DRV_APP_START && app_mode <= CVM_DRV_APP_END)
		return oct_dev_app_str[app_mode - CVM_DRV_APP_START];
	return oct_dev_app_str[CVM_DRV_INVALID_APP - CVM_DRV_APP_START];
}

void octeon_free_device_mem(octeon_device_t * oct)
{
	int i;

	for (i = 0; i < oct->num_oqs; i++) {
		if (oct->droq[i])
			cavium_free_virt(oct->droq[i]);
	}

	for (i = 0; i < oct->num_iqs; i++) {
		if (oct->instr_queue[i])
			cavium_free_virt(oct->instr_queue[i]);
	}

	i = oct->octeon_id;
	cavium_free_virt(oct);

	octeon_device[i] = NULL;
	octeon_device_count--;
}

octeon_device_t *octeon_allocate_device_mem(int pci_id)
{
	octeon_device_t *oct;
	uint8_t *buf = NULL;
	int octdevsize = 0, configsize = 0, size;

	switch (pci_id) {

	case OCTEON_CN83XX_PF:
		configsize = sizeof(octeon_cn83xx_pf_t);
		break;

	case OCTEON_CN93XX_PF:
	case OCTEON_CN98XX_PF:
		configsize = sizeof(octeon_cn93xx_pf_t);
		break;

	default:
		cavium_print_msg("%s: Unknown PCI Device: 0x%x\n", __FUNCTION__,
				 pci_id);
		return NULL;
	}

	if (configsize & 0x7)
		configsize += (8 - (configsize & 0x7));

	octdevsize = sizeof(octeon_device_t);
	if (octdevsize & 0x7)
		octdevsize += (8 - (octdevsize & 0x7));

	size =
	    octdevsize + configsize +
	    (sizeof(octeon_dispatch_t) * DISPATCH_LIST_SIZE);
	buf = cavium_alloc_virt(size);
	if (buf == NULL)
		return NULL;

	cavium_memset(buf, 0, size);

	oct = (octeon_device_t *) buf;
	oct->chip = (void *)(buf + octdevsize);
	oct->dispatch.dlist =
	    (octeon_dispatch_t *) (buf + octdevsize + configsize);

	return oct;
}

octeon_device_t *octeon_allocate_device(int pci_id)
{
	int oct_idx = 0;
	octeon_device_t *oct = NULL;

	for (oct_idx = 0; oct_idx < MAX_OCTEON_DEVICES; oct_idx++) {
		if (octeon_device[oct_idx] == NULL)
			break;
	}

	if (oct_idx == MAX_OCTEON_DEVICES) {
		cavium_error
		    ("OCTEON: Could not find empty slot for device pointer. octeon_device_count: %d MAX_OCTEON_DEVICES: %d\n",
		     octeon_device_count, MAX_OCTEON_DEVICES);
		return NULL;
	}

	oct = octeon_allocate_device_mem(pci_id);
	if (oct == NULL) {
		cavium_error("OCTEON: Allocation failed for octeon device\n");
		return NULL;
	}

	octeon_device_count++;
	octeon_device[oct_idx] = oct;

	oct->octeon_id = oct_idx;
	octeon_assign_dev_name(oct);

	return oct;
}

int octeon_setup_io_queues(octeon_device_t * octeon_dev)
{
	int i, num_ioqs, retval = 0;

	num_ioqs = octeon_dev->sriov_info.rings_per_pf;

	/* set up DROQs. */
	for (i = 0; i < num_ioqs; i++) {
		if (octeon_dev->droq[i]) {
			cavium_print_msg
			    ("Droq %d is already initialized. Skipping initialization.\n",
			     i);
		} else {
			retval =
			    octeon_setup_droq(octeon_dev->octeon_id, i, NULL);
			if (retval) {
				cavium_print_msg
				    (" %s : Runtime DROQ(RxQ) creation failed.\n",
				     __FUNCTION__);
				return 1;
			}
		}
	}

	/* set up IQs. */
	for (i = 0; i < num_ioqs; i++) {
		if (octeon_dev->instr_queue[i]) {
			cavium_print_msg
			    ("IQ %d is already initialized. Skipping initialization.\n",
			     i);
		} else {
			retval = octeon_setup_iq(octeon_dev, i, NULL);
			if (retval) {
				cavium_print_msg
				    (" %s : Runtime IQ(TxQ) creation failed.\n",
				     __FUNCTION__);
				return 1;
			}
		}
	}

	return 0;
}

int octeon_allocate_ioq_vector(octeon_device_t * oct)
{
	int i;
	octeon_ioq_vector_t *ioq_vector;

	for (i = 0; i < oct->num_oqs; i++) {
		oct->ioq_vector[i] =
		    cavium_alloc_virt(sizeof(octeon_ioq_vector_t));
		if (oct->ioq_vector[i] == NULL)
			goto free_ioq_vector;

		cavium_memset(oct->ioq_vector[i], 0,
			      sizeof(octeon_ioq_vector_t));

		ioq_vector = oct->ioq_vector[i];
		ioq_vector->iq = oct->instr_queue[i];
		ioq_vector->droq = oct->droq[i];
//        ioq_vector->mbox        = oct->mbox[i];
		ioq_vector->oct_dev = oct;

		/* No model check is required, as this is called only for PFs of 73XX and 78XX */
		ioq_vector->ioq_num = i + oct->sriov_info.pf_srn;
	}

	cavium_print_msg("Allocated %d IOQ vectors\n", oct->num_oqs);
	return 0;

free_ioq_vector:
	while (i) {
		i--;
		cavium_free_virt(oct->ioq_vector[i]);
	}
	return 1;
}

int octeon_setup_irq_affinity(octeon_device_t * oct)
{
	int i;
	octeon_ioq_vector_t *ioq_vector;
	int cpu_num;

	for (i = 0; i < oct->num_oqs; i++) {
		ioq_vector = oct->ioq_vector[i];

		if (octeon_msix) {
		/* Enable these, if 2 PFs exist. */
#if 0			
			/* PF0 interrupts will be handled by even numbered cores,
			 * PF1 interrupts will be handled by odd numbered cores.
			 *
			 * CPU affinity scheme for PF0 and PF1 for a 4 core machine
			 *       PF0               PF1   
			 *  queue   core      queue   core
			 *    0      0          0      1
			 *    1      2          1      3
			 *    2      0          2      1
			 *    3      2          3      3
			 * */
			if (oct->chip_id == OCTEON_CN73XX_PF)
				cpu_num =
				    (oct->pf_num +
				     i * 2) % cavium_get_cpu_count();
			else
				cpu_num = i % cavium_get_cpu_count();
#endif				
			cpu_num = i % cavium_get_cpu_count();

			cpumask_clear(&ioq_vector->affinity_mask);
			cpumask_set_cpu(cpu_num, &ioq_vector->affinity_mask);

			/* assign the cpu mask for the msix interrupt vector */
// *INDENT-OFF*
                irq_set_affinity_hint(oct->msix_entries[i].vector,
                                   &(oct->ioq_vector[i]->affinity_mask));
// *INDENT-ON*
	        cavium_print(PRINT_DEBUG, "pf_num:%d queue:%d cpu:%d\n", 
                    oct->pf_num, i, cpu_num);
		}
	}

	return 0;
}

int octeon_clear_irq_affinity(octeon_device_t * oct)
{
	int i;

	/* Disable Octeon device interrupts */
	oct->fn_list.disable_interrupt(oct->chip, OCTEON_ALL_INTR);

	for (i = 0; i < oct->num_oqs; i++) {
		/* clearing the intr-cpu affinity */
		irq_set_affinity_hint(oct->msix_entries[i].vector, NULL);
	}

	cavium_print_msg("Cleared %d IOQ vectors\n", oct->num_oqs);
	return 0;
}

int octeon_delete_ioq_vector(octeon_device_t * oct)
{
	int i;

	for (i = 0; i < oct->num_oqs; i++) {
		cavium_memset(oct->ioq_vector[i], 0,
			      sizeof(octeon_ioq_vector_t));
		cavium_free_virt(oct->ioq_vector[i]);

		oct->ioq_vector[i] = NULL;
	}

	cavium_print_msg("Deleted %d IOQ vectors\n", (oct->num_irqs - 1));
	oct->num_irqs = 0;
	return 0;
}

int octeon_setup_instr_queues(octeon_device_t * oct)
{
	int i, num_iqs = 0, retval = 0;

	if (oct->chip_id == OCTEON_CN83XX_PF)
		num_iqs =
		    CFG_GET_IQ_MAX_BASE_Q(CHIP_FIELD(oct, cn83xx_pf, conf));
	else if (oct->chip_id == OCTEON_CN93XX_PF ||
		 oct->chip_id == OCTEON_CN98XX_PF)
		num_iqs =
		    CFG_GET_IQ_MAX_BASE_Q(CHIP_FIELD(oct, cn93xx_pf, conf));

	oct->num_iqs = 0;
	for (i = 0; i < num_iqs; i++) {
		retval = octeon_setup_iq(oct, i, NULL);
		if (retval) {
			cavium_print_msg
			    (" %s : Runtime IQ(TxQ) creation failed.\n",
			     __FUNCTION__);
			return 1;
		}
		cavium_print_msg(" %s : Runtime IQ(TxQ):%d creation success.\n",
				 __FUNCTION__, i);
	}

	return 0;
}

int octeon_setup_output_queues(octeon_device_t * oct)
{
	int i, num_oqs = 0, retval = 0;

	if (oct->chip_id == OCTEON_CN83XX_PF)
		num_oqs =
		    CFG_GET_OQ_MAX_BASE_Q(CHIP_FIELD(oct, cn83xx_pf, conf));
	else if (oct->chip_id == OCTEON_CN93XX_PF ||
		 oct->chip_id == OCTEON_CN98XX_PF)
		num_oqs =
		    CFG_GET_OQ_MAX_BASE_Q(CHIP_FIELD(oct, cn93xx_pf, conf));

	oct->num_oqs = 0;
	for (i = 0; i < num_oqs; i++) {
		retval = octeon_setup_droq(oct->octeon_id, i, NULL);
		if (retval) {
			cavium_print_msg
			    (" %s : Runtime DROQ(RxQ) creation failed.\n",
			     __FUNCTION__);
			return 1;
		}
		cavium_print_msg
		    (" %s : Runtime DROQ(RxQ):%d creation success.\n",
		     __FUNCTION__, i);
	}
	return 0;
}

int octeon_setup_mbox(octeon_device_t * oct)
{
	int i = 0, num_ioqs = 0;

	if (!(oct->drv_flags & OCTEON_MBOX_CAPABLE))
		return 0;

	if (oct->chip_id == OCTEON_CN83XX_PF)
		num_ioqs =
		    CFG_GET_TOTAL_PF_RINGS(CHIP_FIELD(oct, cn83xx_pf, conf),
					   oct->pf_num);
	else if (oct->chip_id == OCTEON_CN93XX_PF ||
		 oct->chip_id == OCTEON_CN98XX_PF)
		num_ioqs =
		    CFG_GET_TOTAL_PF_RINGS(CHIP_FIELD(oct, cn93xx_pf, conf),
					   oct->pf_num);
	else
		return 0;

	for (i = 0; i < num_ioqs; i++) {
		oct->mbox[i] = cavium_alloc_virt(sizeof(octeon_mbox_t));
		if (oct->mbox[i] == NULL)
			goto free_mbox;

		cavium_memset(oct->mbox[i], 0, sizeof(octeon_mbox_t));
		oct->fn_list.setup_mbox_regs(oct, i);
	}

	/* Mail Box Thread creation */
#if 0
	if (octeon_init_mbox_thread(oct))
		goto free_mbox;
#endif
	return 0;

free_mbox:
	while (i) {
		i--;
		cavium_free_virt(oct->mbox[i]);
	}
	return 1;
}

int octeon_delete_mbox(octeon_device_t * oct)
{
	int i = 0, num_ioqs = 0;

	if (!(oct->drv_flags & OCTEON_MBOX_CAPABLE))
		return 0;

	if (oct->chip_id == OCTEON_CN83XX_PF)
		num_ioqs =
		    CFG_GET_TOTAL_PF_RINGS(CHIP_FIELD(oct, cn83xx_pf, conf),
					   oct->pf_num);
	else
		return 0;

#if 0
//	octeon_delete_mbox_thread(oct);
//	cavium_print_msg("OCTEON[%d]: deleted MBOX thread.\n", oct->octeon_id);
#endif

	for (i = 0; i < num_ioqs; i++) {
		cavium_memset(oct->mbox[i], 0, sizeof(octeon_mbox_t));
		cavium_free_virt(oct->mbox[i]);

		oct->mbox[i] = NULL;
	}
	cavium_print_msg("OCTEON[%d]: freed mbox struct.\n", oct->octeon_id);

	return 0;
}

int octeon_init_base_ioqs(octeon_device_t * oct)
{
	int j;

	if (octeon_setup_io_queues(oct))
		return 1;

	if (octeon_setup_irq_affinity(oct))
		return 1;

	/* Enable Octeon device interrupts */
	oct->fn_list.enable_interrupt(oct->chip, OCTEON_ALL_INTR);

	/* Enable the input and output queues for this Octeon device */
	oct->fn_list.enable_io_queues(oct);

	/* Send Credit for Octeon Output queues. Credits are always sent after the
	   output queue is enabled. */
	for (j = 0; j < oct->num_oqs; j++) {
		OCTEON_WRITE32(oct->droq[j]->pkts_credit_reg,
			       oct->droq[j]->max_count);
	}

	return 0;
}


/**	
 * Checks the IOQ's reset state and brings it out of reset
 * @param   octeon_dev   Pointer to Octeon Device structure
 * @param   ioq          Queue number    
 * @return  Void
 */  
void octeon_reset_ioq(octeon_device_t * octeon_dev, int ioq)
{
	volatile uint64_t reg_val = 0ULL;

	ioq += octeon_dev->sriov_info.pf_srn;

	if (octeon_dev->chip_id == OCTEON_CN83XX_PF) {
			/* wait for IDLE to set to 1 */
		do {
			reg_val = octeon_read_csr64(octeon_dev,
						    CN83XX_SDP_EPF_R_IN_CONTROL
						    (octeon_dev->epf_num, ioq));
		} while (!(reg_val & CN83XX_R_IN_CTL_IDLE));

		do {
			reg_val = octeon_read_csr64(octeon_dev,
						    CN83XX_SDP_EPF_R_OUT_CONTROL
						    (octeon_dev->epf_num, ioq));
		} while (!(reg_val & CN83XX_R_OUT_CTL_IDLE));

	} else if (octeon_dev->chip_id == OCTEON_CN93XX_PF ||
		   octeon_dev->chip_id == OCTEON_CN98XX_PF) {
	    		/* wait for IDLE to set to 1 */
	    	do {
	    		reg_val = octeon_read_csr64(octeon_dev,
	    					    CN93XX_SDP_R_IN_CONTROL(ioq));
	    	} while (!(reg_val & CN93XX_R_IN_CTL_IDLE));
	
	    	do {
	    		reg_val = octeon_read_csr64(octeon_dev,
	    					    CN93XX_SDP_R_OUT_CONTROL(ioq));
	    	} while (!(reg_val & CN93XX_R_OUT_CTL_IDLE));
	}
}

void octeon_set_io_queues_off(octeon_device_t * oct)
{
	if (oct->chip_id == OCTEON_CN83XX_PF) {
	}
	else if (oct->chip_id == OCTEON_CN93XX_PF) {
	}
}

void octeon_set_droq_pkt_op(octeon_device_t * oct, int q_no, int enable)
{

	if (oct->chip_id == OCTEON_CN83XX_PF) {
		if (enable)
			oct->fn_list.enable_input_queue(oct, q_no);
		else
			oct->fn_list.disable_input_queue(oct, q_no);

		return;
	}

}

int octeon_hot_reset(octeon_device_t * oct)
{
	int status;
	octeon_poll_ops_t poll_ops;

	cavium_print_msg("\n\n OCTEON[%d]: Starting Hot Reset.\n",
			 oct->octeon_id);

	status = (int)cavium_atomic_read(&oct->status);

	if (status != OCT_DEV_RUNNING) {
		cavium_error
		    ("OCTEON: Hot Reset received when device state is %s\n",
		     get_oct_state_string(&oct->status));
		cavium_error("OCTEON: Device state will remain at %s (0x%x)\n",
			     get_oct_state_string(&oct->status),
			     (int)cavium_atomic_read(&oct->status));

		/* If device is not in running state, issue a soft_reset, 
		 * reprogram sli global registers and then return. 
		 */
		oct->fn_list.soft_reset(oct);
		oct->fn_list.setup_device_regs(oct);
		return 0;
	}

	cavium_print_msg("OCTEON: Stopping modules.\n");

	/* Stop any driver modules that are running. Do this before sending the hot
	   reset command so that the modules get a chance to stop their traffic. */
	if ((oct->app_mode != CVM_DRV_INVALID_APP)
	    && (oct->app_mode != CVM_DRV_BASE_APP)
	    && (oct->app_mode != CVM_DRV_ZLIB_APP)) {
		if (octeon_reset_module(oct->app_mode, oct->octeon_id)) {
			cavium_error
			    ("OCTEON: Module for app_type: %s is busy\n",
			     get_oct_app_string(oct->app_mode));
			cavium_error
			    ("OCTEON: Hot Reset aborted. Try again after unloading the module\n");
			return 1;
		}
	}

	if (status == OCT_DEV_RUNNING) {
		/* The core application is known to be running only in this state. */
		/* Sent instruction to core indicating that the host is about to reset.
		 */
		cavium_print_msg
		    ("OCTEON[%d]: Modules stopped. Sending Reset command.\n",
		     oct->octeon_id);

		//if (oct->pf_num != OCTEON_CN73XX_PF1) {
			if (octeon_send_short_command
			    (oct, HOT_RESET_OP, 0, NULL, 0)) {
				cavium_error
				    ("Failed to send HOT RESET instruction\n");
				cavium_error
				    ("OCTEON: Device state will remain at %s (0x%x)\n",
				     get_oct_state_string(&oct->status),
				     (int)cavium_atomic_read(&oct->status));
				return 1;
			} else {
				cavium_print_msg
				    ("OCTEON: HotReset command sent.\n");
			}
		//}
	}

	/* For 73xx, initiating hot-reset on PF0 first, soft_reset() clears all SLI registers of PF0&PF1
	 * Need to restore the PF1's SLI_MAC_RINFO register beforing going to reset IOQs, so that
	 * PF0 and PF1 reinitialize it's corresponding SLI registers.*/
#if 0	
	if (oct->pf_num == OCTEON_CN73XX_PF1)
		oct->fn_list.setup_device_regs(oct);
#endif		

	if ((oct->app_mode == CVM_DRV_BASE_APP)
	    || (oct->app_mode == CVM_DRV_ZLIB_APP))
		oct_stop_base_module(oct->octeon_id, oct);

	//octeon_unregister_module_handler(CVM_DRV_BASE_APP);

	/* No more instructions will be forwarded. */
	cavium_atomic_set(&oct->status, OCT_DEV_IN_RESET);

	oct->app_mode = CVM_DRV_INVALID_APP;
	cavium_print_msg("OCTEON: Device state is now %s\n",
			 get_oct_state_string(&oct->status));

	/* Sleep a short while to allow for in-flight requests to be setup
	   correctly. No new requests would be allowed once the RESET state
	   is set above. */
	cavium_sleep_timeout(100);

	oct->fn_list.soft_reset(oct);

	cavium_print_msg("OCTEON[%d]: Performing device initialization\n",
			 oct->octeon_id);

	oct->fn_list.setup_device_regs(oct);

	cavium_print_msg
	    ("OCTEON[%d]: Reset Done. Load a new core application to continue.\n",
	     oct->octeon_id);
	cavium_atomic_set(&oct->status, OCT_DEV_HOST_OK);

	cavium_memset(&poll_ops, 0, sizeof(octeon_poll_ops_t));

	poll_ops.fn = oct_poll_module_starter;
	poll_ops.fn_arg = 0UL;
	poll_ops.ticks = CAVIUM_TICKS_PER_SEC;
	cavium_strncpy(poll_ops.name, sizeof(poll_ops.name), "Module Starter",
		       sizeof(poll_ops.name) - 1);
	octeon_register_poll_fn(oct->octeon_id, &poll_ops);

#if !defined(ETHERPCI)
	/* Register a Host - Firmware (OCTEON) handshake poll function */
	cavium_memset(&poll_ops, 0, sizeof(octeon_poll_ops_t));
	poll_ops.fn = octeon_hostfw_handshake;
	poll_ops.fn_arg = 0UL;
	poll_ops.ticks = CAVIUM_TICKS_PER_SEC;
	cavium_strcpy(poll_ops.name, sizeof(poll_ops.name),
		      "Host Firmware Handshake Thread[HOT-RESET]");
	octeon_register_poll_fn(oct->octeon_id, &poll_ops);
#endif

	return 0;

#if 0
hot_reset_failed:
	cavium_error
	    ("OCTEON[%d]: Device will remain in RESET state\n Try again!",
	     oct->octeon_id);
	return 1;
#endif
}

int octeon_init_dispatch_list(octeon_device_t * oct)
{
	int i;

	oct->dispatch.count = 0;

	for (i = 0; i < DISPATCH_LIST_SIZE; i++) {
		oct->dispatch.dlist[i].opcode = 0;
		CAVIUM_INIT_LIST_HEAD(&(oct->dispatch.dlist[i].list));
	}

	cavium_spin_lock_init(&oct->dispatch.lock);

	return 0;
}

void octeon_delete_dispatch_list(octeon_device_t * oct)
{
	int i;
	cavium_list_t freelist, *temp, *tmp2;

	CAVIUM_INIT_LIST_HEAD(&freelist);

	cavium_spin_lock_softirqsave(&oct->dispatch.lock);

	for (i = 0; i < DISPATCH_LIST_SIZE; i++) {
		cavium_list_t *dispatch;

		dispatch = &(oct->dispatch.dlist[i].list);
		while (dispatch->le_next != dispatch) {
			temp = dispatch->le_next;
			cavium_list_del(temp);
			cavium_list_add_tail(temp, &freelist);
		}

		oct->dispatch.dlist[i].opcode = 0;
	}

	oct->dispatch.count = 0;

	cavium_spin_unlock_softirqrestore(&oct->dispatch.lock);

	cavium_list_for_each_safe(temp, tmp2, &freelist) {
		cavium_list_del(temp);
		cavium_free_virt(temp);
	}

}

/*
   octeon_register_dispatch_fn
   Parameters:
     octeon_id - id of the octeon device.
     opcode    - opcode for which driver should call the registered function
     fn        - The function to call when a packet with "opcode" arrives in
                 octeon output queues.
     fn_arg    - The argument to be passed when calling function "fn".
   Description:
     Registers a function and its argument to be called when a packet
     arrives in Octeon output queues with "opcode".
   Returns:
     Success: 0
     Failure: 1
   Locks:
     No locks are held.
 */
uint32_t
octeon_register_dispatch_fn(uint32_t octeon_id,
			    octeon_opcode_t opcode,
			    octeon_dispatch_fn_t fn, void *fn_arg)
{

	int idx;
	octeon_device_t *oct;
	octeon_dispatch_fn_t pfn;

	oct = get_octeon_device(octeon_id);
	if (oct == NULL) {
		cavium_error
		    ("OCTEON: No device with id %d to register dispatch\n",
		     octeon_id);
		return 1;
	}

	idx = opcode & OCTEON_OPCODE_MASK;

	cavium_spin_lock_softirqsave(&oct->dispatch.lock);
	/* Add dispatch function to first level of lookup table */
	if (oct->dispatch.dlist[idx].opcode == 0) {
		oct->dispatch.dlist[idx].opcode = opcode;
		oct->dispatch.dlist[idx].dispatch_fn = fn;
		oct->dispatch.dlist[idx].arg = fn_arg;
		oct->dispatch.count++;
		cavium_spin_unlock_softirqrestore(&oct->dispatch.lock);
		return 0;
	}

	cavium_spin_unlock_softirqrestore(&oct->dispatch.lock);

	/* Check if there was a function already registered for this opcode. */
	pfn = octeon_get_dispatch(oct, opcode);
	if (pfn == NULL) {
		octeon_dispatch_t *dispatch;
		cavium_print(PRINT_DEBUG,
			     "Adding opcode to dispatch list linked list\n");
		dispatch = (octeon_dispatch_t *)
		    cavium_alloc_virt(sizeof(octeon_dispatch_t));
		if (dispatch == NULL) {
			cavium_error
			    ("OCTEON[%d]: No memory to add dispatch function\n",
			     octeon_id);
			return 1;
		}
		dispatch->opcode = opcode;
		dispatch->dispatch_fn = fn;
		dispatch->arg = fn_arg;

		/* Add dispatch function to linked list of fn ptrs at the hashed index. */
		cavium_spin_lock_softirqsave(&oct->dispatch.lock);
		cavium_list_add_head(&(dispatch->list),
				     &(oct->dispatch.dlist[idx].list));
		oct->dispatch.count++;
		cavium_spin_unlock_softirqrestore(&oct->dispatch.lock);

	} else {
		cavium_error
		    ("OCTEON[%d]: Found previously registered dispatch fn for opcode: %x\n",
		     octeon_id, opcode);
		return 1;
	}

	return 0;
}

/*
   octeon_unregister_dispatch_fn
   Parameters:
     octeon_id - id of the octeon device.
     opcode    - driver should unregister the function for this opcode
   Description:
     Unregister the function set for this opcode.
   Returns:
     Success: 0
     Failure: 1
   Locks:
     No locks are held.
 */
uint32_t
octeon_unregister_dispatch_fn(uint32_t octeon_id, octeon_opcode_t opcode)
{
	int idx, retval = 0;
	octeon_device_t *octeon_dev;
	cavium_list_t *dispatch, *dfree = NULL, *tmp2;

	cavium_print(PRINT_FLOW, "#### Unregister dispatch\n");
	octeon_dev = get_octeon_device(octeon_id);
	if (octeon_dev == NULL) {
		cavium_error
		    ("OCTEON: No device with id %d to unregister dispatch\n",
		     octeon_id);
		return 1;
	}

	idx = opcode & OCTEON_OPCODE_MASK;
	cavium_print(PRINT_DEBUG, "idx is %d, opcode is 0x%x\n", idx, opcode);

	cavium_spin_lock_softirqsave(&octeon_dev->dispatch.lock);

	if (octeon_dev->dispatch.count == 0) {
		cavium_spin_unlock_softirqrestore(&octeon_dev->dispatch.lock);
		cavium_error
		    ("OCTEON[%d]: No dispatch functions registered for this device\n",
		     octeon_id);
		return 1;
	}

	if (octeon_dev->dispatch.dlist[idx].opcode == opcode) {
		cavium_print(PRINT_DEBUG,
			     "--get_dispatch: found entry in main list\n");
		dispatch = &(octeon_dev->dispatch.dlist[idx].list);
		if (dispatch->le_next != dispatch) {
			dispatch = dispatch->le_next;
			octeon_dev->dispatch.dlist[idx].opcode =
			    ((octeon_dispatch_t *) dispatch)->opcode;
			octeon_dev->dispatch.dlist[idx].dispatch_fn =
			    ((octeon_dispatch_t *) dispatch)->dispatch_fn;
			octeon_dev->dispatch.dlist[idx].arg =
			    ((octeon_dispatch_t *) dispatch)->arg;
			cavium_list_del(dispatch);
			dfree = dispatch;
		} else {
			octeon_dev->dispatch.dlist[idx].opcode = 0;
			octeon_dev->dispatch.dlist[idx].dispatch_fn = NULL;
			octeon_dev->dispatch.dlist[idx].arg = NULL;
		}
	} else {
		retval = 1;
// *INDENT-OFF*
        cavium_list_for_each_safe(dispatch, tmp2, &(octeon_dev->dispatch.dlist[idx].list)) {
            if(((octeon_dispatch_t *)dispatch)->opcode == opcode)  {
                cavium_list_del(dispatch);
                dfree = dispatch;
                retval = 0;
            }
        }
// *INDENT-ON*
	}

	if (!retval)
		octeon_dev->dispatch.count--;

	cavium_spin_unlock_softirqrestore(&octeon_dev->dispatch.lock);

	if (dfree)
		cavium_free_virt(dfree);

	return (retval);
}

int octeon_core_drv_init(octeon_recv_info_t * recv_info, void *buf)
{
	int i, oct_id;
	char app_name[16];
	octeon_device_t *oct = (octeon_device_t *) buf;
	octeon_recv_pkt_t *recv_pkt = recv_info->recv_pkt;

	if (cavium_atomic_read(&oct->status) >= OCT_DEV_RUNNING) {
		cavium_error
		    ("OCTEON[%d]: Received CORE OK when device state is 0x%x\n",
		     oct->octeon_id, cavium_atomic_read(&oct->status));
		goto core_drv_init_err;
	}

	cavium_strncpy(app_name, sizeof(app_name),
		       get_oct_app_string(recv_pkt->resp_hdr.dest_qport),
		       sizeof(app_name) - 1);
	cavium_print_msg("OCTEON[%d]: Received active indication from core\n",
			 oct->octeon_id);
	oct->app_mode = recv_pkt->resp_hdr.dest_qport;
	cavium_atomic_set(&oct->status, OCT_DEV_CORE_OK);

	if (recv_pkt->buffer_size[0] != sizeof(octeon_core_setup_t)) {
		cavium_error
		    ("OCTEON[%d]: Core setup bytes expected %u found %d\n",
		     oct->octeon_id, (uint32_t) sizeof(octeon_core_setup_t),
		     recv_pkt->buffer_size[0]);
	}

	oct_id = oct->octeon_id;
	cavium_memcpy(&core_setup[oct_id],
		      get_recv_buffer_data(recv_pkt->buffer_ptr[0], NULL),
		      sizeof(octeon_core_setup_t));

	octeon_swap_8B_data((uint64_t *) & core_setup[oct_id],
			    (sizeof(octeon_core_setup_t) >> 3));

	cavium_print(PRINT_DEBUG,
		     "OCTEON[%d] is running %s application (core clock: %llu Hz)\n",
		     oct->octeon_id, app_name,
		     CVM_CAST64(core_setup[oct_id].corefreq));

core_drv_init_err:
	for (i = 0; i < recv_pkt->buffer_count; i++) {
		free_recv_buffer(recv_pkt->buffer_ptr[i]);
	}
	octeon_free_recv_info(recv_info);
	return 0;
}

void octeon_setup_driver_dispatches(uint32_t oct_id)
{
	octeon_register_dispatch_fn(oct_id, CORE_DRV_ACTIVE_OP,
				    octeon_core_drv_init,
				    get_octeon_device_ptr(oct_id));
}

int octeon_get_tx_qsize(int octeon_id, int q_no)
{
	octeon_device_t *oct_dev = get_octeon_device(octeon_id);

	if (oct_dev && (q_no < oct_dev->num_iqs))
		return oct_dev->instr_queue[q_no]->max_count;

	return -1;
}

int octeon_get_rx_qsize(int octeon_id, int q_no)
{
	octeon_device_t *oct_dev = get_octeon_device(octeon_id);

	if (oct_dev && (q_no < oct_dev->num_oqs))
		return oct_dev->droq[q_no]->max_count;
	return -1;
}

#if 0
int octeon_send_oq_mask_cmd(octeon_device_t * oct, uint8_t param)
{
	int retval = 0;
	uint32_t *respbuf, loop_count = 100;
	volatile uint32_t *resp;

	respbuf = cavium_malloc_dma(4, GFP_ATOMIC);
	if (respbuf == NULL) {
		cavium_error("%s buffer alloc failed\n", __CVM_FUNCTION__);
		return -ENOMEM;
	}
	resp = (volatile uint32_t *)respbuf;
	*resp = 0xFFFFFFFF;
	/* Send a command to Octeon to notify the OQ mask of these PCIe function */
	if (octeon_send_short_command
	    (oct, PKO_OQ_MASK_INDICATION, param, respbuf, 4)) {
		cavium_error("%s command failed\n", __CVM_FUNCTION__);
		retval = -EINVAL;
		goto buf_free;
	}

	/* Wait for response from Octeon. */
	while ((*resp == 0xFFFFFFFF) && (loop_count--)) {
		cavium_sleep_timeout(1);
	}

	if (*resp != 0) {
		cavium_error("%s command failed: %s\n", __CVM_FUNCTION__,
			     (*resp ==
			      0xFFFFFFFF) ? "time-out" : "Failed in core");
		retval = -EBUSY;
		goto buf_free;
	}

buf_free:
	if (resp)
		cavium_free_dma(respbuf);
	return retval;

}
#endif

int oct_reinit_oq(octeon_device_t * oct, int oq_no)
{
	octeon_droq_t *droq = oct->droq[oq_no];

	droq->host_read_index = 0;
	droq->octeon_write_index = 0;
	droq->host_refill_index = 0;
	droq->refill_count = 0;
	cavium_atomic_set(&droq->pkts_pending, 0);

	if (oct->chip_id == OCTEON_CN83XX_PF)
		cn83xx_pf_setup_global_oq_reg(oct, oq_no);

	oct->fn_list.setup_oq_regs(oct, oq_no);

	/* Write the credit count register after enabling the queues. */
	OCTEON_WRITE32(droq->pkts_credit_reg, droq->max_count);

	return 0;
}

#if 0
extern void cn78xx_pf_setup_global_iq_reg(octeon_device_t * oct, int q_no);

extern void cn73xx_pf_setup_global_iq_reg(octeon_device_t * oct, int q_no);

int oct_reinit_iq(octeon_device_t * oct, int iq_no)
{
	octeon_instr_queue_t *iq =
	    (octeon_instr_queue_t *) oct->instr_queue[iq_no];

	if (oct->chip_id == OCTEON_CN83XX_PF)
		cn83xx_pf_setup_global_iq_reg(oct, iq_no);
	else if (oct->chip_id == OCTEON_CN73XX_PF)
		cn73xx_pf_setup_global_iq_reg(oct, iq_no);
	else if (oct->chip_id == OCTEON_CN78XX_PF)
		cn78xx_pf_setup_global_iq_reg(oct, iq_no);

	oct->fn_list.setup_iq_regs(oct, iq_no);

	iq->fill_cnt = 0;
	iq->host_write_index = 0;
	iq->octeon_read_index = 0;
	iq->flush_index = 0;
	iq->last_db_time = 0;
	iq->do_auto_flush = 1;
	cavium_atomic_set(&iq->instr_pending, 0);

	return 0;
}

int oct7xxx_reset_ioq(octeon_device_t * oct, int q_no)
{
	volatile uint64_t reg_val =
	    octeon_read_csr64(oct, CN78XX_SLI_IQ_PKT_CONTROL64(q_no));
	int ret_val, srn, time_threshold;
	uint64_t loop = CAVIUM_TICKS_PER_SEC;
	octeon_cn78xx_pf_t *cn78xx = (octeon_cn78xx_pf_t *) oct->chip;

	srn = oct->sriov_info.pf_srn;

	/* Write all 1's in INT_LEVEL reg to disable PO_INT */
	octeon_write_csr64(oct, CN78XX_SLI_OQ_PKT_INT_LEVELS(q_no + srn),
			   0XfffffffffffffULL);
#if 0
	/* Disable PI_INT in IN_DONE reg */
	octeon_write_csr64(oct, CN78XX_SLI_IQ_INSTR_COUNT64(q_no + srn),
			   (octeon_read_csr64
			    (oct,
			     CN78XX_SLI_IQ_INSTR_COUNT64(q_no +
							 srn)) &
			    ~CN78XX_INTR_CINT_ENB));
#endif
	oct->fn_list.disable_input_queue(oct, q_no);
	oct->fn_list.disable_output_queue(oct, q_no);

	while ((reg_val & CN78XX_PKT_INPUT_CTL_RST) &&
	       !(reg_val & CN78XX_PKT_INPUT_CTL_QUITE)) {
		reg_val =
		    octeon_read_csr64(oct, CN78XX_SLI_IQ_PKT_CONTROL64(q_no));
	}

	reg_val = reg_val & ~CN78XX_PKT_INPUT_CTL_RST;
	octeon_write_csr64(oct, CN78XX_SLI_IQ_PKT_CONTROL64(q_no), reg_val);
	reg_val = octeon_read_csr64(oct, CN78XX_SLI_IQ_PKT_CONTROL64(q_no));

	while ((reg_val & CN78XX_PKT_INPUT_CTL_RST) && loop--) {
		reg_val = reg_val & ~CN78XX_PKT_INPUT_CTL_RST;
		octeon_write_csr64(oct, CN78XX_SLI_IQ_PKT_CONTROL64(q_no),
				   reg_val);
		reg_val =
		    octeon_read_csr64(oct, CN78XX_SLI_IQ_PKT_CONTROL64(q_no));
		cavium_sleep_timeout(1);
	}

	if (reg_val & CN78XX_PKT_INPUT_CTL_RST) {
		cavium_print_msg(" ioq[%d] reset failed.\n", q_no);
		return ret_val;
	}

	oct_reinit_iq(oct, q_no);
	oct_reinit_oq(oct, q_no);

	if (octeon_msix) {
		oct->ioq_vector[q_no]->iq = oct->instr_queue[q_no];
		oct->ioq_vector[q_no]->droq = oct->droq[q_no];
		oct->ioq_vector[q_no]->oct_dev = oct;

		oct->ioq_vector[q_no]->ioq_num = q_no + oct->sriov_info.pf_srn;

#if 0
       /** Set the ioq_vector's cpu mask same as droq_thread's cpu mask */
		cpu_num = q_no % cavium_get_cpu_count();
		cpumask_set_cpu(cpu_num,
				&(oct->ioq_vector[q_no]->affinity_mask));

		/*assign the cpu mask for the msix interrupt vector */
		irq_set_affinity_hint(oct->msix_entries[q_no].vector,
				      &(oct->ioq_vector[q_no]->affinity_mask));
#endif
	}

	/* Set up interrupt packet and time thresholds for all the OQs */
	time_threshold = cn78xx_get_oq_ticks(oct, (uint32_t)
					     CFG_GET_OQ_INTR_TIME
					     (cn78xx->conf));

	octeon_write_csr64(oct, CN78XX_SLI_OQ_PKT_INT_LEVELS(q_no + srn),
			   (CFG_GET_OQ_INTR_PKT(cn78xx->conf) |
			    ((uint64_t) time_threshold << 32)));
#if 0
	/* Set CINT_ENB to enable IQ interrupt   */
	octeon_write_csr64(oct, CN78XX_SLI_IQ_INSTR_COUNT64(q_no + srn),
			   (octeon_read_csr64
			    (oct,
			     CN78XX_SLI_IQ_INSTR_COUNT64(q_no +
							 srn)) |
			    CN78XX_INTR_CINT_ENB));
#endif

	/* Enable Octeon device interrupts */
	oct->fn_list.enable_interrupt(oct->chip, OCTEON_ALL_INTR);

	oct->fn_list.enable_input_queue(oct, q_no);
	oct->fn_list.enable_output_queue(oct, q_no);

	return 0;
}
#endif

void cn93xx_dump_regs(octeon_device_t * oct, int qno);
int oct_init_base_module(int octeon_id, void *octeon_dev)
{
	int j = 0;
	octeon_device_t *oct = (octeon_device_t *) octeon_dev;

#if 0
    /* Wait for f/w PKO/PKI and DPI DMA enable before going to setup IOQs */
    {
        volatile uint64_t reg_val = 0;

        cavium_print_msg("wait for DPI to enable from f/w before sending any cmd\n");

        while( reg_val != 0xaabbccddULL)
                reg_val = octeon_read_csr64(oct, CN83XX_SDP_SCRATCH(0));

    }
#endif

    cavium_print_msg("%s : \n", __FUNCTION__);
	if (octeon_setup_instr_queues(oct)) {
		cavium_error
		    ("OCTEON: instruction queue initialization failed\n");
		/* On error, release any previously allocated queues */
		for (j = 0; j < oct->num_iqs; j++)
			octeon_delete_instr_queue(oct, j);

		oct->num_iqs = 0;
		goto init_fail;
	}

    cavium_print_msg("IQs set up completed\n");
	cavium_atomic_set(&oct->status, OCT_DEV_INSTR_QUEUE_INIT_DONE);

	if (octeon_setup_output_queues(oct)) {
		cavium_error("OCTEON: Output queue initialization failed\n");
		/* Release any previously allocated queues */
		for (j = 0; j < oct->num_oqs; j++)
			octeon_delete_droq(oct, j);

		oct->num_oqs = 0;
		goto init_fail;
	}

    cavium_print_msg("OQs set up completed\n");
	cavium_atomic_set(&oct->status, OCT_DEV_DROQ_INIT_DONE);

	if (oct->drv_flags & OCTEON_MSIX_CAPABLE) {
		if (octeon_allocate_ioq_vector(oct)) {
			cavium_error("OCTEON: ioq vector allocation failed\n");

			goto init_fail;
		}

		if (octeon_enable_msix_interrupts(oct)) {
			octeon_delete_ioq_vector(oct);
			cavium_error("OCTEON: setup msix interrupt failed\n");

			goto init_fail;
		}
		octeon_setup_irq_affinity(oct);
	}

    cavium_print_msg("Interrupts set up completed\n");
	/* Enable Octeon device interrupts */
	oct->fn_list.enable_interrupt(oct->chip, OCTEON_ALL_INTR);

	/* Enable the input and output queues for this Octeon device */
	oct->fn_list.enable_io_queues(oct);
    cavium_print_msg("IQ/OQs Enable completed\n");

	for (j = 0; j < oct->num_iqs; j++)
		cn93xx_dump_regs(oct, j);

    /* dbell needs to be programmed after enabling OQ. */
	for (j = 0; j < oct->num_oqs; j++) {
		OCTEON_WRITE32(oct->droq[j]->pkts_credit_reg,
			oct->droq[j]->max_count);
	}

	/* Send an indication to f/w saying ioq creation is completed */
	if (oct->chip_id == OCTEON_CN83XX_PF) {
		octeon_write_csr64(oct, CN83XX_SDP_SCRATCH(0), 0x11223344ULL);
	} else if (oct->chip_id == OCTEON_CN93XX_PF ||
		   oct->chip_id == OCTEON_CN98XX_PF) {
		octeon_write_csr64(oct, CN93XX_SDP_EPF_SCRATCH, 0x11223344ULL);
	}
    
    cavium_atomic_set(&oct->status, OCT_DEV_RUNNING);

    cavium_sleep_timeout(1000); /*Wait for some time(till cores reach data loop) befores sending start command */
    octeon_send_short_command(oct, DEVICE_START_OP, (DEVICE_PKO), NULL, 0);

    cavium_print_msg(" %s : Success\n", __FUNCTION__);
	return 0;

init_fail:
	/* send a error msg to prompt */
    cavium_print_msg("Returning error from Function %s \n", __FUNCTION__);
	return -1;
}

int oct_reset_base_module(int octeon_id, void *octeon_dev)
{
	return 0;
}

int oct_stop_base_module(int octeon_id, void *octeon_dev)
{
	octeon_device_t *oct_dev = (octeon_device_t *) octeon_dev;
	int attempts = 10, i = 0;

    cavium_print_msg("%s :\n", __FUNCTION__);
	switch (cavium_atomic_read(&oct_dev->status)) {
	case OCT_DEV_RUNNING:

		/* Inform core driver to stop pushing packets on output queues. */
		while (attempts--
		       && octeon_send_short_command(oct_dev, DEVICE_STOP_OP,
						    (DEVICE_PKO), NULL, 0)) ;

		cavium_atomic_set(&oct_dev->status, OCT_DEV_CORE_OK);
		/* required for multi PF Octeon h/w */
		cavium_mdelay(100);

        cavium_print_msg("Send the stop cmd \n");
		if (wait_for_all_pending_requests(oct_dev)) {
			cavium_error
			    ("OCTEON[%d]: There were pending requests\n",
			     oct_dev->octeon_id);
		}

        cavium_print_msg("wait for pending request completed\n");
		if (wait_for_instr_fetch(oct_dev)) {
			cavium_error
			    ("OCTEON[%d]: IQ had pending instructions\n",
			     oct_dev->octeon_id);
		}

        cavium_print_msg("wait for instr fetch completed\n");
		/* Disable the input and output queues now. No more packets will
		   arrive from Octeon, but we should wait for all packet processing
		   to finish. */
		oct_dev->fn_list.disable_io_queues(oct_dev);

        cavium_print_msg("Disabled the ioqs\n");
		if (wait_for_oq_pkts(oct_dev)) {
			cavium_error("OCTEON[%d]: OQ had pending packets\n",
				     oct_dev->octeon_id);
		}

        cavium_print_msg("wait for oq pkts completed\n");
		if (oct_dev->msix_on) {
			octeon_clear_irq_affinity(oct_dev);
			octeon_disable_msix_interrupts(oct_dev);
			octeon_delete_ioq_vector(oct_dev);
		}
        cavium_print_msg("deleted the ioq vectors\n");

#ifdef PCIE_AER
	case OCT_DEV_IN_RESET:
#endif

	case OCT_DEV_DROQ_INIT_DONE:

		cavium_mdelay(100);
		for (i = 0; i < oct_dev->num_oqs; i++) {
			octeon_delete_droq(oct_dev, i);
		}
		oct_dev->num_oqs = 0;
		cavium_print_msg("OCTEON[%d]: DROQs deleted.\n",
				 oct_dev->octeon_id);

       cavium_print_msg("deleted the droqs\n");

	case OCT_DEV_INSTR_QUEUE_INIT_DONE:

		for (i = 0; i < oct_dev->num_iqs; i++) {
			octeon_delete_instr_queue(oct_dev, i);
		}
		oct_dev->num_iqs = 0;
		cavium_print_msg("OCTEON[%d]: IQs deleted.\n",
				 oct_dev->octeon_id);

       cavium_print_msg("deleted the iqs\n");

	}
	cavium_print_msg("OCTEON[%d]: Octeon is in %s state\n",
			 oct_dev->octeon_id,
			 get_oct_state_string(&oct_dev->status));
	return 0;
}

int octeon_register_base_handler(void)
{
	octeon_module_handler_t base_handler;

	base_handler.startptr = oct_init_base_module;
	base_handler.resetptr = oct_reset_base_module;
	base_handler.stopptr = oct_stop_base_module;
	base_handler.app_type = CVM_DRV_BASE_APP;
	if (octeon_register_module_handler(&base_handler))
		return -1;

	return 0;

}

oct_poll_fn_status_t
oct_poll_module_starter(void *octptr, unsigned long arg UNUSED)
{
	octeon_device_t *oct = (octeon_device_t *) octptr;

	if (cavium_atomic_read(&oct->status) == OCT_DEV_RUNNING) {
		return OCT_POLL_FN_FINISHED;
	}

	/* If the status of the device is CORE_OK, the core
	   application has reported its application type. Call
	   any registered handlers now and move to the RUNNING
	   state. */
	if (cavium_atomic_read(&oct->status) != OCT_DEV_CORE_OK)
		return OCT_POLL_FN_CONTINUE;

//    cavium_atomic_set(&oct->status,OCT_DEV_RUNNING);

	/* for NIC mode, start_module is called from nic_module_handler */
	if (oct->app_mode == CVM_DRV_NIC_APP)
		return OCT_POLL_FN_CONTINUE;

	if (oct->app_mode) {
		printk("OCTEON[%d]: Starting module for app type: %s\n",
		       oct->octeon_id, get_oct_app_string(oct->app_mode));
		cavium_print(PRINT_DEBUG,
			     "OCTEON[%d]: Starting module for app type: %s\n",
			     oct->octeon_id, get_oct_app_string(oct->app_mode));
		if (octeon_start_module(oct->app_mode, oct->octeon_id)) {
			cavium_error
			    ("OCTEON[%d]: Start Handler failed for app_mode: %s\n",
			     oct->octeon_id, get_oct_app_string(oct->app_mode));
		}
	}

	return OCT_POLL_FN_CONTINUE;
}

/* Retruns the host firmware handshake OCTEON specific configuration */
octeon_config_t *octeon_get_conf(octeon_device_t * oct)
{
	octeon_config_t *default_oct_conf = NULL;

	/* check the OCTEON Device model & return the corresponding octeon configuration.
	 **/
	if (oct->chip_id == OCTEON_CN83XX_PF)
		default_oct_conf =
		    (octeon_config_t *) (CHIP_FIELD(oct, cn83xx_pf, conf));
	else if (oct->chip_id == OCTEON_CN93XX_PF ||
		 oct->chip_id == OCTEON_CN98XX_PF)
		default_oct_conf =
		    (octeon_config_t *) (CHIP_FIELD(oct, cn93xx_pf, conf));

	return default_oct_conf;
}

int dump_hostfw_config(octeon_config_t * temp_oct_conf)
{
	cavium_print(PRINT_DEBUG, "\nIQ Configuration:\n");
	cavium_print(PRINT_DEBUG, "-------------------\n");
	cavium_print(PRINT_DEBUG,
		     "max IQ:%d,	max base iq: %d, pending_list size: %d, \n",
		     CFG_GET_IQ_MAX_Q(temp_oct_conf),
		     CFG_GET_IQ_MAX_BASE_Q(temp_oct_conf),
		     CFG_GET_IQ_PENDING_LIST_SIZE(temp_oct_conf));
	cavium_print(PRINT_DEBUG,
		     "num_desc:%d,	instr type: %d, db_min: %d, db_timeout: %d\n",
		     CFG_GET_IQ_NUM_DESC(temp_oct_conf),
		     CFG_GET_IQ_INSTR_TYPE(temp_oct_conf),
		     CFG_GET_IQ_DB_MIN(temp_oct_conf),
		     CFG_GET_IQ_DB_TIMEOUT(temp_oct_conf));

	cavium_print(PRINT_DEBUG, "\nOQ Configuration:\n");
	cavium_print(PRINT_DEBUG, "-------------------\n");
	cavium_print(PRINT_DEBUG,
		     "max OQ: %d, max base OQ: %d, num_desc: %d, \n",
		     CFG_GET_OQ_MAX_Q(temp_oct_conf),
		     CFG_GET_OQ_MAX_BASE_Q(temp_oct_conf),
		     CFG_GET_OQ_NUM_DESC(temp_oct_conf));
	cavium_print(PRINT_DEBUG,
		     "info_ptr: %d, buf-size: %d, pkts_per_intr: %d, \n",
		     CFG_GET_OQ_INFO_PTR(temp_oct_conf),
		     CFG_GET_OQ_BUF_SIZE(temp_oct_conf),
		     CFG_GET_OQ_PKTS_PER_INTR(temp_oct_conf));
	cavium_print(PRINT_DEBUG,
		     "refill_threshold: %d, oq_intr_pkt: %d, oq_intr_time: %d, \n",
		     CFG_GET_OQ_REFILL_THRESHOLD(temp_oct_conf),
		     CFG_GET_OQ_INTR_PKT(temp_oct_conf),
		     CFG_GET_OQ_INTR_TIME(temp_oct_conf));

	cavium_print(PRINT_DEBUG, "\nPKO Configuration:\n");
	cavium_print(PRINT_DEBUG, "-------------------\n");
	cavium_print(PRINT_DEBUG, "IF 0: cmdq:%d, links: %d\n",
		     CFG_GET_PKO_CMDQ_PER_IF(temp_oct_conf, 0),
		     CFG_GET_PKO_LINK_PER_IF(temp_oct_conf, 0));
	cavium_print(PRINT_DEBUG, "IF 1: cmdq:%d, links: %d\n",
		     CFG_GET_PKO_CMDQ_PER_IF(temp_oct_conf, 1),
		     CFG_GET_PKO_LINK_PER_IF(temp_oct_conf, 1));
	cavium_print(PRINT_DEBUG, "IF 2: cmdq:%d, links: %d\n",
		     CFG_GET_PKO_CMDQ_PER_IF(temp_oct_conf, 2),
		     CFG_GET_PKO_LINK_PER_IF(temp_oct_conf, 2));
	cavium_print(PRINT_DEBUG, "cmdq per pci port: %d\n",
		     CFG_GET_PKO_CMDQ_PER_PCI_PORT(temp_oct_conf, 0));

	cavium_print(PRINT_DEBUG, "\nFPA Configuration:\n");
	cavium_print(PRINT_DEBUG, "-------------------\n");
	cavium_print(PRINT_DEBUG, "Pool-0: size:%d count: %d\n",
		     CFG_GET_POOL_BUF_SIZE(temp_oct_conf, 0),
		     CFG_GET_POOL_BUF_CNT(temp_oct_conf, 0));
	cavium_print(PRINT_DEBUG, "Pool-1: size:%d count: %d\n",
		     CFG_GET_POOL_BUF_SIZE(temp_oct_conf, 1),
		     CFG_GET_POOL_BUF_CNT(temp_oct_conf, 1));
	cavium_print(PRINT_DEBUG, "Pool-2: size:%d count: %d\n",
		     CFG_GET_POOL_BUF_SIZE(temp_oct_conf, 2),
		     CFG_GET_POOL_BUF_CNT(temp_oct_conf, 2));
	cavium_print(PRINT_DEBUG, "Pool-3: size:%d count: %d\n",
		     CFG_GET_POOL_BUF_SIZE(temp_oct_conf, 3),
		     CFG_GET_POOL_BUF_CNT(temp_oct_conf, 3));

	cavium_print(PRINT_DEBUG, "\nPORT Configuration:\n");
	cavium_print(PRINT_DEBUG, "-------------------\n");
	cavium_print(PRINT_DEBUG,
		     "SRN for the device: %d	Num IOQs for each interface:%d\n",
		     CFG_GET_PORTS_SRN(temp_oct_conf),
		     CFG_GET_PORTS_NUM_IOQ(temp_oct_conf));

	cavium_print(PRINT_DEBUG, "\nMISC Configuration:\n");
	cavium_print(PRINT_DEBUG, "-------------------\n");
	cavium_print(PRINT_DEBUG,
		     "mem_size: %d, core cnt:%d, ctrlq_num: %d flags: %d, crc: %d\n",
		     CFG_GET_MEM_SIZE(temp_oct_conf),
		     CFG_GET_CORE_CNT(temp_oct_conf),
		     CFG_GET_CTRL_Q_NO(temp_oct_conf),
		     CFG_GET_FLAGS(temp_oct_conf), CFG_GET_CRC(temp_oct_conf));
	cavium_print(PRINT_DEBUG, "Host Link_query_interval : %d\n",
		     CFG_GET_HOST_LINK_QUERY_INTERVAL(temp_oct_conf));
	cavium_print(PRINT_DEBUG, "Octeon Link_query_interval : %d\n",
		     CFG_GET_OCT_LINK_QUERY_INTERVAL(temp_oct_conf));

	return 0;
}

void npu_mem_and_intr_test (octeon_device_t *octeon_dev,
			    int idx,
			    struct npu_bar_map *barmap)
{
	struct facility_bar_map *facility_map;

	//write to first 4-bytes of every region
	facility_map = &barmap->facility_map[MV_FACILITY_CONTROL];
	*(volatile uint32_t *)(octeon_dev->mmio[idx].hw_addr +
				facility_map->offset) = 0xA5A5A5A5;

	facility_map = &barmap->facility_map[MV_FACILITY_MGMT_NETDEV];
	*(volatile uint32_t *)(octeon_dev->mmio[idx].hw_addr +
				facility_map->offset) = 0xA6A6A6A6;

	facility_map = &barmap->facility_map[MV_FACILITY_NW_AGENT];
	*(volatile uint32_t *)(octeon_dev->mmio[idx].hw_addr +
				facility_map->offset) = 0x5A5A5A5A;

	facility_map = &barmap->facility_map[MV_FACILITY_RPC];
	*(volatile uint32_t *)(octeon_dev->mmio[idx].hw_addr +
				facility_map->offset) = 0xABABABAB;
	//raise control interrupt
	facility_map = &barmap->facility_map[MV_FACILITY_CONTROL];
	printk("Raising interrupt; offset=%x, #spi=%x\n",
	       barmap->gicd_offset, facility_map->h2t_dbell_start);
	*(volatile uint32_t *)(octeon_dev->mmio[idx].hw_addr +
		 barmap->gicd_offset) = facility_map->h2t_dbell_start;
}

//struct npu_bar_map npu_memmap_info;

static void npu_bar_map_save(void *src, octeon_device_t *oct)
{
	memcpy(&oct->npu_memmap_info, src, sizeof(struct npu_bar_map));
}

#define NPU_BASE_READY_MAGIC 0xABCDABCD
bool npu_handshake_done=false;
extern void mv_facility_conf_init(octeon_device_t *oct);
extern int host_device_access_init(octeon_device_t *oct);
oct_poll_fn_status_t 
octeon_wait_for_npu_base(void *octptr, unsigned long arg UNUSED)
{
	octeon_device_t *octeon_dev = (octeon_device_t *) octptr;
	volatile uint64_t reg_val = 0;
    u8 mps_val, mrrs_val;
    int mps, mrrs, port = 0, dpi_num = 0;

	/** 
	 * Along with the app mode firmware sends core clock(in MHz),
	 * co-processor clock(in MHz) and pkind value.
	 * Bits: 00-31  Signature indicating NPU base driver ready
	 * Bits: 32-63  offset in BAR1 where the memory map structure is written
	 **/
	if(octeon_dev->chip_id == OCTEON_CN83XX_PF) {
		reg_val = octeon_read_csr64(octeon_dev, CN83XX_SDP_SCRATCH(0));
		if((reg_val & 0xffffffff) != NPU_BASE_READY_MAGIC) {
			return OCT_POLL_FN_CONTINUE;
		}
		printk("%s: CN83xx NPU is ready; MAGIC=0x%llX; memmap=0x%llX\n",
		       __func__, reg_val & 0xffffffff, reg_val >> 32);
	printk("hw_addr = 0x%llx\n", (unsigned long long)octeon_dev->mmio[1].hw_addr);
		npu_bar_map_save(octeon_dev->mmio[1].hw_addr + (reg_val >> 32), octeon_dev);
		npu_barmap_dump((void *)&octeon_dev->npu_memmap_info);
		npu_mem_and_intr_test(octeon_dev, 1, &octeon_dev->npu_memmap_info);
	//npu_handshake_done = true;
	//return OCT_POLL_FN_FINISHED;
		mv_facility_conf_init(octeon_dev);

		/* setup the Host device access for RPC */
		if (host_device_access_init(octeon_dev) < 0)
			pr_err("host_device_access_init failed\n");
	} else if(octeon_dev->chip_id == OCTEON_CN93XX_PF ||
		  octeon_dev->chip_id == OCTEON_CN98XX_PF) {
		reg_val = octeon_read_csr64(octeon_dev, CN93XX_SDP_EPF_SCRATCH);
		if((reg_val & 0xffffffff) != NPU_BASE_READY_MAGIC) {
            printk("read CN93XX_SDP_EPF_SCRATCH 0x%llx\n", reg_val);
			return OCT_POLL_FN_CONTINUE;
		}
		printk("%s: CN93xx NPU is ready; MAGIC=0x%llX; memmap=0x%llX\n",
		       __func__, reg_val & 0xffffffff, reg_val >> 32);
		printk("hw_addr = 0x%llx\n", (unsigned long long)octeon_dev->mmio[2].hw_addr);
		npu_bar_map_save(octeon_dev->mmio[2].hw_addr + (reg_val >> 32), octeon_dev);
		npu_barmap_dump((void *)&octeon_dev->npu_memmap_info);
        if (octeon_dev->npu_memmap_info.version == 0xFFFFFFFF) {
            printk("%s: FATAL error; CN9xxx bar map info corrupted, maybe host_sid error !!!\n",
                    __func__);
            WARN_ON(1);
            octeon_dev->facility_conf_init_error = true;
            return OCT_POLL_FN_FINISHED;
        }
		npu_mem_and_intr_test(octeon_dev, 2, &octeon_dev->npu_memmap_info);
	//npu_handshake_done = true;
	//return OCT_POLL_FN_FINISHED;
		mv_facility_conf_init(octeon_dev);

		/* setup the Host device access for RPC */
		if (host_device_access_init(octeon_dev) < 0)
			pr_err("host_device_access_init failed\n");
	} else {
		printk("%s: Chip id 0x%x is not supported\n",
		       __func__, octeon_dev->chip_id);
		return OCT_POLL_FN_CONTINUE;
	}

    /* setup DPI MPS and MRRS accordingly */
    mps = pcie_get_mps(octeon_dev->pci_dev);
    mrrs = pcie_get_readrq(octeon_dev->pci_dev);
    cavium_print_msg(" MPS=%d, MRRS=%d\n",mps, mrrs);

    mps_val = fls(mps) - 8;
    mrrs_val = fls(mrrs) - 8;

    if (octeon_dev->chip_id == OCTEON_CN83XX_PF)
        port = octeon_dev->pcie_port;
    else if (octeon_dev->chip_id == OCTEON_CN93XX_PF)
        port = octeon_dev->pcie_port / 2; //its either 0 or 1
    /*
     * Due to SDP-38594 the workaround is to pass the PEM number through the
     * memmap structure from the EP
     */
    else if (octeon_dev->chip_id == OCTEON_CN98XX_PF) {
    }

    if (!dpi_num) {
        reg_val = OCTEON_PCI_WIN_READ(octeon_dev, DPI0_EBUS_PORTX_CFG(port));
        reg_val |= 0x10000 | (mps_val << 4) | mrrs_val;
        cavium_print_msg("DPI0 port %d MPS=%d, MRRS=%d\n", port, mps_val, mrrs_val);
        OCTEON_PCI_WIN_WRITE(octeon_dev, DPI0_EBUS_PORTX_CFG(port), reg_val);
    } else {
        reg_val = OCTEON_PCI_WIN_READ(octeon_dev, DPI1_EBUS_PORTX_CFG(port));
        reg_val |= 0x10000 | (mps_val << 4) | mrrs_val;
        cavium_print_msg("DPI1 port %d MPS=%d, MRRS=%d\n", port, mps_val, mrrs_val);
        OCTEON_PCI_WIN_WRITE(octeon_dev, DPI1_EBUS_PORTX_CFG(port), reg_val);
    }

	npu_handshake_done = true;
	octeon_dev->is_set=1;
	return OCT_POLL_FN_FINISHED;
}

#define SDP_HOST_LOADED                 0xDEADBEEFULL
#define SDP_GET_HOST_INFO               0xBEEFDEEDULL 
#define SDP_HOST_INFO_RECEIVED          0xDEADDEULL
#define SDP_HANDSHAKE_COMPLETED         0xDEEDDEEDULL
#define OTX2_CUSTOM_PKIND		59

oct_poll_fn_status_t 
octeon_get_app_mode(void *octptr, unsigned long arg UNUSED)
{
    octeon_device_t *octeon_dev = (octeon_device_t *) octptr;
    volatile uint64_t reg_val = 0;
    uint16_t core_clk, coproc_clk;
    static octeon_config_t *default_oct_conf = NULL;
    uint64_t epf_rinfo;
    uint16_t vf_srn;
 
    if(octeon_dev->chip_id == OCTEON_CN93XX_PF ||
       octeon_dev->chip_id == OCTEON_CN98XX_PF) {
	//octeon_dev->app_mode = CVM_DRV_BASE_APP;
	reg_val = 0;
        if(((g_app_mode[octeon_dev->octeon_id] & 0xffff) != CVM_DRV_BASE_APP) && 
            ((g_app_mode[octeon_dev->octeon_id] & 0xffff) != CVM_DRV_NIC_APP)) {
		return OCT_POLL_FN_CONTINUE;
	}
	octeon_dev->app_mode = CVM_DRV_NIC_APP;
	core_clk = 1200;
	coproc_clk = (reg_val >> 16) & 0xffff;
	octeon_dev->pkind = OTX2_CUSTOM_PKIND;
    } else {
	reg_val = octeon_read_csr64(octeon_dev, CN83XX_SLI_EPF_SCRATCH(0));
	if (reg_val == SDP_HOST_LOADED)
		return OCT_POLL_FN_CONTINUE;

	epf_rinfo = octeon_read_csr64(octeon_dev, CN83XX_SDP_EPF_RINFO(octeon_dev->epf_num));
	/* vf_srn is just the starting ring number */
	vf_srn = epf_rinfo & 0x3f;
	if (reg_val == SDP_GET_HOST_INFO) {
		reg_val = 0;
		reg_val = ((uint64_t)CVM_DRV_NIC_APP << 40 |
			   (uint64_t)octeon_dev->sriov_info.pf_srn << 32 |
			   (uint64_t)octeon_dev->sriov_info.rings_per_pf << 24 |
			   (uint64_t)octeon_dev->sriov_info.num_vfs << 16 |
			   (uint64_t)vf_srn << 8 |
			   (uint64_t)octeon_dev->sriov_info.rings_per_vf);
	
		octeon_write_csr64(octeon_dev, CN83XX_SLI_EPF_SCRATCH(0), reg_val);	
	}
	while (octeon_read_csr64(octeon_dev, CN83XX_SLI_EPF_SCRATCH(0)) == reg_val);

	reg_val = octeon_read_csr64(octeon_dev, CN83XX_SLI_EPF_SCRATCH(0));
	octeon_write_csr64(octeon_dev, CN83XX_SLI_EPF_SCRATCH(0), SDP_HANDSHAKE_COMPLETED);

	octeon_dev->app_mode = CVM_DRV_NIC_APP;
	core_clk = 1200;
	coproc_clk = (reg_val >> 16) & 0xffff;
	octeon_dev->pkind = 40;
    }

    cavium_print_msg("OCTEON running with Core clock:%d Copro clock:%d\n",
            core_clk, coproc_clk);
    cavium_print(PRINT_DEBUG,"Application mode:%d pkind:%d\n", 
            octeon_dev->app_mode, octeon_dev->pkind);
    cavium_print_msg("Application mode:%d pkind:%d\n", 
            octeon_dev->app_mode, octeon_dev->pkind);
    if (octeon_dev->chip_id == OCTEON_CN83XX_PF)
    	default_oct_conf = (octeon_config_t *) (CHIP_FIELD(octeon_dev, cn83xx_pf, conf));
    else if (octeon_dev->chip_id == OCTEON_CN93XX_PF ||
	     octeon_dev->chip_id == OCTEON_CN98XX_PF)
		default_oct_conf = (octeon_config_t *) (CHIP_FIELD(octeon_dev, cn93xx_pf, conf));
	
    CFG_GET_CORE_TICS_PER_US(default_oct_conf) = core_clk;
    CFG_GET_COPROC_TICS_PER_US(default_oct_conf) = coproc_clk;
    CFG_GET_DPI_PKIND(default_oct_conf) = octeon_dev->pkind;
    cavium_atomic_set(&octeon_dev->status, OCT_DEV_CORE_OK);

    if(octeon_dev->app_mode == CVM_DRV_NIC_APP) {
        /* Number of interfaces are 1 */
        CFG_GET_NUM_INTF(default_oct_conf) = 1;
        cavium_print_msg("Octeon is running nic application\n");
    }
    octeon_probe_module_handlers(octeon_dev->octeon_id);
    return OCT_POLL_FN_FINISHED;
}

/* scratch register address for CN73XX */
#define CN73XX_SLI_SCRATCH1     0x283C0

oct_poll_fn_status_t
octeon_hostfw_handshake(void *octptr, unsigned long arg UNUSED)
{

	int64_t scratch_val = 0LL;
	uint64_t buf_addr = 0ULL;
	uint64_t value = 0ULL, scratch_reg_addr = 0ULL;
	uint32_t indication = 0;
	static int num_cores = 0, num_intf = 0;
	static octeon_config_t temp_oct_conf, *default_oct_conf = NULL;
	octeon_device_t *oct = (octeon_device_t *) octptr;
	char app_name[16];


	switch (oct->chip_id) {
	case OCTEON_CN83XX_PF:
		scratch_reg_addr = CN83XX_SDP_SCRATCH(0);
		break;
	case OCTEON_CN93XX_PF:
	case OCTEON_CN98XX_PF:
		scratch_reg_addr = CN93XX_SDP_EPF_SCRATCH;
		break;
	}

	scratch_val = octeon_read_csr64(oct, scratch_reg_addr);

	indication = scratch_val & 0xffff;	//indication is lsb 2 bytes
	value = (scratch_val & ~0xffffULL) >> 16;	//msb 6 bytes is the value

	switch (cavium_atomic_read(&oct->hostfw_hs_state)) {
		/* check for Host Firmware Handshake support */
	case HOSTFW_HS_INIT:
		if (indication == HOSTFW_HS_APP_INDICATION) {
			oct->app_mode = value & 0xffffff;
			cavium_strncpy(app_name, sizeof(app_name),
				       get_oct_app_string(oct->app_mode),
				       sizeof(app_name) - 1);
			cavium_print_msg("Received app type from Octeon: %s\n",
					 app_name);

			/* NAPI and RX reuse buffers should be disabled for Base mode */
#if defined(OCT_NIC_USE_NAPI) || defined(OCT_REUSE_RX_BUFS)
			if ((oct->app_mode == CVM_DRV_BASE_APP)
			    || (oct->app_mode == CVM_DRV_ZLIB_APP)) {
				cavium_print_msg
				    ("\n\n\t\t########################################################\n");
				cavium_print_msg
				    ("WARNING: Macros OCT_NIC_USE_NAPI and OCT_REUSE_RX_BUFS");
				cavium_print_msg
				    ("\n\t\t\tshould be disabled for BASE mode operations");
				cavium_print_msg
				    ("\n\t\t########################################################\n\n");
				/* this is an error: so exit the hand shake */
				return OCT_POLL_FN_FINISHED;
			}
#endif
			default_oct_conf = octeon_get_conf(oct);

			if ((value >> 32) == HOSTFW_HS_SUPPORT_INDICATION) {
				/* Send ack to core */
				octeon_write_csr64(oct,
						   scratch_reg_addr,
						   HOSTFW_HS_ACK);

				cavium_atomic_set(&oct->hostfw_hs_state,
						  HOSTFW_HS_WAIT_NAMED_BLOCK);
			} else {
				octeon_write_csr64(oct,
						   scratch_reg_addr,
						   HOSTFW_HS_ACK);

				cavium_atomic_set(&oct->hostfw_hs_state,
						  HOSTFW_HS_NUM_INTF);

			}
			CFG_GET_APP_MODE(default_oct_conf) = oct->app_mode;
		}

		break;

	case HOSTFW_HS_WAIT_NAMED_BLOCK:
		if (indication == HOSTFW_HS_NB_BLOCK_INDICATION) {
			/* Extract the num cores, num intf and buffer address from the scratch val. */
			buf_addr = (scratch_val >> 16);
			cavium_print
			    (PRINT_DEBUG,
			     "Received Named Block from Octeon with addr:  %016llx \n",
			     buf_addr);

			/* Copy the config params to a temp buffer and do 8-byte swapping before sending to core */
			cavium_memcpy(&temp_oct_conf, default_oct_conf,
				      sizeof(octeon_config_t));

			octeon_swap_8B_data((uint64_t *) & temp_oct_conf,
					    sizeof(octeon_config_t) / 8);

			/* Write the cfg details to core buffer */
			octeon_pci_write_core_mem(oct, buf_addr,
						  (uint8_t *) & temp_oct_conf,
						  sizeof(octeon_config_t), 0);
			cavium_print(PRINT_DEBUG,
				     "Host Wrote the cfg details to the NB.\n");

			/* Read back the cfg values from core buffer */
			octeon_pci_read_core_mem(oct, buf_addr,
						 (uint8_t *) & temp_oct_conf,
						 sizeof(octeon_config_t), 0);

			octeon_swap_8B_data((uint64_t *) & temp_oct_conf,
					    sizeof(temp_oct_conf) / 8);

			if (cavium_memcmp
			    (&temp_oct_conf, default_oct_conf,
			     sizeof(octeon_config_t)))
				cavium_print(PRINT_ERROR,
					     " Read Write Mismatch in Host Firmware Config Params \n");

			/* Send ack to core */
			octeon_write_csr64(oct, scratch_reg_addr,
					   HOSTFW_HS_ACK);

			cavium_print(PRINT_DEBUG,
				     "Waiting for the cfg read confirmation from the firmware \n");
			cavium_atomic_set(&oct->hostfw_hs_state,
					  HOSTFW_HS_WAIT_CFG_READ);
		}

		break;

	case HOSTFW_HS_WAIT_CFG_READ:
		if (indication == HOSTFW_HS_READ_DONE_INDICATION) {
			num_cores = value & 0xff;

			cavium_print
			    (PRINT_DEBUG,
			     "Received Read completion indication from the firmware.\n");
			cavium_print_msg("Firmware is running on %d cores.n",
					 num_cores);

			/* Send ack to core */
			octeon_write_csr64(oct, scratch_reg_addr,
					   HOSTFW_HS_ACK);

			cavium_atomic_set(&oct->hostfw_hs_state,
					  HOSTFW_HS_NUM_INTF);
		}

		break;

	case HOSTFW_HS_NUM_INTF:
		if (indication == HOSTFW_HS_NUM_INTF_INDICATION) {
#ifdef ETHERPCI
			value = (scratch_val & ~0xffffULL) >> 32;
#endif
			oct->pkind = (uint8_t) value & 0xff;
			num_intf = (uint8_t) (value >> 8) & 0xff;
			cavium_print_msg
			    ("Received Pkind for DPI: 0x%x, num interfaces: %d\n",
			     oct->pkind, num_intf);

			/* Send ack to core */
			octeon_write_csr64(oct, scratch_reg_addr,
					   HOSTFW_HS_ACK);
#ifndef ETHERPCI
			CFG_GET_DPI_PKIND(default_oct_conf) = oct->pkind;
			CFG_GET_NUM_INTF(default_oct_conf) = num_intf;
			cavium_atomic_set(&oct->hostfw_hs_state,
					  HOSTFW_HS_CORE_ACTIVE);
#else
			cavium_atomic_set(&oct->hostfw_hs_state,
					  HOSTFW_HS_DONE);
			cavium_atomic_set(&oct->status, OCT_DEV_CORE_OK);
			return OCT_POLL_FN_FINISHED;
#endif

		}

		break;
	case HOSTFW_HS_CORE_ACTIVE:
		if (indication == HOSTFW_HS_CORE_ACTIVE_INDICATION) {
			int oct_id = oct->octeon_id;
			uint16_t core_clk, coproc_clk;

			cavium_print_msg
			    ("OCTEON[%d]: Received active indication from core\n",
			     oct->octeon_id);

			core_clk = (value & 0xffff);
			coproc_clk = ((value >> 16) & 0xffff);
			CFG_GET_CORE_TICS_PER_US(default_oct_conf) = core_clk;
			CFG_GET_COPROC_TICS_PER_US(default_oct_conf) =
			    coproc_clk;

			cavium_print(PRINT_DEBUG, " coprocessor clock::%x\n",
				     CFG_GET_COPROC_TICS_PER_US
				     (default_oct_conf));
			core_setup[oct_id].corefreq = core_clk * 1000 * 1000;
			cavium_print_msg
			    ("OCTEON[%d] is running with core clock: %llu Hz\n",
			     oct->octeon_id,
			     CVM_CAST64(core_setup[oct_id].corefreq));

			/* Send ack to core */
			octeon_write_csr64(oct, scratch_reg_addr,
					   HOSTFW_HS_ACK);

			if (oct->chip_id == OCTEON_CN83XX_PF)
				cavium_atomic_set(&oct->hostfw_hs_state,
						  HOSTPF0_HS_INIT);
			else
				cavium_atomic_set(&oct->hostfw_hs_state,
						  HOSTFW_HS_DONE);
		}
		break;

		/*  PF0 gets to these state after PF0-FIRMWARE handshake is done */
	case HOSTPF0_HS_INIT:
		if (indication == HOSTFW_HS_SCRATCH_FREE_INDICATION) {
			uint32_t oct_id = oct->octeon_id;
			uint64_t oct_idx = 0;

			oct_idx = (oct_id << 0x10) | HOST_HS_OCT_IDX_INDICATION;

			/* Write PF0's oct_idx in scratch reg, PF1 can leverage it 
			 * to read the app_mode , pkind etc.*/
			octeon_write_csr64(oct, scratch_reg_addr,
					   oct_idx);

			cavium_atomic_set(&oct->hostfw_hs_state,
					  HOSTFW_HS_DONE);

		}
		break;

		/*  PF1 gets to these state by default and polls for PF0-PF1 handshake */
	case HOSTPF1_HS_INIT:
		if (indication == HOST_HS_OCT_IDX_INDICATION) {
			int oct_pf0_idx = 0, oct_pf1_idx = 0;
			octeon_device_t *oct_pf0 = NULL;
			oct_pf0_idx = value;
			oct_pf1_idx = oct->octeon_id;

			oct_pf0 = octeon_device[oct_pf0_idx];

			/* PF0-FW handshake is done, now read the core config from PF0 */
			if (NULL != oct_pf0) {
				/* Firmware allocates consecutive pkinds for PF0 & PF1. */
				oct->pkind = oct_pf0->pkind + 1;
				oct->app_mode = oct_pf0->app_mode;

				//    cavium_atomic_set(&oct->status, OCT_DEV_CORE_OK);

				cavium_atomic_set(&oct->hostfw_hs_state,
						  HOSTFW_HS_DONE);
			} else
				cavium_print_msg
				    ("[HS ERROR]: Incorrect oct idx is received.\n");
		}
		break;

		/*      Now, we are done with handshake. So unregister this poll thread */
	case HOSTFW_HS_DONE:

		cavium_atomic_set(&oct->status, OCT_DEV_CORE_OK);

		/* complete the IOQ's creation and misc initialisation (only for CN83XX) */
		if (((oct->app_mode == CVM_DRV_BASE_APP)
		     || (oct->app_mode == CVM_DRV_ZLIB_APP))
		    && (oct->chip_id == OCTEON_CN83XX_PF)) {
			octeon_register_base_handler();
		}

		/* restore the state to init */
		cavium_atomic_set(&oct->hostfw_hs_state, HOSTFW_HS_INIT);
#if 0		
		if ((oct->pf_num == OCTEON_CN73XX_PF1)
		    || (oct->pf_num == OCTEON_CN78XX_PF1))
			cavium_atomic_set(&oct->hostfw_hs_state,
					  HOSTPF1_HS_INIT);
#endif

		return OCT_POLL_FN_FINISHED;
	}

	return OCT_POLL_FN_CONTINUE;
}

static inline int
__octeon_module_action(uint32_t app_type,
		       uint32_t operation, uint32_t octeon_id)
{
	int i, retval = 0;
	octeon_module_handler_t *handler = NULL;
	octeon_device_t *octeon_dev = NULL;

	octeon_dev = get_octeon_device(octeon_id);
	if (octeon_dev == NULL) {
		cavium_error("OCTEON: No octeon device (id:%d) found in %s\n",
			     octeon_id, __CVM_FUNCTION__);
		return -ENODEV;
	}

	cavium_spin_lock(&octmodhandlers_lock);

	for (i = 0; i < OCTEON_MAX_MODULES; i++) {

		/* Check if a handler exists for the given app_type. */
		if (!(octmodhandlers[i].app_type & app_type))
			continue;

		handler = &octmodhandlers[i];

		/* If no handler is found, return without error. */
		if (handler == NULL) {
			cavium_error
			    ("OCTEON: No handler found for application type %s\n",
			     get_oct_app_string(app_type));
			continue;
		}

		cavium_print_msg("OCTEON[%d]: Found handler for app_type: %s\n",
				 octeon_dev->octeon_id,
				 get_oct_app_string(handler->app_type));

		cavium_spin_unlock(&octmodhandlers_lock);

		/* If a handler exists, call the start or stop routine based on
		   the operation specified. */
		switch (operation) {
		case OCTEON_START_MODULE:
			retval =
			    handler->startptr(octeon_id,
					      octeon_device[octeon_id]);
			break;
		case OCTEON_RESET_MODULE:
			retval =
			    handler->resetptr(octeon_id,
					      octeon_device[octeon_id]);
			break;
		case OCTEON_STOP_MODULE:
			retval =
			    handler->stopptr(octeon_id,
					     octeon_device[octeon_id]);
			break;
		default:
			cavium_error("OCTEON: Unknown operation %d in %s\n",
				     operation, __CVM_FUNCTION__);
			return -EINVAL;
		}

		cavium_spin_lock(&octmodhandlers_lock);
	}

	cavium_spin_unlock(&octmodhandlers_lock);

	return retval;
}

int octeon_start_module(uint32_t app_type, uint32_t octeon_id)
{
	return __octeon_module_action(app_type, OCTEON_START_MODULE, octeon_id);
}

int octeon_reset_module(uint32_t app_type, uint32_t octeon_id)
{
	return __octeon_module_action(app_type, OCTEON_RESET_MODULE, octeon_id);
}

int octeon_stop_module(uint32_t app_type, uint32_t octeon_id)
{
	return __octeon_module_action(app_type, OCTEON_STOP_MODULE, octeon_id);
}

void octeon_init_module_handler_list(void)
{
	cavium_memset(&octmodhandlers, 0, sizeof(octeon_module_handler_t));
	cavium_spin_lock_init(&octmodhandlers_lock);
}

void octeon_probe_module_handlers(int octeon_id)
{
	octeon_device_t *oct_dev = octeon_device[octeon_id];
	int modidx;

	/* Call the start method for all existing octeon devices. */
	for (modidx = 0; modidx < OCTEON_MAX_MODULES; modidx++) {
		octeon_module_handler_t *handler = &octmodhandlers[modidx];

		if ((oct_dev->app_mode & handler->app_type) &&
		    (cavium_atomic_read(&oct_dev->mod_status[modidx]) ==
		     OCTEON_MODULE_HANDLER_INIT_LATER)) {
			cavium_print_msg("OCTEON[%d]: Starting modules for app_type: %s\n",
				     octeon_id,
				     get_oct_app_string(handler->app_type));
			if (handler->startptr(octeon_id, oct_dev)) {
				/* Call the stop method */
				handler->stopptr(octeon_id, oct_dev);
				cavium_atomic_set(&oct_dev->mod_status[modidx],
						OCTEON_MODULE_HANDLER_STOPPED);
				cavium_spin_lock(&octmodhandlers_lock);
				cavium_memset(handler, 0,
					      sizeof(octeon_module_handler_t));
				cavium_spin_unlock(&octmodhandlers_lock);
				continue;
			}
			cavium_atomic_set(&oct_dev->mod_status[modidx],
					  OCTEON_MODULE_HANDLER_INIT_DONE);
		}
	}
}

int octeon_register_module_handler(octeon_module_handler_t * handler)
{
	int modidx, octidx, retval = 0;

	if (!handler || !handler->startptr || !handler->stopptr
	    || !handler->resetptr || !handler->app_type) {
		cavium_error("OCTEON: Invalid arguments in module handler\n");
		return -EINVAL;
	}

	cavium_spin_lock(&octmodhandlers_lock);
	/* Check if a handler has already been registered for this app type. */
	for (modidx = 0; modidx < OCTEON_MAX_MODULES; modidx++) {
		if (octmodhandlers[modidx].app_type == handler->app_type) {
			cavium_print
			    (PRINT_DEBUG,
			     "OCTEON: Module Handler exists for application type 0x%x\n",
			     handler->app_type);
			cavium_spin_unlock(&octmodhandlers_lock);
			return -EINVAL;
		}
	}

	/* Check if space exists in handler array to register this handler. */
	for (modidx = 0; modidx < OCTEON_MAX_MODULES; modidx++) {
		if (octmodhandlers[modidx].app_type == 0)
			break;
	}

	if (modidx == OCTEON_MAX_MODULES) {
		cavium_error
		    ("OCTEON: Module handler registration failed (Max handlers reached)\n");
		cavium_spin_unlock(&octmodhandlers_lock);
		return -ENOMEM;
	}

	/* Add this handler to the module handlers array. */
	cavium_memcpy(&octmodhandlers[modidx], handler,
		      sizeof(octeon_module_handler_t));

	cavium_spin_unlock(&octmodhandlers_lock);

	cavium_print(PRINT_DEBUG,
		     "OCTEON: Registered handler for app_type: %s\n",
		     get_oct_app_string(handler->app_type));

	/* If app_type is BASE, return from here itself, else the start routine gets called for
	 * all the available octeon_devices irrespective of device driver's state.
	 */
	if (handler->app_type == CVM_DRV_BASE_APP)
		return retval;

	/* Call the start method for all existing octeon devices. */
	for (octidx = 0; octidx < MAX_OCTEON_DEVICES; octidx++) {
		octeon_device_t *oct_dev = octeon_device[octidx];

		if (oct_dev == NULL)
			continue;

		cavium_atomic_set(&oct_dev->mod_status[modidx],
				  OCTEON_MODULE_HANDLER_REGISTERED);
#ifdef  ETHERPCI
		oct_dev->app_mode = CVM_DRV_NIC_APP;	// Emulate NIC PCI Device
		cavium_atomic_set(&oct_dev->status, OCT_DEV_CORE_OK);
#endif
		if (oct_dev->app_mode & handler->app_type) {
			cavium_print(PRINT_DEBUG,
				     "OCTEON[%d]: Starting modules for app_type: %s\n",
				     oct_dev->octeon_id,
				     get_oct_app_string(handler->app_type));
			retval = handler->startptr(octidx, oct_dev);
			if (retval) {
				/* Call the stop method for all octeon devices */
				octidx--;
				while (octidx >= 0) {
					octeon_device_t *oct =
					    octeon_device[octidx];
					handler->stopptr(octidx, oct);
					octidx--;
				}
				cavium_spin_lock(&octmodhandlers_lock);
				cavium_memset(&octmodhandlers[modidx], 0,
					      sizeof(octeon_module_handler_t));
				cavium_spin_unlock(&octmodhandlers_lock);
				return retval;
			}
			cavium_atomic_set(&oct_dev->mod_status[modidx],
					  OCTEON_MODULE_HANDLER_INIT_DONE);
		} else {
			cavium_print_msg("OCTEON[%d]: waiting for app mode; "
				"\"%s\" module will be started one app mode is identified\n",
				oct_dev->octeon_id,
				get_oct_app_string(handler->app_type));
			cavium_atomic_set(&oct_dev->mod_status[modidx],
					  OCTEON_MODULE_HANDLER_INIT_LATER);
		}
	}

	return retval;
}

int octeon_unregister_module_handler(uint32_t app_type)
{
	int modidx, octidx, retval = 0;
	octeon_module_handler_t handler;

	handler.app_type = CVM_DRV_NO_APP;

	cavium_spin_lock(&octmodhandlers_lock);
	/* Check if a handler exists for this app type. */
	for (modidx = 0; modidx < OCTEON_MAX_MODULES; modidx++) {
		if (octmodhandlers[modidx].app_type == app_type) {
			cavium_memcpy(&handler, &octmodhandlers[modidx],
				      sizeof(octeon_module_handler_t));
			cavium_memset(&octmodhandlers[modidx], 0,
				      sizeof(octeon_module_handler_t));
			break;
		}
	}
	cavium_spin_unlock(&octmodhandlers_lock);

	if (modidx == OCTEON_MAX_MODULES) {
		cavium_error("OCTEON: No handler for application type 0x%x\n",
			     app_type);
		return -ENODEV;
	}

	/* Call the stop method for all existing octeon devices. */
	for (octidx = 0; octidx < MAX_OCTEON_DEVICES; octidx++) {
		octeon_device_t *oct_dev = octeon_device[octidx];

		if ((oct_dev) && (oct_dev->app_mode & handler.app_type)) {
			cavium_print_msg
			    ("OCTEON[%d]: Stopping modules for app_type: %s\n",
			     oct_dev->octeon_id,
			     get_oct_app_string(handler.app_type));
			retval |= handler.stopptr(octidx, oct_dev);
		}
	}

	cavium_print_msg("OCTEON: Unregistered handler for app_type: %s\n",
			 get_oct_app_string(app_type));

	return retval;
}

void print_octeon_state_errormsg(octeon_device_t * oct)
{
	cavium_error("Octeon device (%d) is in state (0x%x)\n",
		     oct->octeon_id, cavium_atomic_read(&oct->status));
}

/** Get the octeon device pointer.
 *  @param octeon_id  - The id for which the octeon device pointer is required.
 *  @return Success: Octeon device pointer.
 *  @return Failure: NULL.
 */
octeon_device_t *get_octeon_device(uint32_t octeon_id)
{
	if (octeon_id >= MAX_OCTEON_DEVICES)
		return NULL;
	else
		return octeon_device[octeon_id];
}

/** Gets the octeon device id when the device structure is given.
 *  @return - The octeon device id.
 */
uint32_t get_octeon_id(octeon_device_t * octeon_dev)
{
	return octeon_dev->octeon_id;
}

/** Get the number of Octeon devices currently in the system.
 *  This function is exported to other modules.
 *  @return  Count of octeon devices.
 */
uint32_t get_octeon_count(void)
{
	octeon_device_t * oct;

	oct = get_octeon_device(0);
	/* 93xx(96xx) supports only one device for now */
#ifdef USE_SINGLE_PF
	if (oct && (oct->chip_id == OCTEON_CN93XX_PF ||
		    oct->chip_id == OCTEON_CN98XX_PF))
		return 1;
	else
#endif
		return octeon_device_count;
}

uint32_t octeon_get_cycles_per_usec(octeon_device_t * oct)
{
	if (oct->chip_id == OCTEON_CN83XX_PF)
		return (CFG_GET_CORE_TICS_PER_US
			(CHIP_FIELD(oct, cn83xx_pf, conf)));

	return 0;
}

/** Get the octeon id assigned to the octeon device passed as argument.
 *  This function is exported to other modules.
 *  @param dev - octeon device pointer passed as a void *.
 *  @return octeon device id
 */
int get_octeon_device_id(void *dev)
{
	octeon_device_t *octeon_dev = (octeon_device_t *) dev;
	int i;

	for (i = 0; i < MAX_OCTEON_DEVICES; i++) {
		if (octeon_device[i] == octeon_dev)
			return (octeon_dev->octeon_id);
	}
	return -1;
}

/** Get the octeon device from the octeon id passed as argument.
 *  This function is exported to other modules.
 *  @param octeon_id - octeon device id.
 *  @return octeon device pointer as a void *.
 */
void *get_octeon_device_ptr(int octeon_id)
{
	return (void *)get_octeon_device(octeon_id);
}

unsigned long
octeon_map_single_buffer(int octeon_id, void *virt_addr, uint32_t size UNUSED,
			 int direction UNUSED)
{
	octeon_device_t *oct_dev = get_octeon_device(octeon_id);

	if (oct_dev == NULL)
		return 0UL;

	return octeon_pci_map_single(oct_dev->pci_dev, virt_addr, size,
				     direction);
}

void
octeon_unmap_single_buffer(int octeon_id, unsigned long dma_addr UNUSED,
			   uint32_t size UNUSED, int direction UNUSED)
{
	octeon_device_t *oct_dev = get_octeon_device(octeon_id);

	if (oct_dev == NULL)
		return;

	octeon_pci_unmap_single(oct_dev->pci_dev, dma_addr, size, direction);
}

unsigned long
octeon_map_page(int octeon_id, cavium_page_t * page UNUSED,
		unsigned long offset UNUSED, uint32_t size UNUSED,
		int direction UNUSED)
{
	octeon_device_t *oct_dev = get_octeon_device(octeon_id);

	if (oct_dev == NULL)
		return 0UL;

	return octeon_pci_map_page(oct_dev->pci_dev, page, offset, size,
				   direction);
}

void
octeon_unmap_page(int octeon_id, unsigned long dma_addr UNUSED,
		  uint32_t size UNUSED, int direction UNUSED)
{
	octeon_device_t *oct_dev = get_octeon_device(octeon_id);

	if (oct_dev == NULL)
		return;

	octeon_pci_unmap_page(oct_dev->pci_dev, dma_addr, size, direction);
}

extern int octeon_reset_recv_buf_size(octeon_device_t *, int, uint32_t);

int octeon_reset_oq_bufsize(int octeon_id, int q_no, int newsize)
{
	octeon_device_t *oct = get_octeon_device(octeon_id);

	if (oct == NULL)
		return -ENODEV;

	return octeon_reset_recv_buf_size(oct, q_no, newsize);
}

int octeon_is_active(int oct_id)
{
	octeon_device_t *oct = get_octeon_device(oct_id);

	if (oct == NULL)
		return -ENODEV;

	return (cavium_atomic_read(&oct->status) == OCT_DEV_RUNNING);
}

uint32_t octeon_active_dev_count(void)
{
	uint32_t i, cnt = 0;

	for (i = 0; i < octeon_device_count; i++)
		cnt += octeon_is_active(i);

	return cnt;
}

int octeon_all_devices_active(void)
{
	return (octeon_active_dev_count() == octeon_device_count);
}

/* $Id: octeon_device.c 165632 2017-08-31 09:12:31Z mchalla $ */
