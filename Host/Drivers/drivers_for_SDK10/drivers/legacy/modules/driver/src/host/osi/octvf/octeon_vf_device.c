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

char oct_dev_state_str[OCT_DEV_STATES + 1][32] = {
	"BEGIN", "PCI-MAP-DONE", "DISPATCH-INIT-DONE",
	"BUFPOOL-INIT-DONE", "RESPLIST-INIT-DONE", "HOST-READY",
	"CORE-READY", "INSTR-QUEUE-INIT-DONE", "DROQ-INIT-DONE",
	"RUNNING", "IN-RESET", "STOPPING",
	"INVALID"
};

char oct_dev_app_str[CVM_DRV_APP_COUNT + 1][32] =
    { "UNKNOWN", "BASE", "NIC", "UNKNOWN", "UNKNOWN", "UNKNOWN" };

octeon_device_t *octeon_device[MAX_OCTEON_DEVICES];
uint32_t octeon_device_count = 0;

octeon_module_handler_t octmodhandlers[OCTEON_MAX_MODULES];
cavium_spinlock_t octmodhandlers_lock;

octeon_core_setup_t core_setup[MAX_OCTEON_DEVICES];

oct_poll_fn_status_t oct_poll_module_starter(void *octptr, unsigned long arg);

extern int octeon_init_mbox_thread(octeon_device_t *);
extern int octeon_delete_mbox_thread(octeon_device_t *);
extern void octeon_mbox_write(octeon_device_t * oct, int qno, uint64_t data);

/*
   All Octeon devices use the default configuration in oct_config_data.h.
   To override the default:
   1.  The Octeon device Id must be known for customizing the octeon configuration.
   2.  Create a custom configuration based on CN73XX_VF or CN78XX_VF config structure
       (see octeon_config.h) in oct_config_data.h.
   3.  Modify the config type of the octeon device in the structure below to
       specify CN73XX_VF or CN78XX_VF configuration and replace the "custom" pointer
       to point to your custom configuration in oct_config_data.h
 */

static struct octeon_config_ptr {
	uint32_t conf_type;
	void *custom;
} oct_conf_info[MAX_OCTEON_DEVICES] = {
	{
	OCTEON_CONFIG_TYPE_DEFAULT, NULL}, {
	OCTEON_CONFIG_TYPE_DEFAULT, NULL}, {
	OCTEON_CONFIG_TYPE_DEFAULT, NULL}, {
	OCTEON_CONFIG_TYPE_DEFAULT, NULL}, {
	OCTEON_CONFIG_TYPE_DEFAULT, NULL}, {
	OCTEON_CONFIG_TYPE_DEFAULT, NULL}, {
	OCTEON_CONFIG_TYPE_DEFAULT, NULL}, {
	OCTEON_CONFIG_TYPE_DEFAULT, NULL}, {
	OCTEON_CONFIG_TYPE_DEFAULT, NULL}, {
	OCTEON_CONFIG_TYPE_DEFAULT, NULL}, {
	OCTEON_CONFIG_TYPE_DEFAULT, NULL}, {
	OCTEON_CONFIG_TYPE_DEFAULT, NULL}, {
	OCTEON_CONFIG_TYPE_DEFAULT, NULL}, {
	OCTEON_CONFIG_TYPE_DEFAULT, NULL}, {
	OCTEON_CONFIG_TYPE_DEFAULT, NULL}, {
	OCTEON_CONFIG_TYPE_DEFAULT, NULL}, {
	OCTEON_CONFIG_TYPE_DEFAULT, NULL}, {
	OCTEON_CONFIG_TYPE_DEFAULT, NULL}, {
	OCTEON_CONFIG_TYPE_DEFAULT, NULL}, {
	OCTEON_CONFIG_TYPE_DEFAULT, NULL}, {
	OCTEON_CONFIG_TYPE_DEFAULT, NULL}, {
	OCTEON_CONFIG_TYPE_DEFAULT, NULL}, {
	OCTEON_CONFIG_TYPE_DEFAULT, NULL}, {
	OCTEON_CONFIG_TYPE_DEFAULT, NULL}, {
	OCTEON_CONFIG_TYPE_DEFAULT, NULL}, {
	OCTEON_CONFIG_TYPE_DEFAULT, NULL}, {
	OCTEON_CONFIG_TYPE_DEFAULT, NULL}, {
	OCTEON_CONFIG_TYPE_DEFAULT, NULL}, {
	OCTEON_CONFIG_TYPE_DEFAULT, NULL}, {
	OCTEON_CONFIG_TYPE_DEFAULT, NULL}, {
	OCTEON_CONFIG_TYPE_DEFAULT, NULL}, {
	OCTEON_CONFIG_TYPE_DEFAULT, NULL}, {
	OCTEON_CONFIG_TYPE_DEFAULT, NULL}, {
	OCTEON_CONFIG_TYPE_DEFAULT, NULL}, {
	OCTEON_CONFIG_TYPE_DEFAULT, NULL}, {
	OCTEON_CONFIG_TYPE_DEFAULT, NULL}, {
	OCTEON_CONFIG_TYPE_DEFAULT, NULL}, {
	OCTEON_CONFIG_TYPE_DEFAULT, NULL}, {
	OCTEON_CONFIG_TYPE_DEFAULT, NULL}, {
	OCTEON_CONFIG_TYPE_DEFAULT, NULL}, {
	OCTEON_CONFIG_TYPE_DEFAULT, NULL}, {
	OCTEON_CONFIG_TYPE_DEFAULT, NULL}, {
	OCTEON_CONFIG_TYPE_DEFAULT, NULL}, {
	OCTEON_CONFIG_TYPE_DEFAULT, NULL}, {
	OCTEON_CONFIG_TYPE_DEFAULT, NULL}, {
	OCTEON_CONFIG_TYPE_DEFAULT, NULL}, {
	OCTEON_CONFIG_TYPE_DEFAULT, NULL}, {
	OCTEON_CONFIG_TYPE_DEFAULT, NULL}, {
	OCTEON_CONFIG_TYPE_DEFAULT, NULL}, {
	OCTEON_CONFIG_TYPE_DEFAULT, NULL}, {
	OCTEON_CONFIG_TYPE_DEFAULT, NULL}, {
	OCTEON_CONFIG_TYPE_DEFAULT, NULL}, {
	OCTEON_CONFIG_TYPE_DEFAULT, NULL}, {
	OCTEON_CONFIG_TYPE_DEFAULT, NULL}, {
	OCTEON_CONFIG_TYPE_DEFAULT, NULL}, {
	OCTEON_CONFIG_TYPE_DEFAULT, NULL}, {
	OCTEON_CONFIG_TYPE_DEFAULT, NULL}, {
	OCTEON_CONFIG_TYPE_DEFAULT, NULL}, {
	OCTEON_CONFIG_TYPE_DEFAULT, NULL}, {
	OCTEON_CONFIG_TYPE_DEFAULT, NULL}, {
	OCTEON_CONFIG_TYPE_DEFAULT, NULL}, {
	OCTEON_CONFIG_TYPE_DEFAULT, NULL}, {
	OCTEON_CONFIG_TYPE_DEFAULT, NULL}, {
	OCTEON_CONFIG_TYPE_DEFAULT, NULL}, {
	OCTEON_CONFIG_TYPE_DEFAULT, NULL}, {
	OCTEON_CONFIG_TYPE_DEFAULT, NULL}, {
	OCTEON_CONFIG_TYPE_DEFAULT, NULL}, {
	OCTEON_CONFIG_TYPE_DEFAULT, NULL}, {
	OCTEON_CONFIG_TYPE_DEFAULT, NULL}, {
	OCTEON_CONFIG_TYPE_DEFAULT, NULL}, {
	OCTEON_CONFIG_TYPE_DEFAULT, NULL}, {
	OCTEON_CONFIG_TYPE_DEFAULT, NULL}, {
	OCTEON_CONFIG_TYPE_DEFAULT, NULL}, {
	OCTEON_CONFIG_TYPE_DEFAULT, NULL}, {
	OCTEON_CONFIG_TYPE_DEFAULT, NULL}, {
	OCTEON_CONFIG_TYPE_DEFAULT, NULL}, {
	OCTEON_CONFIG_TYPE_DEFAULT, NULL}, {
	OCTEON_CONFIG_TYPE_DEFAULT, NULL}, {
	OCTEON_CONFIG_TYPE_DEFAULT, NULL}, {
	OCTEON_CONFIG_TYPE_DEFAULT, NULL}, {
	OCTEON_CONFIG_TYPE_DEFAULT, NULL}, {
	OCTEON_CONFIG_TYPE_DEFAULT, NULL}, {
	OCTEON_CONFIG_TYPE_DEFAULT, NULL}, {
	OCTEON_CONFIG_TYPE_DEFAULT, NULL}, {
	OCTEON_CONFIG_TYPE_DEFAULT, NULL}, {
	OCTEON_CONFIG_TYPE_DEFAULT, NULL}, {
	OCTEON_CONFIG_TYPE_DEFAULT, NULL}, {
	OCTEON_CONFIG_TYPE_DEFAULT, NULL}, {
	OCTEON_CONFIG_TYPE_DEFAULT, NULL}, {
	OCTEON_CONFIG_TYPE_DEFAULT, NULL}, {
	OCTEON_CONFIG_TYPE_DEFAULT, NULL}, {
	OCTEON_CONFIG_TYPE_DEFAULT, NULL}, {
	OCTEON_CONFIG_TYPE_DEFAULT, NULL}, {
	OCTEON_CONFIG_TYPE_DEFAULT, NULL}, {
	OCTEON_CONFIG_TYPE_DEFAULT, NULL}, {
	OCTEON_CONFIG_TYPE_DEFAULT, NULL}, {
	OCTEON_CONFIG_TYPE_DEFAULT, NULL}, {
	OCTEON_CONFIG_TYPE_DEFAULT, NULL}, {
	OCTEON_CONFIG_TYPE_DEFAULT, NULL}, {
	OCTEON_CONFIG_TYPE_DEFAULT, NULL}, {
	OCTEON_CONFIG_TYPE_DEFAULT, NULL}, {
	OCTEON_CONFIG_TYPE_DEFAULT, NULL}, {
	OCTEON_CONFIG_TYPE_DEFAULT, NULL}, {
	OCTEON_CONFIG_TYPE_DEFAULT, NULL}, {
	OCTEON_CONFIG_TYPE_DEFAULT, NULL}, {
	OCTEON_CONFIG_TYPE_DEFAULT, NULL}, {
	OCTEON_CONFIG_TYPE_DEFAULT, NULL}, {
	OCTEON_CONFIG_TYPE_DEFAULT, NULL}, {
	OCTEON_CONFIG_TYPE_DEFAULT, NULL}, {
	OCTEON_CONFIG_TYPE_DEFAULT, NULL}, {
	OCTEON_CONFIG_TYPE_DEFAULT, NULL}, {
	OCTEON_CONFIG_TYPE_DEFAULT, NULL}, {
	OCTEON_CONFIG_TYPE_DEFAULT, NULL}, {
	OCTEON_CONFIG_TYPE_DEFAULT, NULL}, {
	OCTEON_CONFIG_TYPE_DEFAULT, NULL}, {
	OCTEON_CONFIG_TYPE_DEFAULT, NULL}, {
	OCTEON_CONFIG_TYPE_DEFAULT, NULL}, {
	OCTEON_CONFIG_TYPE_DEFAULT, NULL}, {
	OCTEON_CONFIG_TYPE_DEFAULT, NULL}, {
	OCTEON_CONFIG_TYPE_DEFAULT, NULL}, {
	OCTEON_CONFIG_TYPE_DEFAULT, NULL}, {
	OCTEON_CONFIG_TYPE_DEFAULT, NULL}, {
	OCTEON_CONFIG_TYPE_DEFAULT, NULL}, {
	OCTEON_CONFIG_TYPE_DEFAULT, NULL}, {
	OCTEON_CONFIG_TYPE_DEFAULT, NULL}, {
	OCTEON_CONFIG_TYPE_DEFAULT, NULL}, {
	OCTEON_CONFIG_TYPE_DEFAULT, NULL}, {
OCTEON_CONFIG_TYPE_DEFAULT, NULL},};

void octeon_init_device_list(void)
{
	cavium_memset(octeon_device, 0, (sizeof(void *) * MAX_OCTEON_DEVICES));
}

static void *__retrieve_octeon_config_info(octeon_device_t * oct)
{
	int oct_id = oct->octeon_id;

	if (oct_conf_info[oct_id].conf_type != OCTEON_CONFIG_TYPE_DEFAULT) {

		if (((oct->chip_id == OCTEON_CN83XX_VF) ||
		     (oct->chip_id == OCTEON_CN93XX_VF) ||
		     (oct->chip_id == OCTEON_CN98XX_VF))
		    && (oct_conf_info[oct_id].conf_type ==
			OCTEON_CONFIG_TYPE_CUSTOM))
			return oct_conf_info[oct_id].custom;

		cavium_error
		    ("OCTEON[%d]: Incompatible config type (%d) for chip type %x\n",
		     oct_id, oct_conf_info[oct_id].conf_type, oct->chip_id);
		return NULL;
	}

	if (oct->chip_id == OCTEON_CN83XX_VF)
		return (void *)&default_cn83xx_vf_conf;
	else if (oct->chip_id == OCTEON_CN93XX_VF ||
		 oct->chip_id == OCTEON_CN98XX_VF)
		return (void *)&default_cn93xx_vf_conf;

	return NULL;
}

static int __verify_octeon_config_info(octeon_device_t * oct, void *conf)
{
	switch (oct->chip_id) {

	case OCTEON_CN83XX_VF:
		return validate_cn83xx_vf_config_info(conf);
	case OCTEON_CN93XX_VF:
	case OCTEON_CN98XX_VF:
		return validate_cn93xx_vf_config_info(conf);
	default:
		cavium_error("Chip config verification failed. Invalid chipid:%d\n",
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

	case OCTEON_CN83XX_VF:
		configsize = sizeof(octeon_cn83xx_vf_t);
		break;

	case OCTEON_CN93XX_VF:
		configsize = sizeof(octeon_cn93xx_vf_t);
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
	octeon_assign_vf_dev_name(oct);

	return oct;
}

int octeon_setup_io_queues(octeon_device_t * octeon_dev)
{
	int i, num_ioqs, retval = 0;

	num_ioqs = octeon_dev->rings_per_vf;

	/* set up DROQs. */
	for (i = 1; i < num_ioqs; i++) {
		if (octeon_dev->droq[i]) {
			cavium_print_msg
			    ("DROQ %d is already initialized. Skipping initialization.\n",
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
	for (i = 1; i < num_ioqs; i++) {
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
		ioq_vector->mbox = oct->mbox[i];
		ioq_vector->oct_dev = oct;

		ioq_vector->ioq_num = i;

	}

	printk("Allocated %d IOQ vectors\n", oct->num_oqs);
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
	int i, num_ioqs = 0;
	octeon_ioq_vector_t *ioq_vector;
	int cpu_num;

	if (oct->chip_id == OCTEON_CN83XX_VF)
		num_ioqs = oct->rings_per_vf;

	for (i = 0; i < num_ioqs; i++) {
		ioq_vector = oct->ioq_vector[i];

		/** Set the ioq_vector's cpu mask same as droq_thread's cpu mask */
		cpu_num = i % cavium_get_cpu_count();
		cpumask_set_cpu(cpu_num, &ioq_vector->affinity_mask);

		/* assign the cpu mask for the msix interrupt vector */
		irq_set_affinity_hint(oct->msix_entries[i].vector,
				      &(oct->ioq_vector[i]->affinity_mask));
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
	printk("Cleared %d IOQ vectors\n", oct->num_oqs);

	return 0;
}

int octeon_delete_ioq_vector(octeon_device_t * oct)
{
	int i;

	printk("Num Vectors: %d \n", oct->num_irqs);
	//for(i=0; i< oct->num_oqs;i++)
	for (i = 0; i < oct->num_irqs; i++) {
		cavium_memset(oct->ioq_vector[i], 0,
			      sizeof(octeon_ioq_vector_t));
		cavium_free_virt(oct->ioq_vector[i]);

		oct->ioq_vector[i] = NULL;
	}
	printk("Deleted %d IOQ vectors\n", oct->num_irqs);
	oct->num_irqs = 0;
	return 0;
}

int octeon_setup_instr_queues(octeon_device_t * oct)
{
	int i, num_iqs = 0, retval = 0;

	if (oct->chip_id == OCTEON_CN83XX_VF || oct->chip_id == OCTEON_CN93XX_VF)
		num_iqs = oct->rings_per_vf;

	oct->num_iqs = 0;

	for (i = 0; i < num_iqs; i++) {
		retval = octeon_setup_iq(oct, i, (void *)(long)i);
		if (retval) {
			cavium_print_msg
			    (" %s : Runtime IQ(TxQ) creation failed.\n",
			     __FUNCTION__);
			return 1;
		}

	}

	return 0;
}

int octeon_setup_output_queues(octeon_device_t * oct)
{
	int i, num_oqs = 0, retval = 0;

	if (oct->chip_id == OCTEON_CN83XX_VF || oct->chip_id == OCTEON_CN93XX_VF)
		num_oqs = oct->rings_per_vf;

	oct->num_oqs = 0;

	for (i = 0; i < num_oqs; i++) {
		retval = octeon_setup_droq(oct->octeon_id, i, NULL);
		if (retval) {
			cavium_print_msg
			    (" %s : Runtime DROQ(RxQ) creation failed.\n",
			     __FUNCTION__);
			return 1;
		}
	}

	return 0;
}

int octeon_setup_mbox(octeon_device_t * oct)
{
	int i = 0, num_ioqs = 0;

	if (!(oct->drv_flags & OCTEON_MBOX_CAPABLE))
		return 0;

	if (oct->chip_id == OCTEON_CN83XX_VF)
		num_ioqs = oct->rings_per_vf;
	else
		return 0;

	for (i = 0; i < num_ioqs; i++) {
		oct->mbox[i] = cavium_alloc_virt(sizeof(octeon_mbox_t));
		if (oct->mbox[i] == NULL)
			goto free_mbox;

		cavium_memset(oct->mbox[i], 0, sizeof(octeon_mbox_t));
		oct->fn_list.setup_mbox_regs(oct, i);
	}
#if 0
	//Mail Box Thread creation
	if (octeon_init_mbox_thread(oct)) {
		cavium_error("%s, Mailbox Thread Creation Failed\n",
			     __CVM_FUNCTION__);
		goto free_mbox;
	}
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

	if (oct->chip_id == OCTEON_CN83XX_VF)
		num_ioqs = oct->rings_per_vf;
	else
		return 0;
#if 0
	octeon_delete_mbox_thread(oct);
#endif

	for (i = 0; i < num_ioqs; i++) {
		cavium_memset(oct->mbox[i], 0, sizeof(octeon_mbox_t));
		cavium_free_virt(oct->mbox[i]);

		oct->mbox[i] = NULL;
	}
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

void octeon_set_io_queues_off(octeon_device_t * oct)
{
	uint64_t reg_val = 0ULL, q_no = 0;
	/* IOQs will already be in reset. */
	/* If RST bit is set, wait for QUITE bit to be set */
	/* Once Quite bit is set, clear the RST bit */

	if (oct->chip_id == OCTEON_CN83XX_VF) {
		for (q_no = 0; q_no < oct->rings_per_vf; q_no++) {
			octeon_write_csr64(oct,
					   CN83XX_VF_SDP_EPF_R_IN_ENABLE
					   (oct->epf_num, q_no), reg_val);

			octeon_write_csr64(oct,
					   CN83XX_VF_SDP_EPF_R_OUT_ENABLE
					   (oct->epf_num, q_no), reg_val);
		}
	}
}

/*
	octeon_reset_ioq: checks the ioq's reset state and brings out of reset
	Parameters:
	octeon_dev - octeon device struct pointer.
	ioq        - queue number    
*/
void octeon_reset_ioq(octeon_device_t * octeon_dev, int ioq)
{
	volatile uint64_t reg_val = 0ULL;

	if (octeon_dev->chip_id == OCTEON_CN83XX_VF) {
		/* wait for IDLE to set to 1 */
		do {
			reg_val = octeon_read_csr64(octeon_dev,
						    CN83XX_VF_SDP_EPF_R_IN_CONTROL
						    (octeon_dev->epf_num, ioq));
		} while (!(reg_val & CN83XX_R_IN_CTL_IDLE));

		do {
			reg_val = octeon_read_csr64(octeon_dev,
						    CN83XX_VF_SDP_EPF_R_OUT_CONTROL
						    (octeon_dev->epf_num, ioq));
		} while (!(reg_val & CN83XX_R_OUT_CTL_IDLE));

	}

}

void octeon_set_droq_pkt_op(octeon_device_t * oct, int q_no, int enable)
{

#if 0
	uint64_t reg = 0, reg_val = 0ULL;
	/* Disable the i/p and o/p queues for this Octeon. */
	if (oct->chip_id == OCTEON_CN83XX_VF) {

		if (enable)
			reg_val = 0x1ULL;
		octeon_write_csr64(oct,
				   CN83XX_VF_SDP_EPF_R_OUT_ENABLE(oct->epf_num,
								  q_no),
				   reg_val);
	}

	reg_val = octeon_read_csr(oct, reg);
	cavium_print(PRINT_DEBUG,
		     "set_droq_pkt_op:  reg_val: %016llx, q_no: %d, enable: %d\n",
		     reg_val, q_no, enable);

	if (enable)
		reg_val = reg_val | (1 << q_no);
	else 
		reg_val = reg_val & (~(1 << q_no));
	

	cavium_print(PRINT_DEBUG,
		     "set_droq_pkt_op: writing val: %016llx to register.\n",
		     reg_val);
	octeon_write_csr(oct, reg, reg_val);
#endif
}

int octeon_hot_reset(octeon_device_t * oct)
{
	int i, status;
	octeon_poll_ops_t poll_ops;

	cavium_print_msg("\n\n OCTEON[%d]: Starting Hot Reset.\n",
			 oct->octeon_id);

	status = (int)cavium_atomic_read(&oct->status);

	if (status < OCT_DEV_HOST_OK || status > OCT_DEV_IN_RESET) {
		cavium_error
		    ("OCTEON: Hot Reset received when device state is %s\n",
		     get_oct_state_string(&oct->status));
		cavium_error("OCTEON: Device state will remain at %s (0x%x)\n",
			     get_oct_state_string(&oct->status),
			     (int)cavium_atomic_read(&oct->status));
		return 1;
	}

	cavium_print_msg("OCTEON: Stopping modules.\n");

	/* Stop any driver modules that are running. Do this before sending the hot
	   reset command so that the modules get a chance to stop their traffic. */
	if ((oct->app_mode != CVM_DRV_INVALID_APP)
	    && (oct->app_mode != CVM_DRV_BASE_APP)) {
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
		    ("OCTEON: Modules stopped. Sending Reset command.\n");
		if (octeon_send_short_command(oct, HOT_RESET_OP, 0, NULL, 0)) {
			cavium_error("Failed to send HOT RESET instruction\n");
			cavium_error
			    ("OCTEON: Device state will remain at %s (0x%x)\n",
			     get_oct_state_string(&oct->status),
			     (int)cavium_atomic_read(&oct->status));
			return 1;
		} else {
			cavium_print_msg("OCTEON: HotReset command sent.\n");
		}
	}

	/* No more instructions will be forwarded. */
	cavium_atomic_set(&oct->status, OCT_DEV_IN_RESET);

	oct->app_mode = CVM_DRV_INVALID_APP;
	cavium_print_msg("OCTEON: Device state is now %s\n",
			 get_oct_state_string(&oct->status));

	/* Sleep a short while to allow for in-flight requests to be setup
	   correctly. No new requests would be allowed once the RESET state
	   is set above. */
	cavium_sleep_timeout(100);

	cavium_print_msg
	    ("OCTEON[%d]: In Reset: Waiting for pending requests to finish\n",
	     oct->octeon_id);

	if (wait_for_all_pending_requests(oct))
		goto hot_reset_failed;

	cavium_print_msg
	    ("OCTEON[%d]: In Reset: No pending requests. Checking Input Queues\n",
	     oct->octeon_id);

	if (wait_for_instr_fetch(oct)) {
		cavium_error
		    ("OCTEON[%d]: Input Queue not empty; Hot Reset Aborted\n",
		     oct->octeon_id);
		goto hot_reset_failed;
	}

	/* Disable the input and output queues now. No more packets will arrive
	   from Octeon, but we should wait for all packet processing to finish. */
	oct->fn_list.disable_io_queues(oct);

	cavium_print_msg
	    ("OCTEON[%d]: In Reset: Input & Output queues stopped\n",
	     oct->octeon_id);
	cavium_print_msg
	    ("OCTEON[%d]: In Reset: Waiting to finish packet processing on Output Queues\n",
	     oct->octeon_id);

	if (wait_for_oq_pkts(oct)) {
		cavium_error
		    ("OCTEON[%d]: Output Queues not empty; Hot Reset Aborted\n",
		     oct->octeon_id);
		goto hot_reset_failed;
	}

	cavium_print_msg
	    ("OCTEON[%d]: In Reset. No more packets pending in Output Queues\n",
	     oct->octeon_id);

	/* Reset is now complete in bringing the octeon device to its init state. */
	cavium_atomic_set(&oct->status, OCT_DEV_RESET_CLEANUP_DONE);

	oct->fn_list.soft_reset(oct);

	cavium_print_msg("OCTEON[%d]: Performing device initialization\n",
			 oct->octeon_id);

	for (i = 0; i < oct->num_iqs; i++) {
		octeon_instr_queue_t *iq = oct->instr_queue[i];

		iq->fill_cnt = 0;
		iq->host_write_index = 0;
		iq->octeon_read_index = 0;
		iq->flush_index = 0;
		iq->last_db_time = 0;
		cavium_atomic_set(&iq->instr_pending, 0);
	}

	for (i = 0; i < oct->num_oqs; i++) {
		octeon_droq_t *droq = oct->droq[i];

		octeon_droq_refill(oct, droq);
		droq->host_read_index = 0;
		droq->octeon_write_index = 0;
		droq->host_refill_index = 0;
		droq->refill_count = 0;
		cavium_atomic_set(&droq->pkts_pending, 0);
	}

	oct->fn_list.reinit_regs(oct);

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

	return 0;

hot_reset_failed:
	cavium_error
	    ("OCTEON[%d]: Device will remain in RESET state\n Try again!",
	     oct->octeon_id);
	return 1;
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
		    ("OCTEON[%d]: Found previously registered dispatch function for opcode: %x\n",
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

// *INDENT-OFF*
    if(octeon_dev->dispatch.count == 0) {
        cavium_spin_unlock_softirqrestore(&octeon_dev->dispatch.lock);
        cavium_error("OCTEON[%d]: No dispatch functions registered for this device\n",
            octeon_id);
        return 1;
    }

    if(octeon_dev->dispatch.dlist[idx].opcode == opcode) {
        cavium_print(PRINT_DEBUG,"--get_dispatch: found entry in main list\n");
        dispatch = &(octeon_dev->dispatch.dlist[idx].list);
        if(dispatch->le_next != dispatch)  {
            dispatch = dispatch->le_next;
            octeon_dev->dispatch.dlist[idx].opcode      =
                ((octeon_dispatch_t *)dispatch)->opcode;
            octeon_dev->dispatch.dlist[idx].dispatch_fn =
                ((octeon_dispatch_t *)dispatch)->dispatch_fn;
            octeon_dev->dispatch.dlist[idx].arg  =
                ((octeon_dispatch_t *)dispatch)->arg;
            cavium_list_del(dispatch);
            dfree = dispatch;
        }
        else  {
            octeon_dev->dispatch.dlist[idx].opcode      = 0;
            octeon_dev->dispatch.dlist[idx].dispatch_fn = NULL;
            octeon_dev->dispatch.dlist[idx].arg         = NULL;
        }
    }
    else  {
        retval = 1;
        cavium_list_for_each_safe(dispatch, tmp2, &(octeon_dev->dispatch.dlist[idx].list)) {
            if(((octeon_dispatch_t *)dispatch)->opcode == opcode)  {
                cavium_list_del(dispatch);
                dfree = dispatch;
                retval = 0;
            }
        }
    }
// *INDENT-ON*

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
	cavium_print_msg
	    ("OCTEON[%d]: Received active indication from firmware\n",
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

static int start_base = 0;
void start_base_handler(void)
{
	start_base = 1;
}

extern int octeon_register_base_handler(void);

oct_poll_fn_status_t
oct_poll_module_starter(void *octptr, unsigned long arg UNUSED)
{
	octeon_device_t *oct = (octeon_device_t *) octptr;

#if 0
	if (cavium_atomic_read(&oct->status) == OCT_DEV_RUNNING) {
		return OCT_POLL_FN_FINISHED;
	}

	/* If the status of the device is CORE_OK, the core
	   application has reported its application type. Call
	   any registered handlers now and move to the RUNNING
	   state. */
	if (cavium_atomic_read(&oct->status) != OCT_DEV_CORE_OK)
		return OCT_POLL_FN_CONTINUE;
#endif
	if(start_base) {
		oct->app_mode = CVM_DRV_BASE_APP;
		cavium_atomic_set(&oct->status, OCT_DEV_CORE_OK);
		octeon_register_base_handler();
		return OCT_POLL_FN_FINISHED;
	} else {
		return OCT_POLL_FN_CONTINUE;
	}
	//cavium_atomic_set(&oct->status,OCT_DEV_RUNNING);

	/* For NIC mode, start_module is called from nic_module_handler */
	if (oct->app_mode == CVM_DRV_NIC_APP)
		return OCT_POLL_FN_CONTINUE;

	if (oct->app_mode) {
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
	if (oct->chip_id == OCTEON_CN83XX_VF)
		default_oct_conf =
		    (octeon_config_t *) (CHIP_FIELD(oct, cn83xx_vf, conf));

	return default_oct_conf;
}

#if 0
int dump_hostfw_config(octeon_config_t * temp_oct_conf)
{
	int i = 0;
	cavium_print(PRINT_DEBUG, "\nIQ Configuration:\n");
	cavium_print(PRINT_DEBUG, "-------------------\n");
	cavium_print(PRINT_DEBUG,
		     "max IQ:%d,	max base iq: %d, pending_list size: %d, \n",
		     CFG_GET_IQ_MAX_Q(&temp_oct_conf),
		     CFG_GET_IQ_MAX_BASE_Q(&temp_oct_conf),
		     CFG_GET_IQ_PENDING_LIST_SIZE(&temp_oct_conf));
	cavium_print(PRINT_DEBUG,
		     "num_desc:%d,	instr type: %d, db_min: %d, db_timeout: %d\n",
		     CFG_GET_IQ_NUM_DESC(&temp_oct_conf),
		     CFG_GET_IQ_INSTR_TYPE(&temp_oct_conf),
		     CFG_GET_IQ_DB_MIN(&temp_oct_conf),
		     CFG_GET_IQ_DB_TIMEOUT(&temp_oct_conf));

	cavium_print(PRINT_DEBUG, "\nOQ Configuration:\n");
	cavium_print(PRINT_DEBUG, "-------------------\n");
	cavium_print(PRINT_DEBUG,
		     "max OQ: %d, max base OQ: %d, num_desc: %d, \n",
		     CFG_GET_OQ_MAX_Q(&temp_oct_conf),
		     CFG_GET_OQ_MAX_BASE_Q(&temp_oct_conf),
		     CFG_GET_OQ_NUM_DESC(&temp_oct_conf));
	cavium_print(PRINT_DEBUG,
		     "info_ptr: %d, buf-size: %d, pkts_per_intr: %d, \n",
		     CFG_GET_OQ_INFO_PTR(&temp_oct_conf),
		     CFG_GET_OQ_BUF_SIZE(&temp_oct_conf),
		     CFG_GET_OQ_PKTS_PER_INTR(&temp_oct_conf));
	cavium_print(PRINT_DEBUG,
		     "refill_threshold: %d, oq_intr_pkt: %d, oq_intr_time: %d, \n",
		     CFG_GET_OQ_REFILL_THRESHOLD(&temp_oct_conf),
		     CFG_GET_OQ_INTR_PKT(&temp_oct_conf),
		     CFG_GET_OQ_INTR_TIME(&temp_oct_conf));

	cavium_print(PRINT_DEBUG, "\nPKO Configuration:\n");
	cavium_print(PRINT_DEBUG, "-------------------\n");
	cavium_print(PRINT_DEBUG, "IF 0: cmdq:%d, links: %d\n",
		     CFG_GET_PKO_CMDQ_PER_IF(&temp_oct_conf, 0),
		     CFG_GET_PKO_LINK_PER_IF(&temp_oct_conf, 0));
	cavium_print(PRINT_DEBUG, "IF 1: cmdq:%d, links: %d\n",
		     CFG_GET_PKO_CMDQ_PER_IF(&temp_oct_conf, 1),
		     CFG_GET_PKO_LINK_PER_IF(&temp_oct_conf, 1));
	cavium_print(PRINT_DEBUG, "IF 2: cmdq:%d, links: %d\n",
		     CFG_GET_PKO_CMDQ_PER_IF(&temp_oct_conf, 2),
		     CFG_GET_PKO_LINK_PER_IF(&temp_oct_conf, 2));
	cavium_print(PRINT_DEBUG, "cmdq per pci port: %d\n",
		     CFG_GET_PKO_CMDQ_PER_PCI_PORT(&temp_oct_conf, 0));

	cavium_print(PRINT_DEBUG, "\nFPA Configuration:\n");
	cavium_print(PRINT_DEBUG, "-------------------\n");
	cavium_print(PRINT_DEBUG, "Pool-0: size:%d count: %d\n",
		     CFG_GET_POOL_BUF_SIZE(&temp_oct_conf, 0),
		     CFG_GET_POOL_BUF_CNT(&temp_oct_conf, 0));
	cavium_print(PRINT_DEBUG, "Pool-1: size:%d count: %d\n",
		     CFG_GET_POOL_BUF_SIZE(&temp_oct_conf, 1),
		     CFG_GET_POOL_BUF_CNT(&temp_oct_conf, 1));
	cavium_print(PRINT_DEBUG, "Pool-2: size:%d count: %d\n",
		     CFG_GET_POOL_BUF_SIZE(&temp_oct_conf, 2),
		     CFG_GET_POOL_BUF_CNT(&temp_oct_conf, 2));
	cavium_print(PRINT_DEBUG, "Pool-3: size:%d count: %d\n",
		     CFG_GET_POOL_BUF_SIZE(&temp_oct_conf, 3),
		     CFG_GET_POOL_BUF_CNT(&temp_oct_conf, 3));

	cavium_print(PRINT_DEBUG, "\nPORT Configuration:\n");
	cavium_print(PRINT_DEBUG, "-------------------\n");
	for (i = 0; i < MAX_OCTEON_NICIF; i++)
		cavium_print(PRINT_DEBUG,
			     "NIC IF: starting IQ:%d	Starting OQ:%d\n",
			     CFG_GET_PORTS_IQ(&temp_oct_conf, i, 0),
			     CFG_GET_PORTS_OQ(&temp_oct_conf, i, 0));

	cavium_print(PRINT_DEBUG, "\nMISC Configuration:\n");
	cavium_print(PRINT_DEBUG, "-------------------\n");
	cavium_print(PRINT_DEBUG,
		     "mem_size: %d, core cnt:%d, ctrlq_num: %d flags: %d, crc: %d\n",
		     CFG_GET_MEM_SIZE(&temp_oct_conf),
		     CFG_GET_CORE_CNT(&temp_oct_conf),
		     CFG_GET_CTRL_Q_NO(&temp_oct_conf),
		     CFG_GET_FLAGS(&temp_oct_conf),
		     CFG_GET_CRC(&temp_oct_conf));
	cavium_print(PRINT_DEBUG, "Host Link_query_interval : %d\n",
		     CFG_GET_HOST_LINK_QUERY_INTERVAL(&temp_oct_conf));
	cavium_print(PRINT_DEBUG, "Octeon Link_query_interval : %d\n",
		     CFG_GET_OCT_LINK_QUERY_INTERVAL(&temp_oct_conf));

	return 0;
}
#endif

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

		cavium_print_msg("OCTEON: Found handler for app_type: %s\n",
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
			cavium_error
			    ("OCTEON: Module Handler exists for application type 0x%x\n",
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

	//if (handler->app_type == CVM_DRV_BASE_APP)
	//	return retval;

	/* Call the start method for all existing octeon devices. */
	for (octidx = 0; octidx < MAX_OCTEON_DEVICES; octidx++) {
		octeon_device_t *oct_dev = octeon_device[octidx];

		if (oct_dev == NULL)
			continue;

#ifdef  ETHERPCI
		oct_dev->app_mode = CVM_DRV_NIC_APP;	// Emulate NIC PCI Device
		cavium_atomic_set(&oct_dev->status, OCT_DEV_RUNNING);
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
	return octeon_device_count;
}

uint32_t octeon_get_cycles_per_usec(octeon_device_t * oct)
{
	return (CFG_GET_CORE_TICS_PER_US(CHIP_FIELD(oct, cn83xx_vf, conf)));
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

int oct_init_base_module(int octeon_id, void *octeon_dev)
{
	octeon_device_t *oct = (octeon_device_t *) octeon_dev;
	int j = 0;

	if (octeon_setup_instr_queues(oct)) {
		cavium_error
		    ("OCTEON[%d]: Instruction queue initialization failed\n",
		     octeon_id);
		/* On error, release any previously allocated queues */
		for (j = 0; j < oct->num_iqs; j++)
			octeon_delete_instr_queue(oct, j);
		goto init_fail;
	}
	cavium_atomic_set(&oct->status, OCT_DEV_INSTR_QUEUE_INIT_DONE);

	if (octeon_setup_output_queues(oct)) {
		cavium_error("OCTEON[%d]: Output queue initialization failed\n",
			     octeon_id);
		/* Release any previously allocated queues */
		for (j = 0; j < oct->num_oqs; j++)
			octeon_delete_droq(oct, j);
		goto init_fail;
	}

	cavium_atomic_set(&oct->status, OCT_DEV_DROQ_INIT_DONE);

	if (octeon_allocate_ioq_vector(octeon_dev)) {
		cavium_error("OCTEON[%d]: IOQ vector allocation failed\n",
			     octeon_id);
		goto init_fail;
	}

	/* Setup the interrupt handler and record the INT SUM register address */
	if (octeon_enable_msix_interrupts(octeon_dev)) {
		cavium_error("OCTEON[%d]: Setup MSI-X interrupts failed\n",
			     octeon_id);
		octeon_delete_ioq_vector(octeon_dev);

		goto init_fail;
	}

	octeon_setup_irq_affinity(oct);

	/* Enable Octeon device interrupts */
	oct->fn_list.enable_interrupt(oct->chip, OCTEON_ALL_INTR);

	/* Enable the input and output queues for this Octeon device */
	oct->fn_list.enable_io_queues(oct);

        /* dbell needs to be programmed after enabling OQ. */
	for (j = 0; j < oct->num_oqs; j++) {
		OCTEON_WRITE32(oct->droq[j]->pkts_credit_reg,
			oct->droq[j]->max_count);
	}
	cavium_atomic_set(&oct->status, OCT_DEV_RUNNING);

	if (octeon_send_short_command
	    (octeon_dev, DEVICE_START_OP, (DEVICE_PKO), NULL, 0))
		cavium_print_msg("COMMAND SEND FAILED>>> AGAIN\n");

	return 0;
init_fail:
	/* send a error msg to prompt */
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

	switch (cavium_atomic_read(&oct_dev->status)) {
	case OCT_DEV_RUNNING:

		while (attempts--
		       && octeon_send_short_command(oct_dev, DEVICE_STOP_OP,
						    (DEVICE_PKO), NULL, 0)) ;

		cavium_atomic_set(&oct_dev->status, OCT_DEV_CORE_OK);

		if (wait_for_all_pending_requests(oct_dev)) {
			cavium_error
			    ("OCTEON[%d]: There were pending requests\n",
			     oct_dev->octeon_id);
		}

		if (wait_for_instr_fetch(oct_dev)) {
			cavium_error
			    ("OCTEON[%d]: IQ had pending instructions\n",
			     oct_dev->octeon_id);
		}

		/* Disable the input and output queues now. No more packets will
		   arrive from Octeon, but we should wait for all packet processing
		   to finish. */
		oct_dev->fn_list.disable_io_queues(oct_dev);

		if (wait_for_oq_pkts(oct_dev)) {
			cavium_error("OCTEON[%d]: OQ had pending packets\n",
				     oct_dev->octeon_id);
		}

		if (oct_dev->msix_on) {
			octeon_clear_irq_affinity(oct_dev);
			octeon_disable_msix_interrupts(oct_dev);
			octeon_delete_ioq_vector(oct_dev);
		}
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

	case OCT_DEV_INSTR_QUEUE_INIT_DONE:

		for (i = 0; i < oct_dev->num_iqs; i++) {
			octeon_delete_instr_queue(oct_dev, i);
		}
		oct_dev->num_iqs = 0;

		cavium_print_msg("OCTEON[%d]: IQs deleted.\n",
				 oct_dev->octeon_id);

	}
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

int octeon_core_cfg_callback(void *octeon_dev, unsigned long arg)
{
	octeon_device_t *oct = (octeon_device_t *) octeon_dev;
	static octeon_config_t *default_oct_conf = NULL;
	char app_name[16];

	default_oct_conf = octeon_get_conf(oct);
	oct->app_mode = CFG_GET_APP_MODE(default_oct_conf);
	oct->pkind = CFG_GET_DPI_PKIND(default_oct_conf);

	cavium_strncpy(app_name, sizeof(app_name),
		       get_oct_app_string(oct->app_mode), sizeof(app_name) - 1);
	cavium_print_msg("Received app type from firmware: %s\n", app_name);
	cavium_print_msg("Received Pkind for DPI: 0x%x\n", oct->pkind);
	cavium_print_msg("Received coprocessor clk: 0x%x\n",
			 CFG_GET_COPROC_TICS_PER_US(default_oct_conf));
	cavium_print_msg
	    ("Received core active indication from Physical Function\n");

//      if(oct->app_mode == CVM_DRV_BASE_APP)
//              octeon_register_base_handler(); 

	return 0;
}

int octeon_request_core_config(octeon_device_t * octeon_dev)
{
	oct_mbox_cmd_t mbox_cmd_queue;
	octeon_config_t *default_oct_conf;

	default_oct_conf = octeon_get_conf(octeon_dev);

	/** Sending VF_ACTIVE indication to the PF driver*/
	mbox_cmd_queue.fn = NULL;
	mbox_cmd_queue.fn_arg = 0UL;
	mbox_cmd_queue.cmd = OCTEON_VF_ACTIVE;
	mbox_cmd_queue.data = NULL;
	mbox_cmd_queue.total_len = 0;
	mbox_cmd_queue.recv_len = 0;
	mbox_cmd_queue.dir = MBOX_DATA_NONE;
	mbox_cmd_queue.qno = 0;

	octeon_mbox_add_to_queue(octeon_dev->octeon_id, &mbox_cmd_queue);
#if 1
	/** Sending core config request to the pf driver. */
	mbox_cmd_queue.fn = octeon_core_cfg_callback;
	mbox_cmd_queue.fn_arg = 0UL;
	mbox_cmd_queue.cmd = OCTEON_CORE_CONFIG;
	mbox_cmd_queue.data = (uint64_t *) & default_oct_conf->core_cfg;
	mbox_cmd_queue.total_len = sizeof(octeon_core_config_t);
	mbox_cmd_queue.recv_len = 0;
	mbox_cmd_queue.dir = MBOX_DATA_GET;
	mbox_cmd_queue.qno = 0;

	octeon_mbox_add_to_queue(octeon_dev->octeon_id, &mbox_cmd_queue);
#endif
	return 0;
}

oct_poll_fn_status_t
octeon_pfvf_handshake(void *octptr, unsigned long arg UNUSED)
{
	octeon_device_t *oct = (octeon_device_t *) octptr;
	oct_mbox_cmd_t mbox_cmd;
	octeon_config_t *default_oct_conf;
	uint64_t data = 0, ret;
	char app_name[16];

	default_oct_conf = octeon_get_conf(oct);

	switch (cavium_atomic_read(&oct->pfvf_hs_state)) {
	case PFVF_HS_INIT:
		{
			/** Sending VF_ACTIVE indication to the PF driver*/
			mbox_cmd.fn = NULL;
			mbox_cmd.fn_arg = 0UL;
			mbox_cmd.cmd = OCTEON_VF_ACTIVE;
			mbox_cmd.data = NULL;
			mbox_cmd.total_len = 0;
			mbox_cmd.recv_len = 0;
			mbox_cmd.dir = MBOX_DATA_NONE;
			mbox_cmd.qno = 0;

			ret = octeon_mbox_send_cmd(oct, &mbox_cmd);

			cavium_atomic_set(&oct->pfvf_hs_state,
					  PFVF_HS_WAIT_CORE_CFG);
			//cavium_print_msg(" VF SENT ACTVIE CMD\n");
		}
		break;

	case PFVF_HS_WAIT_CORE_CFG:
		{
			if (OCTEON_READ64(oct->mbox[0]->mbox_write_reg) ==
			    OCTEON_PFVFSIG) {

				data =
				    OCTEON_READ64(oct->mbox[0]->mbox_read_reg);
				cavium_memcpy(&default_oct_conf->core_cfg,
					      &data, sizeof(data));

				oct->app_mode =
				    CFG_GET_APP_MODE(default_oct_conf);
				oct->pkind =
				    CFG_GET_DPI_PKIND(default_oct_conf);

				cavium_strncpy(app_name, sizeof(app_name),
					       get_oct_app_string
					       (oct->app_mode),
					       sizeof(app_name) - 1);
				cavium_print_msg
				    ("Received app type from PF: %s\n",
				     app_name);
				cavium_print_msg
				    ("Received Pkind for DPI: 0x%x\n",
				     oct->pkind);
				cavium_print
				    (PRINT_DEBUG,
				     "Received coprocessor clk: 0x%x\n",
				     CFG_GET_COPROC_TICS_PER_US
				     (default_oct_conf));
				cavium_print_msg
				    ("Received core active indication from Physical Function\n");

				//cavium_print_msg(" VF device num::%d core cfg val:::%llx\n",oct->octeon_id, data);

				cavium_atomic_set(&oct->pfvf_hs_state,
						  PFVF_HS_DONE);

			}

		}
		break;

		/* Now, we are done with handshake. So unregister this poll thread */
	case PFVF_HS_DONE:
		cavium_atomic_set(&oct->pfvf_hs_state, PFVF_HS_INIT);

		cavium_print_msg(" PF-VF handshake done.\n");

		cavium_atomic_set(&oct->status, OCT_DEV_CORE_OK);

		if (oct->app_mode == CVM_DRV_BASE_APP)
			octeon_register_base_handler();

		return OCT_POLL_FN_FINISHED;
	}
	return OCT_POLL_FN_CONTINUE;

}
