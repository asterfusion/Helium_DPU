/* Copyright (c) 2020 Marvell.
 * SPDX-License-Identifier: GPL-2.0
 */

#include "octeon_mailbox.h"
#include "octeon_config.h"
#include "octeon_macros.h"

//Max cmds that can be posted to mbox cmd queue
#define MAX_MBOX_CMDS	100

/**
 * octeon_setup_mbox_cmd_queue: - 
 * @param oct: Pointer Octeon Device
 *
 * Allocates and Initalizes mbox cmd queue. 
 */
static int octeon_setup_mbox_cmd_queue(octeon_device_t * oct)
{
	int size = (MAX_MBOX_CMDS * sizeof(oct_mbox_cmd_t));

	oct->mbox_cmd_queue = cavium_alloc_virt(size);
	if (oct->mbox_cmd_queue == NULL)
		return -ENOMEM;

	cavium_memset(oct->mbox_cmd_queue, 0, size);
	cavium_spin_lock_init(&oct->mbox_lock);

	return 0;
}

/**
 * octeon_delete_mbox_cmd_queue:
 * @param oct: Pointer Octeon Device
 *
 * Frees the memory allocated for the cmd queue
 */

static void octeon_delete_mbox_cmd_queue(octeon_device_t * oct)
{
	cavium_free_virt(oct->mbox_cmd_queue);
	oct->mbox_cmd_queue = NULL;
}

/**
 * octeon_delete_mbox_thread:
 * @param oct: Pointer Octeon Device
 *
 * Deletes the mailbox thread
 */
int octeon_delete_mbox_thread(octeon_device_t * oct)
{
	oct->mbox_stop_thread = 1;

	//Wake up the mailbox thread before delete
	oct->mbox_wait_cond = 1;
	cavium_wakeup(&oct->mbox_wc);
	cavium_mdelay(100);

	octeon_delete_mbox_cmd_queue(oct);

	if (CVM_KTHREAD_EXISTS(&oct->mbox_id)) {
		cavium_kthread_destroy(&oct->mbox_id);
	}

	return 0;
}

/**
 * octeon_mbox_add_to_queue:
 * @param oct_id: Pointer Octeon Device
 * @param cmd: cmd to add to the mbox queue
 *
 * API to add the cmd to mbox cmd queue
 */
int octeon_mbox_add_to_queue(int oct_id, oct_mbox_cmd_t * cmd)
{
	int i = 0;
	oct_mbox_cmd_t *n, *mbox_cmd_queue;
	octeon_device_t *oct = get_octeon_device(oct_id);

	if (oct == NULL)
		return -ENODEV;

	if (cmd == NULL)
		return -EINVAL;

	mbox_cmd_queue = (oct_mbox_cmd_t *) oct->mbox_cmd_queue;

	cavium_spin_lock(&oct->mbox_lock);

	for (i = 0; i < MAX_MBOX_CMDS; i++) {
		if (mbox_cmd_queue[i].state == MBOX_QIDX_UNUSED)
			break;
	}

	if (i == MAX_MBOX_CMDS) {
		cavium_spin_unlock(&oct->mbox_lock);
		return -ENOMEM;
	}

	n = &mbox_cmd_queue[i];
	cavium_memset(n, 0, sizeof(oct_mbox_cmd_t));
	cavium_memcpy(n, cmd, sizeof(oct_mbox_cmd_t));

	n->state = MBOX_QIDX_USED;

	cavium_spin_unlock(&oct->mbox_lock);

	return 0;
}

/**
 * octeon_mbox_read:
 * @param oct: Pointer Octeon Device
 * @param qno: Queue number which has mbox the data
 *
 * Reads the 8-bytes of data from the mbox register
 * Writes back the acknowldgement inidcating completion of read
 */
static uint64_t octeon_mbox_read(octeon_device_t * oct, int qno)
{
	uint64_t val = 0;
	octeon_mbox_t *mbox = oct->mbox[qno];

	val = OCTEON_READ64(mbox->mbox_read_reg);
	//OCTEON_WRITE64(mbox->mbox_read_reg, OCTEON_PFVFACK);

	return val;
}

/**
 * octeon_mbox_write:
 * @param oct: Pointer Octeon Device
 * @param qno: Queue number to which data has to write
 * @param data: Data to send to mbox
 *
 * Writes 8-bytes of data to mbox register
 * Waits for the read completion acknowldgement
 */
static void octeon_mbox_write(octeon_device_t * oct, int qno, uint64_t data)
{
	octeon_mbox_t *mbox = oct->mbox[qno];

	OCTEON_WRITE64(mbox->mbox_write_reg, data);
	OCTEON_WRITE64(mbox->mbox_read_reg, OCTEON_PFVFSIG);
#if 0
	while (OCTEON_READ64(mbox->mbox_write_reg) != OCTEON_PFVFACK) {

		cavium_schedule();
	}
#endif
}

/**
 * octeon_mbox_send_cmd:
 * @param oct: Pointer Octeon Device
 * @param cmd: Cmd to send to mailbox.
 *
 * Populates the queue specific mbox structure
 * with cmd information.
 * Write the cmd to mbox register
 */
int octeon_mbox_send_cmd(octeon_device_t * oct, oct_mbox_cmd_t * cmd)
{
	octeon_mbox_t *mbox = oct->mbox[cmd->qno];

//      if(mbox->state == OCT_MBOX_STATE_IDLE) {
//              mbox->state = OCT_MBOX_STATE_BUSY;
	mbox->mbox_data.cmd = cmd->cmd | cmd->dir;
	mbox->mbox_data.total_len = cmd->total_len;
	mbox->mbox_data.recv_len = cmd->recv_len;
	mbox->mbox_data.data = cmd->data;

	octeon_mbox_write(oct, cmd->qno, mbox->mbox_data.cmd);

	return OCT_MBOX_CMD_DONE;
//      }
//      return OCT_MBOX_CMD_BUSY;
}

/**
 * octeon_mbox_send_data:
 * @param oct: Pointer Octeon Device
 * @param qno: Queue number of mbox to which the data has to send.
 *
 * Write the data to mbox register in chunks of 8-bytes
 */
static int octeon_mbox_send_data(octeon_device_t * oct, uint32_t qno)
{
	int i = 0;
	octeon_mbox_t *mbox = oct->mbox[qno];
	octeon_mbox_data_t *mbox_data = &mbox->mbox_data;

	for (i = 0; i < mbox_data->total_len; i += 8) {
		octeon_mbox_write(oct, qno, *(mbox_data->data));
		mbox_data->data++;

	}
	mbox->state = OCT_MBOX_STATE_IDLE;
	return 0;
}

/**
 * octeon_mbox_get_data:
 * @param oct: Pointer Octeon Device
 * @param qno: Queue number of mbox which expects data
 *
 * Check if the expected data is received
 * if expected data is received, change the mbox state to idle
 */
static int octeon_mbox_get_data(octeon_device_t * oct, uint32_t qno)
{
	octeon_mbox_t *mbox = oct->mbox[qno];
	octeon_mbox_data_t *mbox_data = &mbox->mbox_data;

	if (mbox_data->total_len == mbox_data->recv_len) {
		mbox->state = OCT_MBOX_STATE_IDLE;
		cavium_print_msg(" VF: mbox state again idle::\n");
		return OCT_MBOX_CMD_DONE;
	}
	cavium_print_msg(" VF: mbox state busy::\n");
	return OCT_MBOX_CMD_BUSY;
}

/**
 * octeon_mbox_read_data:
 * @param oct: Pointer Octeon Device
 * @param qno; Queue number of mbox which received the data
 *
 * Reads the data from mbox and stores it in mbox data of that queue.
 */
static int octeon_mbox_read_data(octeon_device_t * oct, uint32_t qno)
{
	uint64_t data;
	int pending_bytes = 0;
	octeon_mbox_data_t *mbox_data = &oct->mbox[qno]->mbox_data;

	data = octeon_mbox_read(oct, qno);
	pending_bytes = mbox_data->total_len - mbox_data->recv_len;

	cavium_print_msg(" total_len :::%d recev_len%d\n", mbox_data->total_len,
			 mbox_data->recv_len);

	//Read in chunk of 8 bytes.
	if (pending_bytes > 8) {
		*mbox_data->data++ = data;
		mbox_data->recv_len += 8;
		pending_bytes -= 8;
	}			//Read data byte by byte, when the len is less than 8 bytes.
	else {
		int i = 0;
		uint8_t *tmp_data = (uint8_t *) mbox_data->data;
		uint8_t *tmp = (uint8_t *) & data;

		/* Need to check the byte ordering of data. */
		for (i = 0; i < pending_bytes; i++)
			*tmp_data++ = *tmp++;

		mbox_data->recv_len += pending_bytes;
		pending_bytes = 0;
	}
	cavium_print_msg(" pending byte are ::::%d\n", pending_bytes);
	return pending_bytes;
}

/**
 * octeon_mbox_process_cmd:
 * @param oct: Pointer Octeon Device
 * @param qno: Queue number of mbox which received the cmd
 *
 * Process the cmd received in mbox
 */
static int octeon_mbox_process_cmd(octeon_device_t * oct, uint32_t qno)
{
	uint32_t cmd;
	uint64_t data;
	octeon_mbox_t *mbox = oct->mbox[qno];

	data = octeon_mbox_read(oct, qno);
	cmd = data & ~0xffff;

	switch (cmd) {

	case OCTEON_VF_ACTIVE:
		{
			octeon_core_config_t core_cfg;
			octeon_config_t *oct_conf = octeon_get_conf(oct);
			octeon_mbox_data_t *mbox_data = &mbox->mbox_data;

			if (oct_conf == NULL)
				return 0;

			cavium_memcpy(&core_cfg, &oct_conf->core_cfg,
				      sizeof(octeon_core_config_t));

			/* config info structure is common for both the PFs, while passing config info 
			 * to VFs, send proper PF pkind values*/
			core_cfg.dpi_pkind = oct->pkind;

			mbox_data->cmd = cmd;
			mbox_data->total_len = sizeof(octeon_core_config_t);
			mbox_data->recv_len = 0;
			mbox_data->data = (uint64_t *) & core_cfg;
			// Sending core cofig info to the corresponding active VF. 
			octeon_mbox_send_data(oct, qno);

			mbox->state = OCT_MBOX_STATE_IDLE;
		}
		break;
		// Not in use currently....
	case OCTEON_CORE_CONFIG:
		{
			octeon_config_t *oct_conf = octeon_get_conf(oct);
			octeon_mbox_data_t *mbox_data = &mbox->mbox_data;

			mbox_data->cmd = cmd;
			mbox_data->total_len = sizeof(octeon_core_config_t);
			mbox_data->recv_len = 0;
			mbox_data->data = (uint64_t *) & oct_conf->core_cfg;
			octeon_mbox_send_data(oct, qno);
		}
		break;
	}
	return 0;
}

/**
 *octeon_mbox_process_interrupt:
 * @param oct: Pointer Octeon Device
 * @param qno: Queue number which received the mbox interrupt.
 *
 * Process the received mbox interrupt.
 */
static int octeon_mbox_process_interrupt(octeon_device_t * oct, int qno)
{
	octeon_mbox_t *mbox = oct->mbox[qno];

	if (mbox->state == OCT_MBOX_STATE_IDLE) {
		mbox->state = OCT_MBOX_STATE_BUSY;
		octeon_mbox_process_cmd(oct, qno);
	} else if (mbox->state == OCT_MBOX_STATE_BUSY) {
		octeon_mbox_read_data(oct, qno);

	}
	return 0;
}

/**
 * oct_mbox_process_cmd_queue:
 * @param oct: Pointer Octeon Device
 *
 * process the cmds from the mbox cmd queue
 */
static void oct_mbox_process_cmd_queue(octeon_device_t * oct)
{
	int ret = 0, loop_count = MAX_MBOX_CMDS;
	static int running_index = 0;
	oct_mbox_cmd_t *cmd, *mbox_cmd_queue;

	mbox_cmd_queue = oct->mbox_cmd_queue;

	while (loop_count--) {

		cavium_spin_lock(&oct->mbox_lock);
		cmd = &mbox_cmd_queue[running_index];

		if (cmd->state == MBOX_QIDX_UNUSED) {
			running_index++;
			if (running_index >= MAX_MBOX_CMDS)
				running_index = 0;

			cavium_spin_unlock(&oct->mbox_lock);

			continue;
		}

		cavium_spin_unlock(&oct->mbox_lock);

		//Only req-response mode is supported.

		//1. Send the cmd. 
		ret = octeon_mbox_send_cmd(oct, cmd);

		//2. Check for expected data to be received
		ret = octeon_mbox_get_data(oct, cmd->qno);

		//3. if the cmd is in progress
		if (ret == OCT_MBOX_CMD_BUSY)
			break;

		//4. if cmd is completed, call the callback once cmd is completed.
		if (cmd->fn)
			cmd->fn((void *)oct, cmd->fn_arg);

		cavium_spin_lock(&oct->mbox_lock);
		cavium_memset(cmd, 0, sizeof(oct_mbox_cmd_t));
		running_index++;

		if (running_index >= MAX_MBOX_CMDS)
			running_index = 0;

		cavium_spin_unlock(&oct->mbox_lock);
	}			//end fo while
}

/**
 * oct_mailbox_thread:
 * @param oct_dev: Pointer to Octeon Device
 *
 * Thread function for mailbox
 */
int oct_mailbox_thread(void *oct_dev)
{
	char name[] = "Octeon_mailbox thread";
	octeon_device_t *oct = (octeon_device_t *) oct_dev;
	octeon_mbox_t *mbox = oct->mbox[0];

	cavium_print_msg("\n-- OCTEON: %s starting execution now!\n", name);

	while (!oct->mbox_stop_thread) {
		uint64_t mbox_int_val = 0, qno = 0, max_qno = 0;

		cavium_sleep_timeout_cond(&oct->mbox_wc,
					  (int *)&oct->mbox_wait_cond, 1000);
//             cavium_sleep_cond(&oct->mbox_wc, (int *)&oct->mbox_wait_cond);
		oct->mbox_wait_cond = 0;

		//read and write 1 to clear.
		mbox_int_val = OCTEON_READ64(mbox->mbox_int_reg);
		OCTEON_WRITE64(mbox->mbox_int_reg, mbox_int_val);

//              cavium_print_msg("pf[%d] ::mbox read int status and cleared::%llx...:%x\n",oct->pf_num,mbox_int_val);

#if 0
		while (mbox_int_val) {
			if (CVM_CHECK_BIT(mbox_int_val, qno)) {
				if ((oct->chip_id == OCTEON_CN73XX_VF)
				    || (oct->chip_id == OCTEON_CN78XX_VF)) {
					octeon_mbox_process_interrupt(oct, 0);
				} else {
					octeon_mbox_process_interrupt(oct, qno);
				}
				CVM_CLEAR_BIT(mbox_int_val, qno);
			}

			qno++;
		}

#endif
		max_qno = OCTEON3_MAX_IOQS;

		// check for signature in all the vf's mbox[0] register.
		while (qno < max_qno) {
			if (OCTEON_READ64(oct->mbox[qno]->mbox_write_reg) ==
			    OCTEON_PFVFSIG) {
				octeon_mbox_process_interrupt(oct, qno);
			}
			qno += oct->sriov_info.rings_per_vf;
		}

		//      cavium_print_msg("mbox processed all interrupts..:%x\n",p);
		if (0)
			oct_mbox_process_cmd_queue(oct);

		//      cavium_print_msg("mbox proceesed cmd queue:%x\n",p);

		oct->fn_list.enable_interrupt(oct->chip, OCTEON_MBOX_INTR);
		//      cavium_print_msg("mbox int enabled....:%x\n",p);
	}
	cavium_print_msg("\n-- OCTEON: Mail box thread quitting now:\n");

	return 0;
}

/**
 * octeon_init_mbox_thread:
 * @param oct: Pointer Octeon Device
 *
 * Initalize the mailbox thread and cmd queue.
 */
int octeon_init_mbox_thread(octeon_device_t * oct)
{
	cavium_init_wait_channel(&(oct->mbox_wc));
	oct->mbox_wait_cond = 0;
	INIT_CVM_KTHREAD(&oct->mbox_id);
	cavium_kthread_setup(&oct->mbox_id, oct_mailbox_thread, oct,
			     "Oct mailbox Thread", 1);
	if (cavium_kthread_create(&oct->mbox_id)) {
		return -1;
	}
	cavium_print_msg("mbox thread created....\n");
	octeon_setup_mbox_cmd_queue(oct);

	cavium_print_msg("mbox setup cmd queue done...\n");
	return 0;
}
