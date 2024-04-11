/* Copyright (c) 2020 Marvell.
 * SPDX-License-Identifier: GPL-2.0
 */

#include "octeon_main.h"
#include "octeon_macros.h"
#include "octeon_hw.h"

static cvm_kthread_t oct_poll_id;
static volatile int oct_poll_thread_off = 1;

#define  MAX_POLL_FN      160

typedef enum {

	POLL_FN_UNUSED = 0,
	POLL_FN_SCHED = 1,
	POLL_FN_DESCHED = 2
} oct_poll_fn_state_t;

static int oct_poll_thread(void *);

typedef struct {

	oct_poll_fn_state_t state;

	unsigned long sched_time;

	octeon_poll_fn_t fn;

	unsigned long fn_arg;

	int ticks;

	char name[80];

	int rsvd;

} octeon_poll_fn_node_t;

static void
oct_poll_fn_print_action(int oct_id, octeon_poll_fn_node_t * n, int action)
{
	char act_str[40];
	char name_str[80];

	if (n->rsvd == 0xff)
		return;

	switch (action) {
	case OCT_POLL_FN_REGISTERED:
		strcpy(act_str, "registered");
		break;
	case OCT_POLL_FN_UNREGISTERED:
		strcpy(act_str, "unregistered");
		break;
	case OCT_POLL_FN_FINISHED:
		strcpy(act_str, "completed (status: Finished)");
		break;
	case OCT_POLL_FN_ERROR:
		strcpy(act_str, "completed (status: Error)");
		break;
	}

	if (strlen(n->name) == 0)
		sprintf(name_str, " @ %p", n->fn);
	else
		strcpy(name_str, n->name);

	cavium_print_msg("OCTEON[%d] Poll Function (%s arg: 0x%lx) %s\n",
			 oct_id, name_str, n->fn_arg, act_str);
}

int octeon_setup_poll_fn_list(octeon_device_t * oct)
{
	int size = (MAX_POLL_FN * sizeof(octeon_poll_fn_node_t));

	oct->poll_list = cavium_alloc_virt(size);
	if (oct->poll_list == NULL) {
		cavium_error("%s: Poll list alloc failed\n", __CVM_FUNCTION__);
		return -ENOMEM;
	}

	cavium_memset(oct->poll_list, 0, size);
	cavium_spin_lock_init(&oct->poll_lock);

	return 0;
}

void octeon_delete_poll_fn_list(octeon_device_t * oct)
{
	cavium_free_virt(oct->poll_list);
	oct->poll_list = NULL;
}

int octeon_init_poll_thread(void)
{
	INIT_CVM_KTHREAD(&oct_poll_id);
	cavium_kthread_setup(&oct_poll_id, oct_poll_thread, NULL,
			     "Oct Poll Thread", 1);
	if (cavium_kthread_create(&oct_poll_id)) {
		cavium_error("%s: kernel thread created\n", __CVM_FUNCTION__);
		return 1;
	}

	return 0;
}

int octeon_delete_poll_thread(void)
{
	cavium_print(PRINT_FLOW, "Deleting poll thread");

	if (CVM_KTHREAD_EXISTS(&oct_poll_id)) {
		/* Wait till the poll thread starts execution */
		while (oct_poll_thread_off)
			cavium_sleep_timeout(1);

		cavium_kthread_destroy(&oct_poll_id);

		/* Wait till the poll thread has come out of its loop. */
		while (!oct_poll_thread_off)
			cavium_sleep_timeout(1);

		cavium_print(PRINT_DEBUG,
			     " free_poll_thread: thread exited normally\n");
	}

	return 0;
}

int octeon_register_poll_fn(int oct_id, octeon_poll_ops_t * ops)
{
	octeon_device_t *oct = get_octeon_device(oct_id);
	octeon_poll_fn_node_t *n, *poll_list;
	int i;

	if (oct == NULL) {
		cavium_error("%s Octeon device %d not found\n",
			     __CVM_FUNCTION__, oct_id);
		return -ENODEV;
	}

	if (ops == NULL) {
		cavium_error("%s ops pointer is NULL\n", __CVM_FUNCTION__);
		return -EINVAL;
	}

	poll_list = (octeon_poll_fn_node_t *) oct->poll_list;

	cavium_spin_lock(&oct->poll_lock);

	for (i = 0; i < MAX_POLL_FN; i++) {
		if (poll_list[i].state == POLL_FN_UNUSED)
			break;
	}

	if (i == MAX_POLL_FN) {
		cavium_error("%s: No space in poll fn list\n",
			     __CVM_FUNCTION__);
		cavium_spin_unlock(&oct->poll_lock);
		return -ENOMEM;
	}

	n = &poll_list[i];
	cavium_memset(n, 0, sizeof(octeon_poll_fn_node_t));

	n->fn = ops->fn;
	n->fn_arg = ops->fn_arg;
	/* in case of max name len, terminating zero present due to memset */
	strncpy(n->name, ops->name, sizeof(n->name) - 1);
	n->ticks = (ops->ticks) ? ops->ticks : 1;
	n->sched_time = cavium_jiffies + n->ticks;
	n->rsvd = ops->rsvd;
	n->state = POLL_FN_DESCHED;

	oct_poll_fn_print_action(oct_id, n, OCT_POLL_FN_REGISTERED);

	cavium_spin_unlock(&oct->poll_lock);

	return 0;
}

int
octeon_unregister_poll_fn(int oct_id, octeon_poll_fn_t fn, unsigned long fn_arg)
{
	octeon_device_t *oct = get_octeon_device(oct_id);
	octeon_poll_fn_node_t *n, *poll_list;
	int i, ret = -EINVAL;

	if (oct == NULL) {
		cavium_error("%s Octeon device %d not found\n",
			     __CVM_FUNCTION__, oct_id);
		return -ENODEV;
	}

	poll_list = (octeon_poll_fn_node_t *) oct->poll_list;

	cavium_spin_lock(&oct->poll_lock);

	for (i = 0; i < MAX_POLL_FN; i++) {

		n = &poll_list[i];

		if ((n->fn == fn) && (n->fn_arg == fn_arg)) {
			/* Meanwhile release and acquire the spin_lock to avoid   
			 * deadlock condition with poll_thread       */
			while (n->state == POLL_FN_SCHED) {
				cavium_sleep_timeout(3);
				cavium_spin_unlock(&oct->poll_lock);
				cavium_sleep_timeout(3);
				cavium_spin_lock(&oct->poll_lock);
			}

			oct_poll_fn_print_action(oct_id, n,
						 OCT_POLL_FN_UNREGISTERED);
			cavium_memset(n, 0, sizeof(octeon_poll_fn_node_t));
			ret = 0;
			break;
		}

	}

	cavium_spin_unlock(&oct->poll_lock);

	if (i == MAX_POLL_FN) {
		cavium_error
		    ("%s: oct[%d]:  Poll Function (@ %p; arg: %lx) not found\n",
		     __CVM_FUNCTION__, oct_id, fn, fn_arg);
	}

	return ret;
}

static void oct_process_poll_list(octeon_device_t * oct)
{
	int i;
	oct_poll_fn_status_t ret;
	octeon_poll_fn_node_t *n, *poll_list;

	if (oct == NULL)
		return;

	oct->stats.poll_count++;

	poll_list = (octeon_poll_fn_node_t *) oct->poll_list;
	if (poll_list == NULL)
		return;

	cavium_spin_lock(&oct->poll_lock);

	for (i = 0; i < MAX_POLL_FN; i++) {

		n = (octeon_poll_fn_node_t *) & poll_list[i];

		if (n->state != POLL_FN_DESCHED)
			continue;

		if (!cavium_check_timeout(cavium_jiffies, n->sched_time))
			continue;

		n->state = POLL_FN_SCHED;

		cavium_spin_unlock(&oct->poll_lock);
		ret = n->fn((void *)oct, n->fn_arg);
		cavium_spin_lock(&oct->poll_lock);

		if ((ret == OCT_POLL_FN_ERROR) || (ret == OCT_POLL_FN_FINISHED)) {

			oct_poll_fn_print_action(oct->octeon_id, n, ret);
			cavium_memset(n, 0, sizeof(octeon_poll_fn_node_t));

		} else {

			n->state = POLL_FN_DESCHED;
			n->sched_time = cavium_jiffies + n->ticks;

		}

	}

	cavium_spin_unlock(&oct->poll_lock);

}

static int oct_poll_thread(void *arg UNUSED)
{
	char name[] = "Octeon Poll Thread";

	cavium_print_msg("OCTEON: %s starting execution now!\n", name);
	oct_poll_thread_off = 0;

	while (!cavium_kthread_signalled()) {
		int i;

		for (i = 0; i < get_octeon_count(); i++) {
			oct_process_poll_list(get_octeon_device(i));
		}

		cavium_sleep_timeout(1);
	}

	cavium_print_msg("OCTEON: Poll_thread quitting now\n");
	oct_poll_thread_off = 1;

	return 0;
}

void octeon_oei_irq_handler(octeon_device_t *oct, u64 reg_val)
{
	if ((reg_val & 0x20) && oct->oei_irq_handler)
		oct->oei_irq_handler(oct);
}
EXPORT_SYMBOL(octeon_oei_irq_handler);
/* $Id: octeon_poll.c 162810 2017-07-17 18:05:03Z mchalla $ */
