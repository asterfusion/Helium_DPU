/*
 * Copyright (c) 2021 Marvell.
 * SPDX-License-Identifier: Apache-2.0
 * https://spdx.org/licenses/Apache-2.0.html
 */

/**
 * @file
 * @brief ONP scheduler interface.
 */

#ifndef included_onp_sched_sched_h
#define included_onp_sched_sched_h

#include <onp/drv/inc/sched.h>

#define ONP_N_SCHED_QUEUES 8

extern vlib_node_registration_t onp_sched_input_node;

#define ONP_SCHED_INPUT_NODE_INDEX onp_sched_input_node.index

typedef struct
{
  /* Is scheduler enabled or disabled */
  i8 is_scheduler_enabled;

  /* Is packet vector simulation enabled */
  i8 is_pkt_vector_sim_enabled;

  i8 sched_handling_ref_count;

  u8 buffer_pool_index;

  /* No. of scheduler core queues */
  u32 n_sched_core_queues;

  /* No. of scheduler default queues */
  u32 n_sched_default_queues;

  vlib_pci_addr_t sched_pci_addr;

} onp_sched_main_t;

extern onp_sched_main_t onp_sched_main;

typedef struct
{
  /* Enable-scheduler-pkt-vector-simulation */
  i8 pkt_vector_simulation_enabled;

  /* Does scheduler needs to be enabled or disabled */
  i8 is_sched_config_enabled;

  u32 n_sched_core_queues;

  u8 n_sched_default_queues;

  u32 sched_handoff_pool_n_buffers;
  vlib_pci_addr_t sched_pci_addr;

  uuid_t uuid_token;
} onp_sched_config_t;

u32 onp_sched_total_queues_get (void);

clib_error_t *onp_sched_dev_config (void *, vlib_pci_addr_t pci_addr);

void onp_sched_register_pre_barrier_callback_fn (u8 enable_disable);
void onp_sched_register_pre_barrier_callback_fn_on_thread (u8 thread_index,
							   u8 enable_disable);

void onp_sched_input_node_enable_disable (vlib_main_t *vm, u32 thread_index,
					  int enable_disable);
#endif /* included_onp_sched_sched_h */
/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
