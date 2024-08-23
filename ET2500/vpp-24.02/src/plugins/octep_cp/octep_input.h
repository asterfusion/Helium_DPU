/*
 * Copyright (c) 2023 Marvell.
 * SPDX-License-Identifier: Apache-2.0
 * https://spdx.org/licenses/Apache-2.0.html
 */

#ifndef __OCTEP_INPUT_H__
#define __OCTEP_INPUT_H__

#define DEVICE_INPUT	"device-input"
#define DPU_INPUT_NODE	"h2d-input"
#define DEVICE_OUTPUT	"interface-output"
#define DPU_OUTPUT_NODE "d2h-output"
/*
 * Initialize loop mode implementation.
 * return value: 0 on success, -errno on failure.
 */
int octep_cp_initialize_receive_vector ();

/*
 * Process interrupts and host messages.
 * return value: size of response in words on success, -errno on failure.
 */
int loop_process_msgs ();

/*
 * Process user interrupt signal.
 * return value: 0 on success, -errno on failure.
 */
int loop_process_sigusr1 ();

/*
 * Uninitialize loop mode implementation.
 * return value: 0 on success, -errno on failure.
 */
int octep_cp_uninitialize_receive_vector ();

#endif /* __OCTEP_INPUT_H__ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
