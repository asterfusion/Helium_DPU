/* Copyright (c) 2020 Marvell.
 * SPDX-License-Identifier: GPL-2.0
 */

#ifndef  __CNXK_PF_CONFIG_DATA_H__
#define  __CNXK_PF_CONFIG_DATA_H__

/** Default configuration
 *  for CNXK OCTEON Model.
 */

cnxk_pf_config_t default_cnxk_pf_conf = {
	/** IQ attributes */
	.iq = {
	       .max_iqs = CNXK_CFG_IO_QUEUES,
	       .max_base_iqs = OCTEON_MAX_CNXK_BASE_IOQ,
	       .pending_list_size =
	       (CNXK_MAX_IQ_DESCRIPTORS * CNXK_CFG_IO_QUEUES),
	       .num_descs = CNXK_MAX_IQ_DESCRIPTORS,
	       .instr_type = OCTEON_64BYTE_INSTR,
	       .db_min = CNXK_DB_MIN,
	       .db_timeout = CNXK_DB_TIMEOUT,
	       .intr_threshold = CNXK_INTR_THRESHOLD,
	       }
	,

	/** OQ attributes */
	.oq = {
	       .max_oqs = CNXK_CFG_IO_QUEUES,
	       .max_base_oqs = OCTEON_MAX_CNXK_BASE_IOQ,
	       .num_descs = CNXK_MAX_OQ_DESCRIPTORS,
	       .info_ptr = OCTEON_OQ_INFOPTR_MODE,
	       .buf_size = CNXK_OQ_BUF_SIZE,
	       .pkts_per_intr = CNXK_OQ_PKTSPER_INTR,
	       .refill_threshold = CNXK_OQ_REFIL_THRESHOLD,
	       .oq_intr_pkt = CNXK_OQ_INTR_PKT,
	       .oq_intr_time = CNXK_OQ_INTR_TIME,
	       }
	,

	.port_cfg = {
		     .srn = 0,
		     .num_ioqs = 0,
		     }
	,

	/** SR-IOV configuration  */
	.pf_sriov_cfg[0] = {
			    .start_ring_num = CNXK_EPF_START_RING_NUM,
			    .total_pf_rings = CNXK_EPF_MAX_RINGS,
			    .rings_per_vf = CNXK_EPF_RINGS_PER_VF,
			    .num_vfs = CNXK_EPF_NUM_VFS}
	,

	/** Miscellaneous attributes */
	.misc = {
		 /* 512 MB OCTEON memory */
		 .mem_size = 0xff,

		 /* No # of OCTEON cores */
		 .core_cnt = 32,

		 /* Control IO queue */
		 .ctrlq_num = 0,

		 /* Misc flags */
		 .flags = 0xaabb,

		 /* CRC  */
		 .crc = 0xeeff,

		 /* Host driver link query interval */
		 .oct_link_query_interval = 100,

		 /* Octeon link query interval */
		 .host_link_query_interval = 500,

		 /* num_pfs exist.. */
		 .num_pfs = 1,

		 }
	,

};

#endif
