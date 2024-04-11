/* Copyright (c) 2020 Marvell.
 * SPDX-License-Identifier: GPL-2.0
 */

#ifndef  __CN83XX_VF_CONFIG_DATA_H__
#define  __CN83XX_VF_CONFIG_DATA_H__

/** Default configuration
 *  for CN83XX OCTEON Model.
 */

cn83xx_vf_config_t default_cn83xx_vf_conf = {
	/** IQ attributes */
	.iq = {
	       .max_iqs = CN83XX_VF_CFG_IO_QUEUES,
	       .max_base_iqs = OCTEON_MAX_83XX_VF_BASE_IOQ,
	       .pending_list_size =
	       (CN83XX_MAX_IQ_DESCRIPTORS * CN83XX_VF_CFG_IO_QUEUES),
	       .num_descs = CN83XX_MAX_IQ_DESCRIPTORS,
	       .instr_type = OCTEON_64BYTE_INSTR,
	       .db_min = CN83XX_DB_MIN,
	       .db_timeout = CN83XX_DB_TIMEOUT,
	       .intr_threshold = CN83XX_INTR_THRESHOLD,
	       }
	,

	/** OQ attributes */
	.oq = {
	       .max_oqs = CN83XX_VF_CFG_IO_QUEUES,
	       .max_base_oqs = OCTEON_MAX_83XX_VF_BASE_IOQ,
	       .num_descs = CN83XX_MAX_OQ_DESCRIPTORS,
	       .info_ptr = OCTEON_OQ_INFOPTR_MODE,
	       .buf_size = CN83XX_OQ_BUF_SIZE,
	       .pkts_per_intr = CN83XX_OQ_PKTSPER_INTR,
	       .refill_threshold = CN83XX_OQ_REFIL_THRESHOLD,
	       .oq_intr_pkt = CN83XX_OQ_INTR_PKT,
	       .oq_intr_time = CN83XX_OQ_INTR_TIME,
	       }
	,

	.port_cfg = {
		     .srn = 0,
		     .num_ioqs = 0,
		     }
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
