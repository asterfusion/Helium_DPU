/* Copyright (c) 2020 Marvell.
 * SPDX-License-Identifier: GPL-2.0
 */

/* Mgmt ethernet driver
 */

#ifndef _DESC_QUEUE_H_
#define _DESC_QUEUE_H_


#define OCTBOOT_NET_DESC_PTR_DIRECT   0
#define OCTBOOT_NET_DESC_PTR_INDIRECT 1

/* hw desc ptr */
struct octboot_net_hw_desc_ptr {
	union {
		uint64_t u64;
		struct {
			uint64_t facility_rsvd: 46;
			uint64_t ptr_type:2; /* direct or indirect */
			uint64_t ptr_len:16; /* length of this buf */
		} s_generic;
		struct {
			uint64_t rsvd:29;
			uint64_t is_frag:1; /* is this part of a packet */
			uint64_t total_len:16; /* total length of the packet */
			uint64_t ptr_type:2; /* direct or indirect */
			uint64_t ptr_len:16; /* length of this buf */
		} s_mgmt_net;
	} hdr;
	uint64_t ptr; /* hardware address */
} __packed;

struct octboot_net_hw_descq {
	uint32_t prod_idx;
	uint32_t cons_idx;
	uint32_t num_entries;
	uint32_t buf_size;
	uint64_t shadow_cons_idx_addr;
	uint64_t shadow_prod_idx_addr;
	struct octboot_net_hw_desc_ptr desc_arr[];
} __packed;

#define OCTBOOT_NET_DESC_ARR_ENTRY_OFFSET(i) \
	(sizeof(struct octboot_net_hw_descq) + (i * sizeof(struct octboot_net_hw_desc_ptr)))

#endif /* _DESC_QUEUE_H_ */
