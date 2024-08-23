/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2023 Intel Corporation
 */

#ifndef MAIN_H
#define MAIN_H


#include <rte_common.h>
#include <rte_cycles.h>
#include <rte_dev.h>

#define MAX_WORKER_NB 128
#define MAX_OUTPUT_STR_LEN 512

#define MAX_DMA_NB 128

extern char output_str[MAX_WORKER_NB + 1][MAX_OUTPUT_STR_LEN];

typedef enum {
	OP_NONE = 0,
	OP_ADD,
	OP_MUL
} alg_op_type;

struct test_configure_entry {
	uint32_t first;
	uint32_t last;
	uint32_t incr;
	alg_op_type op;
	uint32_t cur;
};

struct lcore_dma_map_t {
	uint32_t lcores[MAX_WORKER_NB];
	char dma_names[MAX_WORKER_NB][RTE_DEV_NAME_MAX_LEN];
	int16_t dma_ids[MAX_WORKER_NB];
	uint16_t cnt;
};

struct test_vchan_dev_config {
	struct rte_dma_port_param port;
	uintptr_t raddr;
};

struct test_configure {
	bool is_valid;
	bool is_skip;
	uint8_t test_type;
	uint8_t transfer_dir;
	const char *test_type_str;
	uint16_t src_numa_node;
	uint16_t dst_numa_node;
	uint16_t opcode;
	bool is_dma;
	bool is_sg;
	struct lcore_dma_map_t lcore_dma_map;
	struct test_configure_entry mem_size;
	struct test_configure_entry buf_size;
	struct test_configure_entry ring_size;
	struct test_configure_entry kick_batch;
	uint8_t nb_src_sges;
	uint8_t nb_dst_sges;
	uint8_t cache_flush;
	uint32_t nr_buf;
	uint16_t test_secs;
	const char *eal_args;
	uint8_t scenario_id;
	struct test_vchan_dev_config vchan_dev;
	bool is_bidir;
};

int mem_copy_benchmark(struct test_configure *cfg);

#endif /* MAIN_H */
