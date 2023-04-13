#ifndef __RTE_FLOW_BLOCK_H__
#define __RTE_FLOW_BLOCK_H__

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <inttypes.h>
#include <sys/types.h>
#include <sys/queue.h>
#include <setjmp.h>
#include <stdarg.h>
#include <ctype.h>
#include <errno.h>
#include <getopt.h>
#include <signal.h>
#include <stdbool.h>

#include <rte_eal.h>
#include <rte_common.h>
#include <rte_malloc.h>
#include <rte_ether.h>
#include <rte_ethdev.h>
#include <rte_mempool.h>
#include <rte_mbuf.h>
#include <rte_net.h>
#include <rte_flow.h>
#include <rte_cycles.h>


#define MAX_PATTERN_NUM		4
#define MAX_ACTION_NUM		2

typedef struct rte_flow_ntuple_filter {
	uint32_t dst_ip;         /**< Destination IP address in big endian. */
	uint32_t dst_ip_mask;    /**< Mask of destination IP address. */
	uint32_t src_ip;         /**< Source IP address in big endian. */
	uint32_t src_ip_mask;    /**< Mask of destination IP address. */
	uint16_t dst_port;       /**< Destination port in big endian. */
	uint16_t dst_port_mask;  /**< Mask of destination port. */
	uint16_t src_port;       /**< Source Port in big endian. */
	uint16_t src_port_mask;  /**< Mask of source port. */
	uint8_t proto;           /**< L4 protocol. */
	uint8_t proto_mask;      /**< Mask of L4 protocol. */
	uint16_t port_id;       /**< (port_id + 1) of egress*/
}rte_flow_ntuple_filter_t;

struct rte_flow *
generate_ipv4_flow(uint16_t port_id, 
        rte_flow_ntuple_filter_t *ntuple_filter,
		struct rte_flow_error *error);


#endif
