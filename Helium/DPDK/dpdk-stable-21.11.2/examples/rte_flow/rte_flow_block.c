/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2017 Mellanox Technologies, Ltd
 */
#include <rte_flow_block.h>

/**
 * create a flow rule that sends packets with matching src and dest ip
 * to selected queue.
 *
 * @param port_id
 *   The selected port.
 * @param rx_q
 *   The selected target queue.
 * @param src_ip
 *   The src ip value to match the input packet.
 * @param src_mask
 *   The mask to apply to the src ip.
 * @param dest_ip
 *   The dest ip value to match the input packet.
 * @param dest_mask
 *   The mask to apply to the dest ip.
 * @param[out] error
 *   Perform verbose error reporting if not NULL.
 *
 * @return
 *   A flow if the rule could be created else return NULL.
 */

/* Function responsible for creating the flow rule. 8< */
struct rte_flow *
generate_ipv4_flow(uint16_t port_id, 
        rte_flow_ntuple_filter_t *ntuple_filter,
		struct rte_flow_error *error)
{
	/* Declaring structs being used. 8< */
	struct rte_flow_attr attr;
	struct rte_flow_item pattern[MAX_PATTERN_NUM];
	struct rte_flow_action action[MAX_ACTION_NUM];
	struct rte_flow *flow = NULL;
    struct rte_flow_action_mark port = { .id = ntuple_filter->port_id };
    struct rte_flow_item_ipv4 ip_spec;
	struct rte_flow_item_ipv4 ip_mask;
    struct rte_flow_item_udp udp_spec;
    struct rte_flow_item_udp udp_mask;
    struct rte_flow_item_tcp tcp_spec;
    struct rte_flow_item_tcp tcp_mask;
	/* >8 End of declaring structs being used. */
	int res;
    //struct rte_flow_action_queue queue = { .index = 3 };

	memset(pattern, 0, sizeof(pattern));
	memset(action, 0, sizeof(action));

	/* Set the rule attribute, only ingress packets will be checked. 8< */
	memset(&attr, 0, sizeof(struct rte_flow_attr));
	attr.ingress = 1;
	/* >8 End of setting the rule attribute. */

	/*
	 * create the action sequence.
	 * one action only,  move packet to queue
	 */
	if (ntuple_filter->port_id != 127)
    {
	    action[0].type = RTE_FLOW_ACTION_TYPE_MARK;
        action[0].conf = &port;
    }
    else
    {
        action[0].type = RTE_FLOW_ACTION_TYPE_DROP;
    }

    action[1].type = RTE_FLOW_ACTION_TYPE_END;

	/*
	 * set the first level of the pattern (ETH).
	 * since in this example we just want to get the
	 * ipv4 we set this level to allow all.
	 */

	/* Set this level to allow all. 8< */
	pattern[0].type = RTE_FLOW_ITEM_TYPE_ETH;
	/* >8 End of setting the first level of the pattern. */

	/*
	 * setting the second level of the pattern (IP).
	 * in this example this is the level we care about
	 * so we set it according to the parameters.
	 */

	/* Setting the second level of the pattern. 8< */
	memset(&ip_spec, 0, sizeof(struct rte_flow_item_ipv4));
	memset(&ip_mask, 0, sizeof(struct rte_flow_item_ipv4));

    ip_spec.hdr.dst_addr = htonl(ntuple_filter->dst_ip);
    ip_spec.hdr.src_addr = htonl(ntuple_filter->src_ip);
    ip_mask.hdr.dst_addr = htonl(ntuple_filter->dst_ip_mask);
    ip_mask.hdr.src_addr = htonl(ntuple_filter->src_ip_mask);;
	pattern[1].type = RTE_FLOW_ITEM_TYPE_IPV4;
	pattern[1].spec = &ip_spec;
	pattern[1].mask = &ip_mask;
	/* >8 End of setting the second level of the pattern. */

    if (ntuple_filter->proto == 17)
    {
        memset(&udp_spec, 0, sizeof(struct rte_flow_item_udp));
    	memset(&udp_mask, 0, sizeof(struct rte_flow_item_udp));
    	udp_spec.hdr.src_port = htons(ntuple_filter->src_port);
    	udp_mask.hdr.src_port = htons(ntuple_filter->src_port_mask);
        udp_spec.hdr.dst_port = htons(ntuple_filter->dst_port);
    	udp_mask.hdr.dst_port = htons(ntuple_filter->dst_port_mask);
        pattern[2].type = RTE_FLOW_ITEM_TYPE_UDP;
    	pattern[2].spec = &udp_spec;
    	pattern[2].mask = &udp_mask;
    
    	pattern[3].type = RTE_FLOW_ITEM_TYPE_END;
    }

    else if (ntuple_filter->proto == 6)
    {
        memset(&tcp_spec, 0, sizeof(struct rte_flow_item_tcp));
    	memset(&tcp_mask, 0, sizeof(struct rte_flow_item_tcp));
    	tcp_spec.hdr.src_port = htons(ntuple_filter->src_port);
    	tcp_mask.hdr.src_port = ntuple_filter->src_port_mask;
        tcp_spec.hdr.dst_port = htons(ntuple_filter->dst_port);
    	tcp_mask.hdr.dst_port = ntuple_filter->dst_port_mask;
        pattern[2].type = RTE_FLOW_ITEM_TYPE_TCP;
    	pattern[2].spec = &tcp_spec;
    	pattern[2].mask = &tcp_mask;
    
    	pattern[3].type = RTE_FLOW_ITEM_TYPE_END;
    }

	else
	{
		pattern[2].type = RTE_FLOW_ITEM_TYPE_END;
	}

	/* Validate the rule and create it. 8< */
	res = rte_flow_validate(port_id, &attr, pattern, action, error);
	if (!res)
		flow = rte_flow_create(port_id, &attr, pattern, action, error);
	/* >8 End of validation the rule and create it. */

	return flow;
}
/* >8 End of function responsible for creating the flow rule. */

