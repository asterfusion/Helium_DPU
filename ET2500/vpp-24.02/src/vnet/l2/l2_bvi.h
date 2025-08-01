/*
 * l2_bvi.h : layer 2 Bridged Virtual Interface
 *
 * Copyright (c) 2013 Cisco and/or its affiliates.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef included_l2bvi_h
#define included_l2bvi_h

#include <vlib/vlib.h>
#include <vnet/ethernet/ethernet.h>
#include <vppinfra/sparse_vec.h>
#include <vnet/bonding/node.h>
#include <vnet/l2/l2_input.h>

#define TO_BVI_ERR_OK        0
#define TO_BVI_ERR_BAD_MAC   1
#define TO_BVI_ERR_ETHERTYPE 2

static_always_inline u32
l2_to_bvi_dmac_check (vnet_hw_interface_t * hi, u8 * dmac,
		      ethernet_interface_t * ei, u8 have_sec_dmac)
{
  ethernet_interface_address_t *sec_addr;

  if (ethernet_mac_address_equal (dmac, hi->hw_address))
    return TO_BVI_ERR_OK;

  if (have_sec_dmac)
    {
      vec_foreach (sec_addr, ei->secondary_addrs)
      {
	if (ethernet_mac_address_equal (dmac, sec_addr->mac.bytes))
	  return TO_BVI_ERR_OK;
      }
    }

  return TO_BVI_ERR_BAD_MAC;
}

static u32 get_parent_sw_if_index(u32 sw_if_index) {
    vnet_sw_interface_t *sw = vnet_get_sw_interface(vnet_get_main(), sw_if_index);
    if (sw && sw->type == VNET_SW_INTERFACE_TYPE_SUB) {
        return sw->sup_sw_if_index;
    }
    return ~0;
}

static bool find_bond_by_sw_if_index(u32 sw_if_index) {
    bond_main_t *bm = &bond_main;
    uword *p = hash_get(bm->bond_by_sw_if_index, sw_if_index);
    if (p != NULL) {
      return true;
    }

    u32 parent_sw_if_index = get_parent_sw_if_index(sw_if_index);
    if (parent_sw_if_index != ~0) {
        p = hash_get(bm->bond_by_sw_if_index, parent_sw_if_index);
        if (p != NULL) {
            return true;
        }
    }
    return false;
}

/**
 * Send a packet from L2 processing to L3 via the BVI interface.
 * Set next0 to the proper L3 input node.
 * Return an error if the packet isn't what we expect.
 */

static_always_inline u32
l2_to_bvi (vlib_main_t * vlib_main,
	   vnet_main_t * vnet_main,
	   vlib_buffer_t * b0,
	   u32 bvi_sw_if_index, next_by_ethertype_t * l3_next, u16 * next0)
{
  ethernet_main_t *em = &ethernet_main;

  /* Perform L3 my-mac filter */
  ethernet_header_t *e0 = vlib_buffer_get_current (b0);
  if (!ethernet_address_cast (e0->dst_address))
    {
      vnet_hw_interface_t *hi =
	vnet_get_sup_hw_interface (vnet_main, bvi_sw_if_index);
      ethernet_interface_t *ei = ethernet_get_interface (em, hi->hw_if_index);
      u32 rv;

      if (PREDICT_FALSE (ei && (vec_len (ei->secondary_addrs) > 0)))
	rv = l2_to_bvi_dmac_check (hi, e0->dst_address, ei,
				   1 /* have_sec_dmac */ );
      else
	rv = l2_to_bvi_dmac_check (hi, e0->dst_address, ei,
				   0 /* have_sec_dmac */ );

      if (rv != TO_BVI_ERR_OK)
	return rv;
    }

  /* Save L2 header position which may be changed due to packet replication */
  vnet_buffer (b0)->l2_hdr_offset = b0->current_data;

  /* Strip L2 header */
  u8 l2_len = vnet_buffer (b0)->l2.l2_len;
  vlib_buffer_advance (b0, l2_len);

  u8 *l3h = vlib_buffer_get_current (b0);
  u16 ethertype = clib_net_to_host_u16 (*(u16 *) (l3h - 2));

  /* store the orignal sw_if_index */
  if(!find_bond_by_sw_if_index(vnet_buffer (b0)->sw_if_index[VLIB_RX]))
  {
    vnet_buffer2 (b0)->l2_rx_sw_if_index = vnet_buffer (b0)->sw_if_index[VLIB_RX];
    b0->flags |= VLIB_BUFFER_NOT_PHY_INTF;
  }

  /* Set the input interface to be the BVI interface */
  vnet_buffer (b0)->sw_if_index[VLIB_RX] = bvi_sw_if_index;
  vnet_buffer (b0)->sw_if_index[VLIB_TX] = ~0;

  /* Go to appropriate L3 input node */
  if (ethertype == ETHERNET_TYPE_IP4)
    {
      *next0 = l3_next->input_next_ip4;
    }
  else if (ethertype == ETHERNET_TYPE_IP6)
    {
      *next0 = l3_next->input_next_ip6;
    }
  else
    {
      /* uncommon ethertype, check table */
      u32 i0 = sparse_vec_index (l3_next->input_next_by_type, ethertype);
      *next0 = vec_elt (l3_next->input_next_by_type, i0);

      if (i0 == SPARSE_VEC_INVALID_INDEX)
	{
	  return TO_BVI_ERR_ETHERTYPE;
	}
    }

  /* increment BVI RX interface stat */
  vlib_increment_combined_counter
    (vnet_main->interface_main.combined_sw_if_counters
     + VNET_INTERFACE_COUNTER_RX,
     vlib_main->thread_index, bvi_sw_if_index,
     1, vlib_buffer_length_in_chain (vlib_main, b0));
  return TO_BVI_ERR_OK;
}

void
l2bvi_register_input_type (vlib_main_t * vm,
			   ethernet_type_t type, u32 node_index);

extern int l2_bvi_create (u32 instance, const mac_address_t * mac,
			  u32 * sw_if_index);
extern int l2_bvi_delete (u32 sw_if_index);

#endif

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
