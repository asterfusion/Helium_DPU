/*
 * Copyright (c) 2015 Cisco and/or its affiliates.
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
/*
 * vnet/buffer.h: vnet buffer flags
 *
 * Copyright (c) 2008 Eliot Dresselhaus
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 *  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 *  EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 *  MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 *  NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
 *  LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
 *  OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
 *  WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

#ifndef included_vnet_buffer_h
#define included_vnet_buffer_h

#include <vlib/vlib.h>

/**
 * Flags that are set in the high order bits of ((vlib_buffer*)b)->flags
 *
 */
#define foreach_vnet_buffer_flag                                              \
  _ (1, L4_CHECKSUM_COMPUTED, "l4-cksum-computed", 1)                         \
  _ (2, L4_CHECKSUM_CORRECT, "l4-cksum-correct", 1)                           \
  _ (3, VLAN_2_DEEP, "vlan-2-deep", 1)                                        \
  _ (4, VLAN_1_DEEP, "vlan-1-deep", 1)                                        \
  _ (5, SPAN_CLONE, "span-clone", 1)                                          \
  _ (6, LOOP_COUNTER_VALID, "loop-counter-valid", 0)                          \
  _ (7, LOCALLY_ORIGINATED, "local", 1)                                       \
  _ (8, IS_IP4, "ip4", 1)                                                     \
  _ (9, IS_IP6, "ip6", 1)                                                     \
  _ (10, OFFLOAD, "offload", 0)                                               \
  _ (11, IS_NATED, "natted", 1)                                               \
  _ (12, L2_HDR_OFFSET_VALID, "l2_hdr_offset_valid", 0)                       \
  _ (13, L3_HDR_OFFSET_VALID, "l3_hdr_offset_valid", 0)                       \
  _ (14, L4_HDR_OFFSET_VALID, "l4_hdr_offset_valid", 0)                       \
  _ (15, FLOW_REPORT, "flow-report", 1)                                       \
  _ (16, IS_DVR, "dvr", 1)                                                    \
  _ (17, QOS_DATA_VALID, "qos-data-valid", 0)                                 \
  _ (18, GSO, "gso", 0)                                                       \
  _ (19, AVAIL1, "avail1", 1)                                                 \
  _ (20, AVAIL2, "avail2", 1)                                                 \
  _ (21, AVAIL3, "avail3", 1)                                                 \
  _ (22, AVAIL4, "avail4", 1)                                                 \
  _ (23, AVAIL5, "avail5", 1)                                                 \
  _ (24, AVAIL6, "avail6", 1)                                                 \
  _ (25, AVAIL7, "avail7", 1)                                                 \
  _ (26, AVAIL8, "avail8", 1)                                                 \
  _ (27, AVAIL9, "avail9", 1)

/*
 * Please allocate the FIRST available bit, redefine
 * AVAIL 1 ... AVAILn-1, and remove AVAILn. Please maintain the
 * VNET_BUFFER_FLAGS_ALL_AVAIL definition.
 */

#define VNET_BUFFER_FLAGS_ALL_AVAIL                                           \
  (VNET_BUFFER_F_AVAIL1 | VNET_BUFFER_F_AVAIL2 | VNET_BUFFER_F_AVAIL3 |       \
   VNET_BUFFER_F_AVAIL4 | VNET_BUFFER_F_AVAIL5 | VNET_BUFFER_F_AVAIL6 |       \
   VNET_BUFFER_F_AVAIL7 | VNET_BUFFER_F_AVAIL8 | VNET_BUFFER_F_AVAIL9)

#define VNET_BUFFER_FLAGS_VLAN_BITS \
  (VNET_BUFFER_F_VLAN_1_DEEP | VNET_BUFFER_F_VLAN_2_DEEP)

enum
{
#define _(bit, name, s, v) VNET_BUFFER_F_##name  = (1 << LOG2_VLIB_BUFFER_FLAG_USER(bit)),
  foreach_vnet_buffer_flag
#undef _
};

enum
{
#define _(bit, name, s, v) VNET_BUFFER_F_LOG2_##name  = LOG2_VLIB_BUFFER_FLAG_USER(bit),
  foreach_vnet_buffer_flag
#undef _
};

/* Make sure that the vnet and vlib bits are disjoint */
STATIC_ASSERT (((VNET_BUFFER_FLAGS_ALL_AVAIL & VLIB_BUFFER_FLAGS_ALL) == 0),
	       "VLIB / VNET buffer flags overlap");

#define foreach_vnet_buffer_offload_flag                                      \
  _ (0, IP_CKSUM, "offload-ip-cksum", 1)                                      \
  _ (1, TCP_CKSUM, "offload-tcp-cksum", 1)                                    \
  _ (2, UDP_CKSUM, "offload-udp-cksum", 1)                                    \
  _ (3, OUTER_IP_CKSUM, "offload-outer-ip-cksum", 1)                          \
  _ (4, OUTER_UDP_CKSUM, "offload-outer-udp-cksum", 1)                        \
  _ (5, TNL_VXLAN, "offload-vxlan-tunnel", 1)                                 \
  _ (6, TNL_IPIP, "offload-ipip-tunnel", 1)

typedef enum
{
#define _(bit, name, s, v) VNET_BUFFER_OFFLOAD_F_##name = (1 << bit),
  foreach_vnet_buffer_offload_flag
#undef _
} vnet_buffer_oflags_t;

#define VNET_BUFFER_OFFLOAD_F_TNL_MASK                                        \
  (VNET_BUFFER_OFFLOAD_F_TNL_VXLAN | VNET_BUFFER_OFFLOAD_F_TNL_IPIP)

#define foreach_buffer_opaque_union_subtype     \
_(ip)                                           \
_(l2)                                           \
_(l2t)                                          \
_(l2_classify)                                  \
_(policer)                                      \
_(ipsec)					\
_(map)						\
_(map_t)					\
_(ip_frag)					\
_(mpls)					        \
_(tcp)

/*
 * vnet stack buffer opaque array overlay structure.
 * The vnet_buffer_opaque_t *must* be the same size as the
 * vlib_buffer_t "opaque" structure member, 32 bytes.
 *
 * When adding a union type, please add a stanza to
 * foreach_buffer_opaque_union_subtype (directly above).
 * Code in vnet_interface_init(...) verifies the size
 * of the union, and will announce any deviations in an
 * impossible-to-miss manner.
 */
typedef struct
{
  u32 sw_if_index[VLIB_N_RX_TX];
  i16 l2_hdr_offset;
  i16 l3_hdr_offset;
  i16 l4_hdr_offset;
  u8 feature_arc_index;
  /* offload flags */
  vnet_buffer_oflags_t oflags : 8;

  union
  {
    /* IP4/6 buffer opaque. */
    struct
    {
      /* Adjacency from destination IP address lookup [VLIB_TX].
         Adjacency from source IP address lookup [VLIB_RX].
         This gets set to ~0 until source lookup is performed. */
      u32 adj_index[VLIB_N_RX_TX];

      union
      {
	struct
	{
	  /* Flow hash value for this packet computed from IP src/dst address
	     protocol and ports. */
	  u32 flow_hash;

	  union
	  {
	    /* next protocol */
	    u32 save_protocol;

	    /* Hint for transport protocols */
	    u32 fib_index;
	  };

	  /* Rewrite length */
	  u8 save_rewrite_length;

	  union
	  {
	    /* sw_if_index of the local interface the buffer was received on
	     * - if hitting a DPO_RECEIVE - it is set in ip[46]-receive.
	     * This is ~0 if the dpo is not a receive dpo, or if the
	     * interface is not specified (e.g. route add via local) */
	    u32 rx_sw_if_index;

	    /* MFIB RPF ID */
	    u32 rpf_id;
	  };
	};

	/* ICMP */
	struct
	{
	  u8 type;
	  u8 code;
	  u32 data;
	} icmp;

	/* reassembly */
	union
	{
	  /* group input/output to simplify the code, this way
	   * we can handoff while keeping input variables intact */
	  struct
	  {
	    /* input variables */
	    struct
	    {
	      u32 next_index;	/* index of next node - used by custom apps */
	      u32 error_next_index;	/* index of next node if error - used by custom apps */
	    };
	    /* handoff variables */
	    struct
	    {
	      u16 owner_thread_index;
	    };
	  };
	  /* output variables */
	  struct
	  {
	    union
	    {
	      /* shallow virtual reassembly output variables */
	      struct
	      {
		u16 l4_src_port;	/* tcp/udp/icmp src port */
		u16 l4_dst_port;	/* tcp/udp/icmp dst port */
		u32 tcp_ack_number;
		u8 save_rewrite_length;
		u8 ip_proto;	/* protocol in ip header */
		u8 icmp_type_or_tcp_flags;
		u8 is_non_first_fragment : 1;
		u8 l4_layer_truncated : 7;
		u32 tcp_seq_number;
	      };
	      /* full reassembly output variables */
	      struct
	      {
		u16 estimated_mtu;	/* estimated MTU calculated during reassembly */
	      };
	    };
	  };
	  /* internal variables used during reassembly */
	  struct
	  {
	    u16 fragment_first;
	    u16 fragment_last;
	    u16 range_first;
	    u16 range_last;
	    u32 next_range_bi;
	    u16 ip6_frag_hdr_offset;
	  };
	} reass;
      };
    } ip;

    /*
     * MPLS:
     * data copied from the MPLS header that was popped from the packet
     * during the look-up.
     */
    struct
    {
      /* do not overlay w/ ip.adj_index[0,1] nor flow hash */
      u32 pad[VLIB_N_RX_TX + 1];
      u8 ttl;
      u8 exp;
      u8 first;
      u8 pyld_proto:3;		/* dpo_proto_t */
      u8 rsvd:5;
      /* Rewrite length */
      u8 save_rewrite_length;
      /* Save the mpls header length including all label stack */
      u8 mpls_hdr_length;
      /*
       * BIER - the number of bytes in the header.
       *  the len field in the header is not authoritative. It's the
       * value in the table that counts.
       */
      struct
      {
	u8 n_bytes;
      } bier;
    } mpls;

    /* l2 bridging path, only valid there */
    struct opaque_l2
    {
      u32 feature_bitmap;
      u16 bd_index;		/* bridge-domain index */
      u16 l2fib_sn;		/* l2fib bd/int seq_num */
      u8 l2_len;		/* ethernet header length */
      u8 shg;			/* split-horizon group */
      u8 bd_age;		/* aging enabled */
    } l2;

    /* l2tpv3 softwire encap, only valid there */
    struct
    {
      u32 pad[4];		/* do not overlay w/ ip.adj_index[0,1] */
      u8 next_index;
      u32 session_index;
    } l2t;

    /* L2 classify */
    struct
    {
      u32 pad[4]; /* do not overlay w/ ip.fib_index nor l2 */
      union
      {
	u32 table_index;
	u32 opaque_index;
      };
      u32 hash;
    } l2_classify;

    /* vnet policer */
    struct
    {
      u32 pad[8 - VLIB_N_RX_TX - 1];	/* to end of opaque */
      u32 index;
    } policer;

    /* interface output features */
    struct
    {
      /* don't overlap the adjcencies nor flow-hash */
      u32 __pad[3];
      u32 sad_index;
      u32 protect_index;
      u16 thread_index;
    } ipsec;

    /* MAP */
    struct
    {
      u16 mtu;
    } map;

    /* MAP-T */
    struct
    {
      u32 map_domain_index;
      struct
      {
	u32 saddr, daddr;
	u16 frag_offset;	//Fragmentation header offset
	u16 l4_offset;		//L4 header overall offset
	u8 l4_protocol;		//The final protocol number
      } v6;			//Used by ip6_map_t only
      u16 checksum_offset;	//L4 checksum overall offset
      u16 mtu;			//Exit MTU
    } map_t;

    /* IP Fragmentation */
    struct
    {
      u32 pad[2];		/* do not overlay w/ ip.adj_index[0,1] */
      u16 mtu;
      u8 next_index;
      u8 flags;			//See ip_frag.h
    } ip_frag;

    /* COP - configurable junk filter(s) */
    struct
    {
      /* Current configuration index. */
      u32 current_config_index;
    } cop;

    /* LISP */
    struct
    {
      /* overlay address family */
      u16 overlay_afi;
    } lisp;

    /* TCP */
    struct
    {
      u32 connection_index;
      union
      {
	u32 seq_number;
	u32 next_node_opaque;
      };
      u32 seq_end;
      u32 ack_number;
      u16 hdr_offset;		/**< offset relative to ip hdr */
      u16 data_offset;		/**< offset relative to ip hdr */
      u16 data_len;		/**< data len */
      u8 flags;
    } tcp;

    /* SNAT */
    struct
    {
      u32 flags;
      u32 required_thread_index;
    } snat;

    u32 unused[6];
  };
} vnet_buffer_opaque_t;

#define VNET_REWRITE_TOTAL_BYTES 128
STATIC_ASSERT (VNET_REWRITE_TOTAL_BYTES <= VLIB_BUFFER_PRE_DATA_SIZE,
	       "VNET_REWRITE_TOTAL_BYTES too big");

STATIC_ASSERT (STRUCT_SIZE_OF (vnet_buffer_opaque_t, ip.save_rewrite_length)
	       == STRUCT_SIZE_OF (vnet_buffer_opaque_t,
				  ip.reass.save_rewrite_length)
	       && STRUCT_SIZE_OF (vnet_buffer_opaque_t,
				  ip.reass.save_rewrite_length) ==
	       STRUCT_SIZE_OF (vnet_buffer_opaque_t, mpls.save_rewrite_length)
	       && STRUCT_SIZE_OF (vnet_buffer_opaque_t,
				  mpls.save_rewrite_length) == 1
	       && VNET_REWRITE_TOTAL_BYTES < UINT8_MAX,
	       "save_rewrite_length member must be able to hold the max value of rewrite length");

STATIC_ASSERT (STRUCT_OFFSET_OF (vnet_buffer_opaque_t, ip.save_rewrite_length)
	       == STRUCT_OFFSET_OF (vnet_buffer_opaque_t,
				    ip.reass.save_rewrite_length)
	       && STRUCT_OFFSET_OF (vnet_buffer_opaque_t,
				    mpls.save_rewrite_length) ==
	       STRUCT_OFFSET_OF (vnet_buffer_opaque_t,
				 ip.reass.save_rewrite_length),
	       "save_rewrite_length must be aligned so that reass doesn't overwrite it");

/*
 * The opaque field of the vlib_buffer_t is interpreted as a
 * vnet_buffer_opaque_t. Hence it should be big enough to accommodate one.
 */
STATIC_ASSERT (sizeof (vnet_buffer_opaque_t) <=
	       STRUCT_SIZE_OF (vlib_buffer_t, opaque),
	       "VNET buffer meta-data too large for vlib_buffer");

#define vnet_buffer(b) ((vnet_buffer_opaque_t *) (b)->opaque)

/* Full cache line (64 bytes) of additional space */
typedef struct
{
  /**
   * QoS marking data that needs to persist from the recording nodes
   * (nominally in the ingress path) to the marking node (in the
   * egress path)
   */
  struct
  {
    u8 bits;
    u8 source;
  } qos;

  u8 loop_counter;

  /* SPI  */
  struct
  {
      u8  cached_session_thread;
      u32 cached_session_index;
  } __attribute__ ((packed)) spi;

  /**
   * The L4 payload size set on input on GSO enabled interfaces
   * when we receive a GSO packet (a chain of buffers with the first one
   * having GSO bit set), and needs to persist all the way to the interface-output,
   * in case the egress interface is not GSO-enabled - then we need to perform
   * the segmentation, and use this value to cut the payload appropriately.
   */
  struct
  {
    u16 gso_size;
    /* size of L4 prototol header */
    u16 gso_l4_hdr_sz;
    i16 outer_l3_hdr_offset;
    i16 outer_l4_hdr_offset;
  };

  struct
  {
    u32 arc_next;
    union
    {
      u32 cached_session_index;
      u32 cached_dst_nat_session_index;
    };
  } nat;

  union {
  struct{
  u32 l2_rx_sw_if_index; /* store the orignal if index when bvi */
  u32 tc_index; /* store the traffic class index*/
  };

  u32 unused[8];
  };
} vnet_buffer_opaque2_t;

#define vnet_buffer2(b) ((vnet_buffer_opaque2_t *) (b)->opaque2)

/*
 * The opaque2 field of the vlib_buffer_t is interpreted as a
 * vnet_buffer_opaque2_t. Hence it should be big enough to accommodate one.
 */
STATIC_ASSERT (sizeof (vnet_buffer_opaque2_t) ==
		 STRUCT_SIZE_OF (vlib_buffer_t, opaque2),
	       "VNET buffer opaque2 meta-data too large for vlib_buffer");

#define gso_mtu_sz(b) (vnet_buffer2(b)->gso_size + \
                       vnet_buffer2(b)->gso_l4_hdr_sz + \
                       vnet_buffer(b)->l4_hdr_offset - \
                       vnet_buffer (b)->l3_hdr_offset)

format_function_t format_vnet_buffer_no_chain;
format_function_t format_vnet_buffer;
format_function_t format_vnet_buffer_offload;
format_function_t format_vnet_buffer_flags;
format_function_t format_vnet_buffer_opaque;
format_function_t format_vnet_buffer_opaque2;

static_always_inline void
vnet_buffer_offload_flags_set (vlib_buffer_t *b, vnet_buffer_oflags_t oflags)
{
  if (b->flags & VNET_BUFFER_F_OFFLOAD)
    {
      /* add a flag to existing offload */
      vnet_buffer (b)->oflags |= oflags;
    }
  else
    {
      /* no offload yet: reset offload flags to new value */
      vnet_buffer (b)->oflags = oflags;
      b->flags |= VNET_BUFFER_F_OFFLOAD;
    }
}

static_always_inline void
vnet_buffer_offload_flags_clear (vlib_buffer_t *b, vnet_buffer_oflags_t oflags)
{
  vnet_buffer (b)->oflags &= ~oflags;
  if (0 == vnet_buffer (b)->oflags)
    b->flags &= ~VNET_BUFFER_F_OFFLOAD;
}

#endif /* included_vnet_buffer_h */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
