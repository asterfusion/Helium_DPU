#include <vlib/vlib.h>
#include <vnet/ethernet/ethernet.h>

#define foreach_dsa_input_next		\
    _ (ETHERNET_INPUT, "ethernet-input") \
    _(ERROR_DROP, "error-drop")

typedef enum
{
#define _(s,n) DSA_INPUT_NEXT_##s,
    foreach_dsa_input_next
#undef _
    DSA_INPUT_N_NEXT,
} dsa_input_next_t;

#define foreach_dsa_error                \
    _(DSA_INPUT, "dsa input packets") \
    _(TYPE_ERROR, "dsa input recv non-dsa packets")

typedef enum
{
#define _(sym,str) DSA_ERROR_##sym,
    foreach_dsa_error
#undef _
    DSA_N_ERROR,
} dsa_error_t;

static char *dsa_error_strings[] = {
#define _(sym,string) string,
    foreach_dsa_error
#undef _
};
#if 0
enum {
	DSA_TAG_TO_CPU,
	DSA_TAG_FROM_CPU,
	DSA_TAG_TO_SNIFFER,
	DSA_TAG_FORWARD
};

typedef union dsa_header {
    struct {
#ifdef CPU_BIG_ENDIAN
        uint32_t cmd        : 2;    /* [31:30]
                                     * 0: TO_CPU_TAG
                                     * 1: FROM_CPU_TAG
                                     * 2: TO_SNIFFER_TAG
                                     * 3: FORWARD_TAG */
        uint32_t T          : 1;    /* [29]
                                     * 0: frame recieved(or to egress) untag
                                     * 1: frame recieved(or to egress) tagged */	 
        uint32_t dev        : 5;    /* [28:24] */
        uint32_t port       : 5;    /* [23:19] */
        uint32_t R2         : 1;    /* [18]
                                     * R: 0 or 1.
                                     * W: must be 0. */
        uint32_t R1         : 1;    /* [17] */			
        uint32_t C          : 1;    /* [16] Frame's CFI */

        uint32_t prio       : 3;    /* [15:13] */
        uint32_t R0         : 1;    /* [12] code=[R2:R1:R0] while cmd=TO_CPU_TAG */
        uint32_t vlan       : 12;   /* [11:00] */
        uint8_t	 eh[];              /* extend headr, 4 bytes. */
#else
        uint8_t dev         : 5;    /* [28:24] */
        uint8_t T           : 1;    /* [29]
                                     * 0: frame recieved(or to egress) untag
                                     * 1: frame recieved(or to egress) tagged */	 
        uint8_t cmd         : 2;    /* [31:30]
                                     * 0: TO_CPU_TAG
                                     * 1: FROM_CPU_TAG
                                     * 2: TO_SNIFFER_TAG
                                     * 3: FORWARD_TAG */

        uint8_t C           : 1;    /* [16] Frame's CFI */
        uint8_t R1          : 1;    /* [17] */			
        uint8_t R2          : 1;    /* [18]
                                     * R: 0 or 1.
                                     * W: must be 0. */
        uint8_t port        : 5;    /* [23:19] */

        uint8_t vlan_up4    : 4;	/* [11:00] */
        uint8_t R0          : 1;	/* [12] code=[R2:R1:R0] while cmd=TO_CPU_TAG */
        uint8_t prio        : 3;	/* [15:13] */

        uint8_t vlan_low8   : 8;	/* [11:00] */
        uint8_t	 eh[];              /* extend headr, 4 bytes. */
#endif
    };
    uint32_t dsa;
}dsa_header_t;

typedef struct dsa_eth_header {
    uint8_t dst_address[6];
    uint8_t src_address[6];
    dsa_header_t dsah;
    uint16_t type;
}dsa_eth_header_t;
#endif

static uint8_t dsa_output_index[8] = {4, 5, 6, 7, 0, 1, 2, 3};
u8 g_dsa_port_start = 0;

int dsa_process(vlib_buffer_t *v_buf)
{
    dsa_eth_header_t *dsa_eth_header = vlib_buffer_get_current(v_buf);
   
    if (dsa_eth_header->dsah.cmd != DSA_TAG_FORWARD)
    {
        return 1;
    }

    else if (dsa_eth_header->dsah.port > 0 && dsa_eth_header->dsah.port < 9)
    {
        vnet_buffer (v_buf)->sw_if_index[VLIB_RX] = dsa_output_index[dsa_eth_header->dsah.port - 1] + g_dsa_port_start;
    }
    else
    {
        return 1;
    }

    uint32_t *u32_array = (uint32_t *)dsa_eth_header;
    u32_array[3] = u32_array[2];
    u32_array[2] = u32_array[1];
    u32_array[1] = u32_array[0];

    vlib_buffer_advance(v_buf, 4);

    return 0;
}

VLIB_NODE_FN (dsa_input_node) (vlib_main_t * vm,
				    vlib_node_runtime_t * node,
				    vlib_frame_t * frame)
{
  u32 n_left_from, *from, *to_next;
  dsa_input_next_t next_index;

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;	/* number of packets to process */
  next_index = node->cached_next_index;

  while (n_left_from > 0)
    {
      u32 n_left_to_next;
      u32 err_count = 0;
      /* get space to enqueue frame to graph node "next_index" */
      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      while (n_left_from >= 8 && n_left_to_next >= 4)
   	{
          int ret = 0;
          u32 bi0, bi1, bi2, bi3;
          vlib_buffer_t *b0, *b1, *b2, *b3;
          u32 next0 = DSA_INPUT_NEXT_ETHERNET_INPUT;
          u32 next1 = DSA_INPUT_NEXT_ETHERNET_INPUT;
          u32 next2 = DSA_INPUT_NEXT_ETHERNET_INPUT;
          u32 next3 = DSA_INPUT_NEXT_ETHERNET_INPUT;
   
   	  /* Prefetch next iteration. */
   	  {
   	    vlib_buffer_t *p4, *p5, *p6, *p7;
   
            p4 = vlib_get_buffer (vm, from[4]);
            p5 = vlib_get_buffer (vm, from[5]);
            p6 = vlib_get_buffer (vm, from[6]);
            p7 = vlib_get_buffer (vm, from[7]);
   
            /* Prefetch the buffer header and packet for the N+2 loop iteration */
            vlib_prefetch_buffer_header (p4, LOAD);
            vlib_prefetch_buffer_header (p5, LOAD);
            vlib_prefetch_buffer_header (p6, LOAD);
            vlib_prefetch_buffer_header (p7, LOAD);
   
            CLIB_PREFETCH (p4->data, CLIB_CACHE_LINE_BYTES, STORE);
            CLIB_PREFETCH (p5->data, CLIB_CACHE_LINE_BYTES, STORE);
            CLIB_PREFETCH (p6->data, CLIB_CACHE_LINE_BYTES, STORE);
            CLIB_PREFETCH (p7->data, CLIB_CACHE_LINE_BYTES, STORE);
          }
   
   	  /* speculatively enqueue b0 and b1 to the current next frame */
   	  /* bi is "buffer index", b is pointer to the buffer */
          to_next[0] = bi0 = from[0];
          to_next[1] = bi1 = from[1];
          to_next[2] = bi2 = from[2];
          to_next[3] = bi3 = from[3];
          from += 4;
          to_next += 4;
          n_left_from -= 4;
          n_left_to_next -= 4;
   
          b0 = vlib_get_buffer (vm, bi0);
          b1 = vlib_get_buffer (vm, bi1);
          b2 = vlib_get_buffer (vm, bi2);
          b3 = vlib_get_buffer (vm, bi3);

          if (1 == vnet_buffer (b0)->sw_if_index[VLIB_RX])
          {
              ret = dsa_process(b0);
              if (ret)
              {
                  next0 = DSA_INPUT_NEXT_ERROR_DROP;
                  err_count++;
              }
          }
          if (1 == vnet_buffer (b1)->sw_if_index[VLIB_RX])
	  {
              ret = dsa_process(b1);
              if (ret)
              {
                  next1 = DSA_INPUT_NEXT_ERROR_DROP;
                  err_count++;
              }
          }
          if (1 == vnet_buffer (b2)->sw_if_index[VLIB_RX])
          {
              ret = dsa_process(b2);
              if (ret)
              {
                  next2 = DSA_INPUT_NEXT_ERROR_DROP;
                  err_count++;
              }
          }
          if (1 == vnet_buffer (b3)->sw_if_index[VLIB_RX])
          {
              ret = dsa_process(b3);
              if (ret)
              {
                  next3 = DSA_INPUT_NEXT_ERROR_DROP;
                  err_count++;
              }
          }
   	  
   	  /* verify speculative enqueues, maybe switch current next frame */
   	  /* if next0==next1==next_index then nothing special needs to be done */
          vlib_validate_buffer_enqueue_x4 (vm, node, next_index,
        				   to_next, n_left_to_next,
   					   bi0, bi1, bi2, bi3,
   					   next0, next1, next2, next3);
         }

        while (n_left_from > 0 && n_left_to_next > 0)
        {
          int ret = 0;
          u32 bi0;
          vlib_buffer_t *b0;
          u32 next0 = DSA_INPUT_NEXT_ETHERNET_INPUT;

          /* speculatively enqueue b0 to the current next frame */
          bi0 = from[0];
          to_next[0] = bi0;
          from += 1;
          to_next += 1;
          n_left_from -= 1;
          n_left_to_next -= 1;

          b0 = vlib_get_buffer (vm, bi0);
       


          if (1 == vnet_buffer (b0)->sw_if_index[VLIB_RX])
          {
              ret = dsa_process(b0);
              if (ret)
              {
                  next0 = DSA_INPUT_NEXT_ERROR_DROP;
                  err_count++;
              }
          }

          vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
					   to_next, n_left_to_next,
					   bi0, next0);
        }

      vlib_node_increment_counter (vm, node->node_index, DSA_ERROR_TYPE_ERROR, err_count);

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  vlib_node_increment_counter (vm, node->node_index, DSA_ERROR_DSA_INPUT, frame->n_vectors);

  return frame->n_vectors;
}


/* *INDENT-OFF* */
VLIB_REGISTER_NODE (dsa_input_node) = {
  .name = "dsa-input",
  .type = VLIB_NODE_TYPE_INTERNAL,
  /* Takes a vector of packets. */
  .vector_size = sizeof (u32),
  .scalar_size = sizeof (ethernet_input_frame_t),
  .n_errors = ARRAY_LEN(dsa_error_strings),
  .error_strings = dsa_error_strings,
  .n_next_nodes = DSA_INPUT_N_NEXT,
  .next_nodes = {
#define _(s,n) [DSA_INPUT_NEXT_##s] = n,
    foreach_dsa_input_next
#undef _
  },
};



