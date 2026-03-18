/*
 * node.c - ha_sync graph nodes
 */

#include <vlib/vlib.h>
#include <vnet/feature/feature.h>
#include <vnet/ip/ip4.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/ip-neighbor/ip_neighbor.h>

#include <ha_sync/ha_sync.h>

typedef struct
{
  u8 is_ha;
  u8 msg_type;
  u8 domain;
  u16 session_count;
  u32 seq_number;
  u32 magic;
  u32 src_ip;
} ha_sync_input_trace_t;

typedef struct
{
  ip4_address_t dst;
  u32 seq_number;
  u16 dst_port;
  u16 payload_len;
  u8 msg_type;
} ha_sync_output_trace_t;

static int
ha_sync_peer_find (ha_sync_main_t *hsm, const ip4_address_t *ip4)
{
  if (!hsm->config_ready)
    return -1;
  return hsm->peer_address.as_u32 == ip4->as_u32 ? 0 : -1;
}

static_always_inline ha_sync_session_registration_t *
ha_sync_get_registration (u32 app_type)
{
  ha_sync_main_t *hsm = &ha_sync_main;
  ha_sync_session_registration_t *reg = NULL;

  vec_foreach (reg, hsm->registrations)
  {
    if (reg->app_type == app_type)
      return reg;
  }

  clib_warning ("No registration for app type %d", app_type);
  return NULL;

}

static_always_inline void
ha_sync_prepare_udp_header (vlib_buffer_t *b, u16 payload_len,
                            const ip4_address_t *dst)
{
  ha_sync_main_t *hsm = &ha_sync_main;
  // static const u8 ha_sync_src_mac[6] = {0x02, 0x00, 0x00, 0x00, 0x00, 0x01};
  
  // ethernet_header_t *eth =
  //   (void *)((u8 *)vlib_buffer_get_current (b) -
  //            sizeof (ethernet_header_t));
  ip4_header_t *ip = (ip4_header_t *) vlib_buffer_get_current(b);
  udp_header_t *udp = (udp_header_t *) (ip + 1);

  u16 l3_len = sizeof (ip4_header_t) + sizeof (udp_header_t) + payload_len;

  // clib_memcpy_fast (eth->src_address, ha_sync_src_mac, 6);
  // clib_memset (eth->dst_address, 0, 6);
  // eth->type = clib_host_to_net_u16 (ETHERNET_TYPE_IP4);

  ip->ip_version_and_header_length = 0x45; /** ip version 4, header length 5 * 4 = 20 bytes */
  ip->tos = 0; /** type of service, default value 0 */
  ip->length = clib_host_to_net_u16 (l3_len);
  ip->fragment_id = 0; /** fragment id, default value 0 */
  ip->flags_and_fragment_offset = 0; /** flags and fragment offset, default value 0 */
  ip->ttl = 255; /** time to live, default value 255 */
  ip->protocol = IP_PROTOCOL_UDP; /** protocol number 17 */
  ip->src_address = hsm->src_address;
  ip->dst_address = *dst;
  ip->checksum = ip4_header_checksum (ip);

  udp->src_port = clib_host_to_net_u16 (hsm->src_port);
  udp->dst_port = clib_host_to_net_u16 (hsm->dst_port);
  udp->length = clib_host_to_net_u16 (payload_len + sizeof (udp_header_t));
  udp->checksum = 0;
}


#ifndef CLIB_MARCH_VARIANT
static u8 *
format_ha_sync_input_trace (u8 *s, va_list *args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  ha_sync_input_trace_t *t = va_arg (*args, ha_sync_input_trace_t *);

  s = format (s, "ha-sync-input: %s", 
              t->is_ha ? "MATCHED" : "SKIPPED (Not HA)");

  if (t->is_ha)
  {
    s = format (s, "\n    magic: 0x%08x, seq: %u, type: %u, domain: %u",
                t->magic, t->seq_number, t->msg_type, t->domain);
    
    s = format (s, "\n    src-ip: %U, sessions: %u",
                format_ip4_address, &t->src_ip,
                t->session_count);
  }
  return s;
}

static u8 *
format_ha_sync_output_trace (u8 *s, va_list *args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  ha_sync_output_trace_t *t = va_arg (*args, ha_sync_output_trace_t *);

  s = format (s, "ha-sync-output: [Type %u] -> %U:%d",
              t->msg_type,
              format_ip4_address, &t->dst,
              t->dst_port);

  s = format (s, "\n    seq: %u, payload-len: %u",
              t->seq_number, 
              t->payload_len);

  char *type_str = "UNKNOWN";
  if (t->msg_type == HA_SYNC_MSG_RESPONSE) type_str = "RESPONSE";
  else if (t->msg_type == HA_SYNC_MSG_REQUEST) type_str = "REQUEST";
  else if (t->msg_type == HA_SYNC_MSG_HELLO_RESPONSE) type_str = "HELLO-RESPONSE";
  else if (t->msg_type == HA_SYNC_MSG_HEARTBEAT) type_str = "HEARTBEAT";
  else if (t->msg_type == HA_SYNC_MSG_HELLO) type_str = "HELLO";
  
  s = format (s, " [%s]", type_str);
  return s;
}
#endif

#define foreach_ha_sync_input_error \
  _(RX, "input packets received")    \
  _(MATCH, "udp/10311 packets matched") \
  _(REQUEST, "ha_sync request packets received") \
  _(RESPONSE, "ha_sync response packets received") \
  _(HELLO, "ha_sync hello packets received") \
  _(HELLO_RESPONSE, "ha_sync hello response packets received") \
  _(HEARTBEAT, "ha_sync heartbeat packets received")

typedef enum
{
#define _(sym, str) HA_SYNC_INPUT_ERROR_##sym,
  foreach_ha_sync_input_error
#undef _
    HA_SYNC_INPUT_N_ERROR,
} ha_sync_input_error_t;

#ifndef CLIB_MARCH_VARIANT
static char *ha_sync_input_error_strings[] = {
#define _(sym, str) str,
  foreach_ha_sync_input_error
#undef _
};
#endif

typedef enum
{
  HA_SYNC_INPUT_NEXT_DROP,
  HA_SYNC_INPUT_N_NEXT,
} ha_sync_input_next_t;

static_always_inline u8
ha_sync_is_udp_10311 (vlib_buffer_t *b)
{
  ip4_header_t *ip4 = vlib_buffer_get_current (b);
  udp_header_t *udp;

  if (PREDICT_FALSE (ip4->protocol != IP_PROTOCOL_UDP))
    return 0;

  udp = ip4_next_header (ip4);
  return clib_net_to_host_u16 (udp->dst_port) == HA_SYNC_UDP_PORT;
}

#define foreach_ha_sync_output_error \
  _(TX, "output packets sent")     \
  _(NO_BUFFER, "buffer allocation failed") \
  _(POOL_MISS, "tx pool sequence not found") \
  _(NO_PEER, "peer address not configured") \
  _(TX_REQUEST_NEW, "ha_sync request packets sent (new)") \
  _(TX_REQUEST_RETX, "ha_sync request packets sent (retransmit)") \
  _(TX_RESPONSE, "ha_sync response packets sent") \
  _(TX_HELLO, "ha_sync hello packets sent") \
  _(TX_HELLO_RESPONSE, "ha_sync hello response packets sent") \
  _(TX_HEARTBEAT, "ha_sync heartbeat packets sent")

typedef enum
{
#define _(sym, str) HA_SYNC_OUTPUT_ERROR_##sym,
  foreach_ha_sync_output_error
#undef _
    HA_SYNC_OUTPUT_N_ERROR,
} ha_sync_output_error_t;

#ifndef CLIB_MARCH_VARIANT
static char *ha_sync_output_error_strings[] = {
#define _(sym, str) str,
  foreach_ha_sync_output_error
#undef _
};
#endif

VLIB_NODE_FN (ha_sync_input_worker_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  ha_sync_main_t *hsm = &ha_sync_main;
  u32 *from, *to_next;
  u32 n_left_from, n_left_to_next;
  u32 next_index = node->cached_next_index;
  u32 n_match = 0;

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;

  while (n_left_from > 0)
  {
    vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

    while (n_left_from > 0 && n_left_to_next > 0)
    {
      u32 bi0;
      vlib_buffer_t *b0;
      ip4_header_t *ip0;
      udp_header_t *udp0;
      ha_sync_packet_header_t *h0;
      u32 next0;
      u8 is_ha_packet = 0;
      
      bi0 = to_next[0] = from[0];
      from += 1;
      to_next += 1;
      n_left_from -= 1;
      n_left_to_next -= 1;

      b0 = vlib_get_buffer (vm, bi0);

      vnet_feature_next (&next0, b0);

      if (hsm->enabled && ha_sync_is_udp_10311 (b0))
      {
        ip0 = vlib_buffer_get_current (b0);
        udp0 = ip4_next_header (ip0);
        u32 udp_len = clib_net_to_host_u16 (udp0->length);

        if (udp_len >= (sizeof(udp_header_t) + sizeof(ha_sync_packet_header_t)))
        {
          h0 = (ha_sync_packet_header_t *) (udp0 + 1);
          u16 total_payload_len = clib_net_to_host_u16 (h0->length);
          if (PREDICT_FALSE (total_payload_len >
                             udp_len - sizeof (udp_header_t) -
                               sizeof (ha_sync_packet_header_t)))
            goto trace_and_next;

          if (clib_net_to_host_u32 (h0->magic) == HA_SYNC_MAGIC &&
                ha_sync_peer_find (hsm, &h0->src_ip) >= 0 &&
                h0->domain == hsm->domain_id)
          {
            is_ha_packet = 1;
            n_match++;
            
            /** match success, drop this packet */
            next0 = HA_SYNC_INPUT_NEXT_DROP;
              
            u8 msg_type = h0->msg_type;
            switch (msg_type)
            {
              case HA_SYNC_MSG_REQUEST: 
              {
                u8 session_count = h0->count;
                u8 *packet_end = (u8 *)h0 + sizeof(ha_sync_packet_header_t) + total_payload_len;
                ha_sync_session_header_t *session_hdr = (ha_sync_session_header_t *)((h0 + 1));
                vlib_node_increment_counter (
                  vm, node->node_index, HA_SYNC_INPUT_ERROR_REQUEST, 1);
                
                for (int i = 0; i < session_count; i++)
                {
                  // check session header boundary
                  if (PREDICT_FALSE((u8 *)session_hdr + sizeof(ha_sync_session_header_t) > packet_end))
                  {
                    clib_warning("HA_SYNC_MSG_REQUEST: Session header exceeds packet boundary");
                    break;
                  }

                  u16 session_data_len = clib_net_to_host_u16 (session_hdr->session_length);
                  u8 app_type = session_hdr->app_type;
                  u8 *session_data = (u8 *)(session_hdr + 1);
                  
                  if (PREDICT_FALSE(session_data + session_data_len > packet_end))
                  {
                    clib_warning("HA_SYNC_MSG_REQUEST: Session data exceeds packet boundary");
                    break;
                  }

                  ha_sync_session_registration_t *reg = ha_sync_get_registration (app_type);
                  if (PREDICT_FALSE(reg != NULL && reg->session_apply_cb != NULL))
                  {
                    reg->session_apply_cb((u32)app_type, reg->context, session_data, session_data_len);
                  }

                  session_hdr = (ha_sync_session_header_t *)(session_data + session_data_len);
                  if ((u8 *)session_hdr >= packet_end)
                    break;
                }

                u32 thread_index = vlib_get_thread_index ();
                ha_sync_send_response (clib_net_to_host_u32 (h0->seq_number), thread_index);
                break;
              }
              case HA_SYNC_MSG_RESPONSE:
                ha_sync_tx_pool_del_by_seq (clib_net_to_host_u32 (h0->seq_number));
                // clib_warning("HA_SYNC_MSG_RESPONSE: Sequence number %u packet received.", clib_net_to_host_u32 (h0->seq_number));
                vlib_node_increment_counter (
                  vm, node->node_index, HA_SYNC_INPUT_ERROR_RESPONSE, 1);
                break;

              case HA_SYNC_MSG_HELLO:
                vlib_node_increment_counter (
                  vm, node->node_index, HA_SYNC_INPUT_ERROR_HELLO, 1);
                if (hsm->enabled && hsm->config_ready)
                {
                  ha_sync_send_hello_response (vlib_get_thread_index ());
                  hsm->hello_retry_count = 0;
                  hsm->last_heartbeat_recv_time = vlib_time_now (vm);
                }
                break;

              case HA_SYNC_MSG_HELLO_RESPONSE:
                hsm->connection_established = 1;
                ha_sync_update_all_contexts ();
                vlib_node_increment_counter (
                  vm, node->node_index, HA_SYNC_INPUT_ERROR_HELLO_RESPONSE, 1);
                hsm->hello_retry_count = 0;
                hsm->last_heartbeat_recv_time = vlib_time_now (vm);
                ha_sync_snapshot_trigger ();
                break;

              case HA_SYNC_MSG_HEARTBEAT:
                hsm->last_heartbeat_recv_time = vlib_time_now (vm);
                vlib_node_increment_counter (
                  vm, node->node_index, HA_SYNC_INPUT_ERROR_HEARTBEAT, 1);
                break;

              default:
                next0 = HA_SYNC_INPUT_NEXT_DROP;
            }
          }
        }
      }
trace_and_next:
      // trace
      if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE) &&
                          (b0->flags & VLIB_BUFFER_IS_TRACED)))
      {
        ha_sync_input_trace_t *t = vlib_add_trace (vm, node, b0, sizeof(*t));
        t->is_ha = is_ha_packet;
        if (is_ha_packet)
        {
          t->msg_type = h0->msg_type;
          t->domain = h0->domain;
          t->session_count = h0->count;
          t->seq_number = clib_net_to_host_u32 (h0->seq_number);
          t->magic = clib_net_to_host_u32 (h0->magic);
          t->src_ip = h0->src_ip.as_u32;
        }
        else
        {
          t->msg_type = 0;
        }
      }
      vlib_validate_buffer_enqueue_x1 (vm, node, next_index, to_next, n_left_to_next, bi0, next0);
    }
    vlib_put_next_frame (vm, node, next_index, n_left_to_next);
  }
  /** increment error counters */
  vlib_node_increment_counter (vm, node->node_index, HA_SYNC_INPUT_ERROR_RX, frame->n_vectors);
  vlib_node_increment_counter (vm, node->node_index, HA_SYNC_INPUT_ERROR_MATCH, n_match);
  return frame->n_vectors;
}

VLIB_NODE_FN (ha_sync_output_worker_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  ha_sync_main_t *hsm = &ha_sync_main;
  u32 thread_index = vm->thread_index;
  ha_sync_per_thread_buffer_t *ptb;
  CLIB_UNUSED (vlib_frame_t * _frame) = frame;

  if (!hsm->enabled)
    return 0;

  if (!hsm->config_ready)
  {
    vlib_node_increment_counter (vm, node->node_index,
                                  HA_SYNC_OUTPUT_ERROR_NO_PEER, 1);
    return 0;
  }

  if (thread_index >= vec_len (hsm->per_thread_buffers))
    return 0;
  ptb = &hsm->per_thread_buffers[thread_index];
  
  /** calculate total number of packets to send */
  u32 n_fast = clib_fifo_elts (ptb->fast_msg_queue);
  u32 n_pending = clib_fifo_elts (ptb->pending_fifo);
  u32 n_total = n_fast + n_pending;

  if (n_total == 0)
    return 0;

  if (n_total > VLIB_FRAME_SIZE)
  {
    n_total = VLIB_FRAME_SIZE;
  }

  /** allocate buffer indices */
  u32 bi[VLIB_FRAME_SIZE];
  u32 n_alloc = vlib_buffer_alloc (vm, bi, n_total);
  if (PREDICT_FALSE (n_alloc == 0))
  {
    vlib_node_increment_counter (vm, node->node_index,
                                  HA_SYNC_OUTPUT_ERROR_NO_BUFFER, n_total);
    return 0;
  }
  
  u32 bi_to_send[VLIB_FRAME_SIZE];
  u32 sent = 0;
  u32 b_idx = 0;

  while (b_idx < n_alloc && clib_fifo_elts (ptb->fast_msg_queue) > 0)
  {
    ha_sync_fast_msg_t fmsg;
    clib_fifo_sub1 (ptb->fast_msg_queue, fmsg);
    vlib_buffer_t *b = vlib_get_buffer (vm, bi[b_idx]);

    /** init buffer */
    b->current_data = 0;
    b->current_length = 0;
    b->flags |= VNET_BUFFER_F_LOCALLY_ORIGINATED;

    u16 l3_l4_hdr_size = sizeof (ip4_header_t) + sizeof (udp_header_t);
    ha_sync_packet_header_t *h =
      (void *)((u8 *)vlib_buffer_get_current (b) + l3_l4_hdr_size);
    h->magic = clib_host_to_net_u32 (HA_SYNC_MAGIC);
    h->src_ip = hsm->src_address;
    h->domain = hsm->domain_id;
    h->msg_type = fmsg.msg_type;
    h->length = 0;
    h->seq_number = clib_host_to_net_u32 (fmsg.seq_number);
    h->count = 0;
    memset (h->reserve, 0, sizeof (h->reserve));

    u16 payload_len = sizeof (ha_sync_packet_header_t);
    b->current_length = l3_l4_hdr_size + payload_len;
    /** prepare udp header */
    ha_sync_prepare_udp_header (b, payload_len, &hsm->peer_address);
    vnet_buffer (b)->sw_if_index[VLIB_TX] = hsm->fib_index;
    vnet_buffer (b)->sw_if_index[VLIB_RX] = hsm->sw_if_index;

    bi_to_send[sent++] = bi[b_idx++];
    if (fmsg.msg_type == HA_SYNC_MSG_RESPONSE)
      vlib_node_increment_counter (vm, node->node_index,
                                   HA_SYNC_OUTPUT_ERROR_TX_RESPONSE, 1);
    else if (fmsg.msg_type == HA_SYNC_MSG_HELLO)
      vlib_node_increment_counter (vm, node->node_index,
                                   HA_SYNC_OUTPUT_ERROR_TX_HELLO, 1);
    else if (fmsg.msg_type == HA_SYNC_MSG_HELLO_RESPONSE)
      vlib_node_increment_counter (vm, node->node_index,
                                   HA_SYNC_OUTPUT_ERROR_TX_HELLO_RESPONSE, 1);
    else if (fmsg.msg_type == HA_SYNC_MSG_HEARTBEAT)
      vlib_node_increment_counter (vm, node->node_index,
                                   HA_SYNC_OUTPUT_ERROR_TX_HEARTBEAT, 1);

    if (PREDICT_FALSE (b->flags & VLIB_BUFFER_IS_TRACED))
    {
      ha_sync_output_trace_t *t = vlib_add_trace (vm, node, b, sizeof(*t));
      t->msg_type = fmsg.msg_type;
      t->dst = hsm->peer_address;
      t->dst_port = hsm->dst_port;
      t->payload_len = 0;
      t->seq_number = fmsg.seq_number;
    }

  }

  while (b_idx < n_alloc && clib_fifo_elts (ptb->pending_fifo) > 0)
  {
    u32 seq;
    clib_fifo_sub1 (ptb->pending_fifo, seq);

    ha_sync_tx_packet_t pkt_info;
    if (PREDICT_FALSE (!ha_sync_tx_pool_get_by_seq (seq, &pkt_info)))
    {
      vlib_buffer_free_one (vm, bi[b_idx]);
      b_idx++;
      vlib_node_increment_counter (vm, node->node_index,
                                   HA_SYNC_OUTPUT_ERROR_POOL_MISS, 1);
      continue;
    }
    if (PREDICT_FALSE (pkt_info.length > 0 && !pkt_info.payload))
    {
      vlib_buffer_free_one (vm, bi[b_idx]);
      b_idx++;
      vlib_node_increment_counter (vm, node->node_index,
                                   HA_SYNC_OUTPUT_ERROR_POOL_MISS, 1);
      continue;
    }

    vlib_buffer_t *b = vlib_get_buffer (vm, bi[b_idx]);
    b->current_data = 0;
    b->current_length = 0;
    b->flags |= VNET_BUFFER_F_LOCALLY_ORIGINATED;

    u16 l3_l4_hdr_size = sizeof (ip4_header_t) + sizeof (udp_header_t);

    /** 1. prepare ha sync packet header */
    ha_sync_packet_header_t *h = (void *)((u8 *)vlib_buffer_get_current(b) + l3_l4_hdr_size);
    h->magic = clib_host_to_net_u32 (HA_SYNC_MAGIC);
    h->src_ip = hsm->src_address;
    h->domain = hsm->domain_id;
    h->msg_type = pkt_info.msg_type;
    h->length = clib_host_to_net_u16 (pkt_info.length);
    h->seq_number = clib_host_to_net_u32 (pkt_info.seq_number);
    h->count = pkt_info.session_count;
    memset (h->reserve, 0, sizeof (h->reserve));

    /** 2. copy payload */
    if (pkt_info.length > 0 && pkt_info.payload)
      clib_memcpy (h + 1, pkt_info.payload, pkt_info.length);
    u16 payload_len = sizeof (ha_sync_packet_header_t) + pkt_info.length;
    b->current_length = l3_l4_hdr_size + payload_len;
    /** 3. prepare udp header */
    ha_sync_prepare_udp_header (b, payload_len, &hsm->peer_address);

    /** 4. set send parameters */
    vnet_buffer (b)->sw_if_index[VLIB_TX] = hsm->fib_index;
    vnet_buffer (b)->sw_if_index[VLIB_RX] = hsm->sw_if_index;

    bi_to_send[sent++] = bi[b_idx++];
    if (pkt_info.msg_type == HA_SYNC_MSG_REQUEST)
      {
        vlib_node_increment_counter (vm, node->node_index,
                                     (pkt_info.retry_count > 0) ?
                                       HA_SYNC_OUTPUT_ERROR_TX_REQUEST_RETX :
                                       HA_SYNC_OUTPUT_ERROR_TX_REQUEST_NEW,
                                     1);
      }

    if (PREDICT_FALSE (b->flags & VLIB_BUFFER_IS_TRACED))
    {
      ha_sync_output_trace_t *t = vlib_add_trace (vm, node, b, sizeof(*t));
      t->msg_type = pkt_info.msg_type;
      t->dst = hsm->peer_address;
      t->dst_port = hsm->dst_port;
      t->payload_len = pkt_info.length;
      t->seq_number = pkt_info.seq_number;
    }

    if (pkt_info.payload)
      vec_free (pkt_info.payload);

  }

  /** 5. batch configure and submit */
  if (PREDICT_TRUE (sent > 0))
  {
    vlib_frame_t *f = vlib_get_frame_to_node (vm, ip4_lookup_node.index);
    u32 *to_next = vlib_frame_vector_args (f);
    clib_memcpy_fast (to_next, bi_to_send, sent * sizeof (u32));
    f->n_vectors = sent;
    vlib_put_frame_to_node (vm, ip4_lookup_node.index, f);
  }

  if (PREDICT_FALSE (b_idx < n_alloc))
  {
    vlib_buffer_free (vm, bi + b_idx, n_alloc - b_idx);
  }

  vlib_node_increment_counter (vm, node->node_index, 
                               HA_SYNC_OUTPUT_ERROR_TX, sent);

  return sent;
}

VLIB_NODE_FN (ha_sync_snapshot_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  ha_sync_main_t *hsm = &ha_sync_main;
  ha_sync_session_registration_t *reg;
  u32 thread_index = vm->thread_index;
  CLIB_UNUSED (vlib_node_runtime_t * _node) = node;
  CLIB_UNUSED (vlib_frame_t * _frame) = frame;

  if (!hsm->enabled || !hsm->connection_established)
    return 0;

  vec_foreach (reg, hsm->registrations)
    {
      if (!reg->snapshot_send_cb)
        continue;
      if (reg->snapshot_mode == HA_SYNC_SNAPSHOT_MODE_PER_THREAD)
        reg->snapshot_send_cb (reg->app_type, reg->context, thread_index);
      else if (thread_index == 0)
        reg->snapshot_send_cb (reg->app_type, reg->context, 0);
    }

  return 0;
}
VLIB_NODE_FN (ha_sync_process_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  CLIB_UNUSED (vlib_main_t * _vm) = vm;
  CLIB_UNUSED (vlib_node_runtime_t * _node) = node;
  CLIB_UNUSED (vlib_frame_t * _frame) = frame;

  f64 timeout = HA_SYNC_DEFAULT_INTERVAL_SEC;
  ha_sync_main_t *hsm = &ha_sync_main;
  f64 now;

  vlib_process_wait_for_event_or_clock (vm, timeout);
  while (1)
  {
    if (hsm->enabled)
    {
      now = vlib_time_now (vm);

      if (hsm->config_ready && !hsm->connection_established)
      {
        if (now >= hsm->next_hello_time)
        {
          if (hsm->sw_if_index_is_set)
          {
            ip46_address_t dst;
            dst.ip4 = hsm->peer_address;
            ip_neighbor_probe_dst (hsm->sw_if_index,
                                   vlib_get_thread_index (),
                                   AF_IP4, &dst);
          }
          ha_sync_send_hello (vlib_get_thread_index ());
          hsm->hello_retry_count++;
          hsm->next_hello_time = now + HA_SYNC_HELLO_RETRY_INTERVAL_SEC;
        }
      }

      if (hsm->connection_established > 0 && hsm->config_ready)
      {
        /** Check if it's time to send a heartbeat. */
        if (now >= (hsm->last_heartbeat_send_time + hsm->heartbeat_interval_sec))
        {
          u32 thread_index = vlib_get_thread_index ();
          ha_sync_per_thread_buffer_t *ptb = &hsm->per_thread_buffers[thread_index];

          ha_sync_fast_msg_t fmsg;
          fmsg.msg_type = HA_SYNC_MSG_HEARTBEAT;
          fmsg.seq_number = clib_atomic_add_fetch(&hsm->global_seq_number, 1);
          
          clib_fifo_add1(ptb->fast_msg_queue, fmsg);
          ha_sync_wake_output_thread (thread_index);
          hsm->last_heartbeat_send_time = now;
          // clib_warning ("ha_sync: send heartbeat seq_number %d", fmsg.seq_number);
        }

        if (now > (hsm->last_heartbeat_recv_time +
                   (hsm->heartbeat_interval_sec * hsm->heartbeat_max_fail_counts)))
        {
          hsm->connection_established = 0; 
          ha_sync_update_all_contexts ();
          hsm->hello_retry_count = 0;
          hsm->next_hello_time = now;
          hsm->snapshot_trigger_pending = 0;
          ha_sync_reset_runtime_state ();
        }

        /** Per-thread flush checks are handled inside ha_sync_timer_node. */
      }
    }

    /** drive per-thread timer nodes (flush/retransmit) */
    if (hsm->enabled && hsm->connection_established)
      {
        u32 ti;
        u32 n_threads = vlib_get_n_threads ();
        for (ti = 0; ti < n_threads; ti++)
          vlib_node_set_interrupt_pending (vlib_get_main_by_index (ti),
                                           ha_sync_timer_node.index);
      }

    /** Run one-shot snapshot callback when triggered. */
    if (hsm->enabled && hsm->snapshot_trigger_pending)
      {
        u32 ti;
        u32 n_threads = vlib_get_n_threads ();
        hsm->snapshot_trigger_pending = 0;
        for (ti = 0; ti < n_threads; ti++)
          vlib_node_set_interrupt_pending (vlib_get_main_by_index (ti),
                                           ha_sync_snapshot_node.index);
      }

    vlib_process_wait_for_event_or_clock (vm, timeout);
  }


  return 0;
}


VLIB_NODE_FN (ha_sync_timer_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{ 
  u32 thread_index = vm->thread_index;
  ha_sync_main_t *hsm = &ha_sync_main;
  ha_sync_per_thread_buffer_t *ptb = &hsm->per_thread_buffers[thread_index];

  f64 now = vlib_time_now (vm);

  if (ptb->session_count > 0 && (now - ptb->last_flush_time) >= HA_SYNC_THREAD_BUFFER_FLUSH_INTERVAL_SEC)
  {
    // clib_warning ("ha_sync in timer node : flush thread buffer %d", thread_index);
    ha_sync_per_thread_buffer_flush (thread_index);
  }

  if (thread_index == 1 && hsm->enabled && hsm->connection_established)
  {
    u32 *i;
    u32 num_expired = 0;
    u32 pool_index;
    u32 seq;

    hsm->timer_expired_vec =
      tw_timer_expire_timers_vec_16t_2w_512sl (&hsm->timer_wheel, now,
                                               hsm->timer_expired_vec);
    // clib_warning ("ha_sync in timer node : expire %d timers",
    //               vec_len (hsm->timer_expired_vec));
    vec_foreach (i, hsm->timer_expired_vec)
    {
      // clib_warning ("ha_sync in timer node : expired timer %d", *i);
      pool_index = (*i) & ((1 << (32 - LOG2_TW_TIMERS_PER_OBJECT)) - 1);

      clib_spinlock_lock (&hsm->tx_lock);
      if (pool_is_free_index (hsm->ha_sync_tx_pool, pool_index))
      {
        clib_spinlock_unlock (&hsm->tx_lock);
        num_expired++;
        continue;
      }

      ha_sync_tx_packet_t *req = pool_elt_at_index (hsm->ha_sync_tx_pool, pool_index);
      req->timer_handle = ~0;
      seq = req->seq_number;

      if (req->retry_count >= hsm->retransmit_times)
      {
        clib_warning ("ha_sync in timer node : retransmit seq_number %d timeout, retry_count %d", seq, req->retry_count);
        clib_spinlock_unlock (&hsm->tx_lock);
        ha_sync_tx_pool_del_by_seq (seq);
        num_expired++;
        continue;
      }

      req->retry_count++;

      // restart timer
      u32 ticks = (u32)(hsm->retransmit_interval / hsm->timer_wheel.timer_interval);
      if (ticks < 1)
        ticks = 1;
      req->timer_handle = tw_timer_start_16t_2w_512sl (&hsm->timer_wheel, pool_index, 0, ticks);
      clib_spinlock_unlock (&hsm->tx_lock);

      if (thread_index < vec_len (hsm->per_thread_buffers))
      {
        ha_sync_per_thread_buffer_t *rptb = &hsm->per_thread_buffers[thread_index];
        clib_fifo_add1 (rptb->pending_fifo, seq);
        ha_sync_wake_output_thread (thread_index);
      }

      num_expired++;
    }

    if (num_expired)
      vec_delete (hsm->timer_expired_vec, num_expired, 0);
  }

  return 0;
}

/* *INDENT-OFF* */
#ifndef CLIB_MARCH_VARIANT
VLIB_REGISTER_NODE (ha_sync_input_worker_node) = {
  .name = "ha-sync-input-worker",
  .vector_size = sizeof (u32),
  .format_trace = format_ha_sync_input_trace,
  .flags = VLIB_NODE_FLAG_TRACE_SUPPORTED,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN (ha_sync_input_error_strings),
  .error_strings = ha_sync_input_error_strings,
  .n_next_nodes = HA_SYNC_INPUT_N_NEXT,
  .next_nodes = {
    [HA_SYNC_INPUT_NEXT_DROP] = "error-drop",
  },
};

VLIB_REGISTER_NODE (ha_sync_output_worker_node) = {
  .name = "ha-sync-output-worker",
  .vector_size = sizeof (u32),
  .format_trace = format_ha_sync_output_trace,
  .flags = VLIB_NODE_FLAG_TRACE_SUPPORTED,
  .type = VLIB_NODE_TYPE_INPUT,
  .state = VLIB_NODE_STATE_INTERRUPT,
  .n_errors = ARRAY_LEN (ha_sync_output_error_strings),
  .error_strings = ha_sync_output_error_strings,
};

VLIB_REGISTER_NODE (ha_sync_snapshot_node) = {
  .name = "ha-sync-snapshot",
  .vector_size = sizeof (u32),
  .type = VLIB_NODE_TYPE_INPUT,
  .state = VLIB_NODE_STATE_INTERRUPT,
};

VLIB_REGISTER_NODE (ha_sync_process_node) = {
  .name = "ha-sync-process-worker",
  .vector_size = sizeof (u32),
  .type = VLIB_NODE_TYPE_PROCESS,
};

VLIB_REGISTER_NODE (ha_sync_timer_node) = {
  .name = "ha-sync-timer-worker",
  .type = VLIB_NODE_TYPE_INPUT,
  .state = VLIB_NODE_STATE_INTERRUPT,
};

VNET_FEATURE_INIT (ha_sync_input_worker_ip4_uc, static) = {
  .arc_name = "ip4-unicast",
  .node_name = "ha-sync-input-worker",
  .runs_before = VNET_FEATURES ("ip4-not-enabled"),
};

VNET_FEATURE_INIT (ha_sync_input_worker_ip4_mc, static) = {
  .arc_name = "ip4-multicast",
  .node_name = "ha-sync-input-worker",
  .runs_before = VNET_FEATURES ("ip4-not-enabled"),
};
#endif
/* *INDENT-ON* */
