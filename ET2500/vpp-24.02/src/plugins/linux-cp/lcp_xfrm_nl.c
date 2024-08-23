/*
 * Copyright (c) 2022 Cisco and/or its affiliates.
 * Copyright (c) 2022 Marvell Technology, Inc and/or its affiliates.
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

#define _GNU_SOURCE
#include <fcntl.h>
#include <sched.h>

#include <linux-cp/lcp_xfrm.h>
#include <plugins/linux-cp/lcp_interface.h>
#include <vlib/unix/unix.h>
#include <vppinfra/error.h>
#include <vppinfra/linux/netns.h>

static nl_xfrm_main_t nl_xfrm_main = {
  .rx_buf_size = NL_RX_BUF_SIZE_DEF,
  .tx_buf_size = NL_TX_BUF_SIZE_DEF,
  .batch_size = NL_BATCH_SIZE_DEF,
  .batch_delay_ms = NL_BATCH_DELAY_MS_DEF,
  .sync_batch_limit = NL_SYNC_BATCH_LIMIT_DEF,
  .sync_batch_delay_ms = NL_SYNC_BATCH_DELAY_MS_DEF,
  .sync_attempt_delay_ms = NL_SYNC_ATTEMPT_DELAY_MS_DEF,
};

nl_xfrm_main_t *nm = &nl_xfrm_main;

static void lcp_xfrm_nl_open_sync_socket ();
static void lcp_xfrm_nl_close_sync_socket ();
static void lcp_xfrm_nl_open_socket ();
static void lcp_xfrm_nl_close_socket ();

void
nl_xfrm_register_vft (const nl_xfrm_vft_t *nv)
{
  vec_add1 (nm->nl_xfrm_vfts, *nv);
}

static void
nl_sp_cfg (struct xfrmnl_sp *sp, void *arg)
{
  FOREACH_XFRM_VFT (nvl_rt_xfrm_sp_cfg, sp);
}
static void
nl_sa_cfg (struct xfrmnl_sa *sa, void *arg)
{
  FOREACH_XFRM_VFT (nvl_rt_xfrm_sa_cfg, sa);
}

static void
nl_xfrm_dispatch (struct nl_object *obj, void *arg)
{
  /* nothing can be done without interface mappings */
  if (!lcp_itf_num_pairs ())
    return;

  switch (nl_object_get_msgtype (obj))
    {
    case XFRM_MSG_EXPIRE:
    case XFRM_MSG_UPDSA:
    case XFRM_MSG_NEWSA:
    case XFRM_MSG_DELSA:
      NL_DBG ("######### SA Notification ######### ");
      nl_sa_cfg ((struct xfrmnl_sa *) obj, arg);
      break;

    case XFRM_MSG_UPDPOLICY:
    case XFRM_MSG_NEWPOLICY:
    case XFRM_MSG_DELPOLICY:
      NL_DBG ("######### SP Notification ######### ");
      nl_sp_cfg ((struct xfrmnl_sp *) obj, arg);
      break;

    default:
      NL_ERROR ("unhandled xfrm notfn: %s %x", nl_object_get_type (obj));
      break;
    }
}

int
send_nl_msg (struct nlmsghdr *nl_hdr, unsigned int groups, u8 msg_type)
{
  int status;
  struct nl_sock *sk_xfrm = nm->sk_xfrm;
  struct sockaddr_nl nl_addr;
  struct iovec iov;
  struct msghdr msg;
  struct nl_msg *nlmsg;

  nlmsg = nlmsg_alloc_simple (msg_type, NLM_F_REQUEST);

  memset (&msg, 0, sizeof (struct msghdr));
  memset (&iov, 0, sizeof (struct iovec));

  iov.iov_base = (void *) nl_hdr;
  iov.iov_len = nl_hdr->nlmsg_len;

  msg.msg_name = &nl_addr;
  msg.msg_namelen = sizeof (nl_addr);
  msg.msg_iov = &iov;
  msg.msg_iovlen = 1;

  memset (&nl_addr, 0, sizeof (nl_addr));
  nl_addr.nl_family = AF_NETLINK;
  nl_addr.nl_groups = groups;
  nl_addr.nl_pid = 0;

  status = nl_sendmsg (sk_xfrm, nlmsg, &msg);
  if (status < 0)
    {
      NL_ERROR ("Expiry send failed");
      return 0;
    }

  return 1;
}

static int
nl_xfrm_process_msgs (void)
{
  nl_msg_info_t *msg_info;
  int err, n_msgs = 0;

  /* process a batch of messages. break if we hit our limit */
  vec_foreach (msg_info, nm->nl_msg_queue)
    {
      if ((err = nl_msg_parse (msg_info->msg, nl_xfrm_dispatch, msg_info)) < 0)
	NL_INFO ("Unable to parse object: %s", nl_geterror (err));
      nlmsg_free (msg_info->msg);
      if (++n_msgs >= nm->batch_size)
	break;
    }

  /* remove the messages we processed from the head of the queue */
  if (n_msgs)
    vec_delete (nm->nl_msg_queue, n_msgs, 0);

  NL_INFO ("Processed %u messages", n_msgs);

  return n_msgs;
}

static int
lcp_xfrm_nl_send_dump_req (int msg_type)
{
  struct nl_sock *sk_xfrm = nm->sk_xfrm;
  int err;
  struct rtgenmsg rt_hdr = {
    .rtgen_family = AF_UNSPEC,
  };

  err =
    nl_send_simple (sk_xfrm, msg_type, NLM_F_DUMP, &rt_hdr, sizeof (rt_hdr));

  if (err < 0)
    {
      NL_ERROR ("Unable to send a dump request: %s", nl_geterror (err));
    }
  else
    NL_INFO ("Dump request sent via socket %d ", nl_socket_get_fd (sk_xfrm));

  return err;
}

static int
lcp_xfrm_nl_dump_cb (struct nl_msg *msg, void *arg)
{
  int err;

  if ((err = nl_msg_parse (msg, nl_xfrm_dispatch, NULL)) < 0)
    NL_ERROR ("Unable to parse object: %s", nl_geterror (err));

  return NL_OK;
}

static int
lcp_xfrm_nl_read (int msg_limit, int *is_done_rcvd)
{
  struct nl_sock *sk_xfrm = nm->sk_xfrm;
  struct sockaddr_nl nla;
  uint8_t *buf = NULL;
  int n_bytes;
  struct nlmsghdr *hdr;
  struct nl_msg *msg = NULL;
  int err = 0;
  int done = 0;
  int n_msgs = 0;

continue_reading:
  n_bytes = nl_recv (sk_xfrm, &nla, &buf, /* creds */ NULL);
  if (n_bytes <= 0)
    return n_bytes;

  hdr = (struct nlmsghdr *) buf;
  while (nlmsg_ok (hdr, n_bytes))
    {
      nlmsg_free (msg);
      msg = nlmsg_convert (hdr);
      if (!msg)
	{
	  err = -NLE_NOMEM;
	  goto out;
	}

      n_msgs++;

      nlmsg_set_proto (msg, NETLINK_XFRM);
      nlmsg_set_src (msg, &nla);

      /* Message that terminates a multipart message. Finish parsing and signal
       * the caller that all dump replies have been received
       */
      if (hdr->nlmsg_type == NLMSG_DONE)
	{
	  done = 1;
	  goto out;
	}
      /* Message to be ignored. Continue parsing */
      else if (hdr->nlmsg_type == NLMSG_NOOP)
	;
      /* Message that indicates data was lost. Finish parsing and return an
       * error
       */
      else if (hdr->nlmsg_type == NLMSG_OVERRUN)
	{
	  err = -NLE_MSG_OVERFLOW;
	  goto out;
	}
      /* Message that indicates an error. Finish parsing, extract the error
       * code, and return it */
      else if (hdr->nlmsg_type == NLMSG_ERROR)
	{
	  struct nlmsgerr *e = nlmsg_data (hdr);

	  if (hdr->nlmsg_len < nlmsg_size (sizeof (*e)))
	    {
	      err = -NLE_MSG_TRUNC;
	      goto out;
	    }
	  else if (e->error)
	    {
	      err = -nl_syserr2nlerr (e->error);
	      goto out;
	    }
	  /* Message is an acknowledgement (err_code = 0). Continue parsing */
	  else
	    ;
	}
      /* Message that contains the requested data. Pass it for processing and
       * continue parsing
       */
      else
	{
	  lcp_xfrm_nl_dump_cb (msg, NULL);
	}

      hdr = nlmsg_next (hdr, &n_bytes);
    }

  nlmsg_free (msg);
  free (buf);
  msg = NULL;
  buf = NULL;

  if (!done && n_msgs < msg_limit)
    goto continue_reading;

out:
  nlmsg_free (msg);
  free (buf);

  if (err)
    return err;

  *is_done_rcvd = done;

  return n_msgs;
}

static void
lcp_xfrm_nl_close_sync_socket ()
{
  struct nl_sock *sk_xfrm = nm->sk_xfrm;

  if (sk_xfrm)
    {
      NL_INFO ("Closing netlink synchronization socket %d",
	       nl_socket_get_fd (sk_xfrm));
      nl_socket_free (sk_xfrm);
      nm->sk_xfrm = NULL;
    }
}

static void
lcp_xfrm_nl_open_sync_socket ()
{
  struct nl_sock *sk_xfrm;

  /* Allocate a new blocking socket for XFRM that will be used for dump
   * requests. Buffer sizes are left default because replies to dump requests
   * are flow-controlled and the kernel will not overflow the socket by sending
   * these
   */

  nm->sk_xfrm = sk_xfrm = nl_socket_alloc ();

  nl_connect (sk_xfrm, NETLINK_XFRM);

  NL_INFO ("Opened netlink synchronization socket %d",
	   nl_socket_get_fd (sk_xfrm));
}

static inline void
lcp_xfrm_nl_recv_dump_replies ()
{
  int is_done = 0, n_msgs;

  do
    {
      n_msgs = lcp_xfrm_nl_read (nm->sync_batch_limit, &is_done);
      if (n_msgs < 0)
	{
	  NL_ERROR ("Error receiving dump replies "
		    ": %s (%d)",
		    nl_geterror (n_msgs), n_msgs);
	  break;
	}
      else if (n_msgs == 0)
	{
	  NL_ERROR ("EOF while receiving dump replies");
	  break;
	}
      else
	NL_INFO ("Processed %u dump replies", n_msgs);
    }
  while (!is_done);
}

static inline void
lcp_xfrm_nl_sync ()
{
  /* close the xfrm socket listening on XFRM notifications */
  lcp_xfrm_nl_close_socket ();
  /* create a new xfrm sync socket only to initiate a DUMP request */
  lcp_xfrm_nl_open_sync_socket ();

  /* get all xfrm cfgs from linux and cfg the same here*/
  lcp_xfrm_nl_send_dump_req (XFRM_MSG_GETSA);
  lcp_xfrm_nl_recv_dump_replies ();
  lcp_xfrm_nl_send_dump_req (XFRM_MSG_GETPOLICY);
  lcp_xfrm_nl_recv_dump_replies ();

  /* close the xfrm sync socket since dump request is handled by now */
  lcp_xfrm_nl_close_sync_socket ();
  /* create the xfrm socket to handle XFRM notifications */
  lcp_xfrm_nl_open_socket ();
}

static uword
nl_xfrm_process (vlib_main_t *vm, vlib_node_runtime_t *node,
		 vlib_frame_t *frame)
{
  uword event_type;
  uword *event_data = 0;
  f64 wait_time = DAY_F64;

  while (1)
    {
      if (nm->nl_status == NL_STATUS_NOTIF_PROC)
	{
	  /* If we process a batch of messages and stop because we reached the
	   * batch size limit, we want to wake up after the batch delay and
	   * process more. Otherwise we just want to wait for a read event.
	   */
	  vlib_process_wait_for_event_or_clock (vm, wait_time);
	  event_type = vlib_process_get_events (vm, &event_data);
	  vec_reset_length (event_data);

	  switch (event_type)
	    {
	    /* Process batch of queued messages on timeout or read event
	     * signal
	     */
	    case ~0:
	    case NL_EVENT_READ:
	      nl_xfrm_process_msgs ();
	      wait_time = (vec_len (nm->nl_msg_queue) != 0) ?
				  nm->batch_delay_ms * 1e-3 :
				  DAY_F64;

	      break;
	    case NL_EVENT_ERR:
	      nm->nl_status = NL_STATUS_SYNC;
	      break;
	    default:
	      NL_ERROR ("Unknown event type: %u", (u32) event_type);
	    }
	}
      else if (nm->nl_status == NL_STATUS_SYNC)
	{
	  NL_INFO ("Start sync");
	  lcp_xfrm_nl_sync ();
	  nm->nl_status = NL_STATUS_NOTIF_PROC;
	  NL_INFO ("Sync done");
	}
      else
	NL_ERROR ("Unknown status: %d", nm->nl_status);
    }
  return frame->n_vectors;
}

VLIB_REGISTER_NODE (nl_xfrm_process_node, static) = {
  .function = nl_xfrm_process,
  .name = "linux-cp-netlink-xfrm-process",
  .type = VLIB_NODE_TYPE_PROCESS,
  .process_log2_n_stack_bytes = 17,
};

VLIB_REGISTER_NODE (ipsec_xfrm_expire_process_node, static) = {
  .function = ipsec_xfrm_expire_process,
  .name = "ipsec-xfrm-expire-process",
  .type = VLIB_NODE_TYPE_PROCESS,
  .process_log2_n_stack_bytes = 17,
};

static int
nl_xfrm_cb (struct nl_msg *msg, void *arg)
{
  nl_msg_info_t *msg_info = 0;

  /* queue for later */
  vec_add2 (nm->nl_msg_queue, msg_info, 1);

  msg_info->msg = msg;
  nlmsg_get (msg);

  return 0;
}

int
lcp_nl_xfrm_drain_messages (void)
{
  int err;

  /* Read until there's an error */
  while ((err = nl_recvmsgs_default (nm->sk_xfrm)) > -1)
    ;

  /* If there was an error other then EAGAIN, signal process node */
  if (err != -NLE_AGAIN)
    vlib_process_signal_event (vlib_get_main (), nl_xfrm_process_node.index,
			       NL_EVENT_ERR, 0);
  else
    {
      /* If netlink notification processing is active, signal process node
       * there were notifications read
       */
      if (nm->nl_status == NL_STATUS_NOTIF_PROC)
	{
	  vlib_process_signal_event (
	    vlib_get_main (), nl_xfrm_process_node.index, NL_EVENT_READ, 0);
	}
    }

  return err;
}

static clib_error_t *
nl_xfrm_read_cb (clib_file_t *f)
{
  int err;

  err = lcp_nl_xfrm_drain_messages ();
  if (err < 0 && err != -NLE_AGAIN)
    NL_ERROR ("Error reading netlink socket (fd %d): %s (%d)",
	      f->file_descriptor, nl_geterror (err), err);

  return 0;
}

static clib_error_t *
nl_xfrm_error_cb (clib_file_t *f)
{
  NL_ERROR ("Error polling netlink socket (fd %d)", f->file_descriptor);

  /* notify process node */
  vlib_process_signal_event (vlib_get_main (), nl_xfrm_process_node.index,
			     NL_EVENT_ERR, 0);

  return clib_error_return (0, "Error polling netlink socket %d",
			    f->file_descriptor);
}

/* Set the RX buffer size to be used on the netlink socket */
void
lcp_xfrm_nl_set_buffer_size (u32 buf_size)
{
  nm->rx_buf_size = buf_size;

  if (nm->sk_xfrm)
    nl_socket_set_buffer_size (nm->sk_xfrm, nm->rx_buf_size, nm->tx_buf_size);
}

/* Set the batch size - maximum netlink messages to process at one time */
void
lcp_xfrm_nl_set_batch_size (u32 batch_size)
{
  nm->batch_size = batch_size;
}

/* Set the batch delay - how long to wait in ms between processing batches */
void
lcp_xfrm_nl_set_batch_delay (u32 batch_delay_ms)
{
  nm->batch_delay_ms = batch_delay_ms;
}

static clib_error_t *
lcp_xfrm_itf_pair_config (vlib_main_t *vm, unformat_input_t *input)
{
  u32 buf_size, batch_size, batch_delay_ms;
  char *tunnel_name = NULL;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "enable-route-mode-ipsec"))
	nm->is_route_mode = 1;
      else if (unformat (input, "nl-rx-buffer-size %u", &buf_size))
	lcp_xfrm_nl_set_buffer_size (buf_size);
      else if (unformat (input, "nl-batch-size %u", &batch_size))
	lcp_xfrm_nl_set_batch_size (batch_size);
      else if (unformat (input, "nl-batch-delay-ms %u", &batch_delay_ms))
	lcp_xfrm_nl_set_batch_delay (batch_delay_ms);
      else if (unformat (input, "interface %s", tunnel_name))
	{
	  if (!clib_strcmp (tunnel_name, "ipsec"))
	    nm->interface_type = NL_INTERFACE_TYPE_IPSEC;

	  vec_free (tunnel_name);
	}
      else
	return clib_error_return (0, "invalid netlink option: %U",
				  format_unformat_error, input);
    }

  if (nm->interface_type && !nm->is_route_mode)
    return clib_error_return (
      0, "enable-route-mode-ipsec configuration is missing");

  return NULL;
}

VLIB_CONFIG_FUNCTION (lcp_xfrm_itf_pair_config, "linux-xfrm-nl");

static void
lcp_xfrm_nl_close_socket (void)
{
  /* delete existing fd from epoll fd set */
  if (nm->clib_file_index != ~0)
    {
      clib_file_main_t *fm = &file_main;
      clib_file_t *f = clib_file_get (fm, nm->clib_file_index);

      if (f)
	{
	  NL_INFO ("Stopping poll of fd %u", f->file_descriptor);
	  fm->file_update (f, UNIX_FILE_UPDATE_DELETE);
	}
      else
	/* stored index was not a valid file, reset stored index to ~0 */
	nm->clib_file_index = ~0;
    }
  /* If we already created a socket, close/free it */
  if (nm->sk_xfrm)
    {
      NL_INFO ("Closing netlink socket %d", nl_socket_get_fd (nm->sk_xfrm));
      nl_socket_free (nm->sk_xfrm);
      nm->sk_xfrm = NULL;
    }
}

static void
lcp_xfrm_nl_open_socket (void)
{
  int dest_ns_fd = 0, curr_ns_fd = 0;
  /*
   * Allocate a new socket for xfrm. Notifications do not use sequence
   * numbers, disable sequence number checking.
   * Define a callback function, which will be called for each
   * notification received
   */
  dest_ns_fd = lcp_get_default_ns_fd ();
  if (dest_ns_fd)
    {
      curr_ns_fd = open ("/proc/self/ns/net", O_RDONLY);
      setns (dest_ns_fd, CLONE_NEWNET);
    }

  nm->sk_xfrm = nl_socket_alloc ();
  nm->xfrm_fd = nl_socket_get_fd (nm->sk_xfrm);
  nl_socket_disable_seq_check (nm->sk_xfrm);
  nl_join_groups (nm->sk_xfrm, XFRMGRP_SA | XFRMGRP_POLICY | XFRMGRP_EXPIRE);
  nl_connect (nm->sk_xfrm, NETLINK_XFRM);

  /* Set socket in nonblocking mode and increase buffer sizes */
  nl_socket_set_nonblocking (nm->sk_xfrm);
  nl_socket_set_buffer_size (nm->sk_xfrm, nm->rx_buf_size, nm->tx_buf_size);

  if (dest_ns_fd && curr_ns_fd >= 0)
    {
      setns (curr_ns_fd, CLONE_NEWNET);
      close (curr_ns_fd);
    }
  if (nm->clib_file_index == ~0)
    {
      clib_file_t rt_file = {
	.read_function = nl_xfrm_read_cb,
	.error_function = nl_xfrm_error_cb,
	.file_descriptor = nl_socket_get_fd (nm->sk_xfrm),
	.description = format (0, "linux-cp netlink route socket"),
      };

      nm->clib_file_index = clib_file_add (&file_main, &rt_file);
      NL_INFO ("Added file %u", nm->clib_file_index);
    }
  else
    /* clib file already created and socket was closed due to error */
    {
      clib_file_main_t *fm = &file_main;
      clib_file_t *f = clib_file_get (fm, nm->clib_file_index);

      f->file_descriptor = nl_socket_get_fd (nm->sk_xfrm);
      fm->file_update (f, UNIX_FILE_UPDATE_ADD);
      NL_INFO ("Starting poll of %d", f->file_descriptor);
    }

  nl_socket_modify_cb (nm->sk_xfrm, NL_CB_VALID, NL_CB_CUSTOM, nl_xfrm_cb,
		       NULL);
  NL_INFO ("Opened netlink socket %d", nl_socket_get_fd (nm->sk_xfrm));
}

clib_error_t *
lcp_nl_xfrm_init (vlib_main_t *vm)
{

  nm->nl_status = NL_STATUS_NOTIF_PROC;
  nm->clib_file_index = ~0;
  nm->nl_logger = vlib_log_register_class ("nl", "xfrm");

  lcp_xfrm_nl_open_socket ();
  vlib_process_signal_event (vlib_get_main (),
			     ipsec_xfrm_expire_process_node.index, 0, 0);
  return NULL;
}

VLIB_INIT_FUNCTION (lcp_nl_xfrm_init) = {
  .runs_after = VLIB_INITS ("ipsec_init"),
};
/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
