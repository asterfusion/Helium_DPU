/*
 * cgnat_ipfix.c - CGNAT IPFIX event export
 *
 * Copyright (c) 2026 Asterfusion.
 * Licensed under the Apache License, Version 2.0.
 */

#include <vnet/ipfix-export/flow_report.h>
#include <vnet/api_errno.h>

#include <nat/cgnat/cgnat_ipfix.h>

#define CGNAT_IPFIX_SESSION_RECORD_SIZE 36
#define CGNAT_IPFIX_PBA_RECORD_SIZE 25

/* Standard IANA information elements only; record encoders below must write
 * fields in exactly this order and with exactly these fixed lengths. */
static ipfix_report_element_t cgnat_ipfix_session_elements[] = {
  { observationTimeMilliseconds, 8 },
  { natEvent, 1 },
  { observationDomainId, 4 },
  { sourceIPv4Address, 4 },
  { sourceTransportPort, 2 },
  { postNATSourceIPv4Address, 4 },
  { postNAPTSourceTransportPort, 2 },
  { destinationIPv4Address, 4 },
  { destinationTransportPort, 2 },
  { protocolIdentifier, 1 },
  { ingressVRFID, 4 },
};

static ipfix_report_element_t cgnat_ipfix_pba_elements[] = {
  { observationTimeMilliseconds, 8 },
  { natEvent, 1 },
  { observationDomainId, 4 },
  { sourceIPv4Address, 4 },
  { postNATSourceIPv4Address, 4 },
  { portRangeStart, 2 },
  { portRangeEnd, 2 },
};

/* flow-report calls this periodically for every registered report.  Finalize
 * any low-volume buffer still pending and append it to the process node's
 * output frame; this bounds record residence time even without another event. */
static vlib_frame_t *
cgnat_ipfix_flow_data_callback (flow_report_main_t *frm,
				ipfix_exporter_t *exp, flow_report_t *fr,
				vlib_frame_t *f, u32 *to_next, u32 node_index)
{
  u32 thread_index = frm->vlib_main->thread_index;
  flow_report_per_thread_t *ptd = &fr->per_thread_data[thread_index];
  flow_report_stream_t *stream = &exp->streams[fr->stream_index];
  u32 bi;

  (void) node_index;

  bi = vnet_ipfix_exp_finalize_buffer (frm->vlib_main, exp, fr, stream,
				       thread_index, ptd->buffer);
  if (bi != ~0)
    {
      to_next[0] = bi;
      f->n_vectors++;
    }
  return f;
}

static void
cgnat_ipfix_report_args (vnet_flow_report_add_del_args_t *a, u8 is_add,
			 u32 domain_id, u16 src_port, uword kind)
{
  clib_memset (a, 0, sizeof (*a));
  a->is_add = is_add;
  a->domain_id = domain_id;
  a->src_port = src_port;
  /* (opaque, rewrite_callback, flow_data_callback) is the report identity
   * used by vnet_flow_report_add_del(); kind separates session from PBA. */
  a->opaque.as_uword = kind;
  a->rewrite_callback = vnet_flow_rewrite_generic_callback;
  a->flow_data_callback = cgnat_ipfix_flow_data_callback;
}

static int
cgnat_ipfix_report_add (ipfix_exporter_t *exp,
			cgnat_ipfix_runtime_t *runtime, u16 src_port,
			uword kind, ipfix_report_element_t *elements,
			u32 n_elements, u32 *report_index, u16 *template_id)
{
  vnet_flow_report_add_del_args_t a;
  int rv;

  cgnat_ipfix_report_args (&a, 1, runtime->instance_id, src_port, kind);
  a.report_elements = elements;
  a.n_report_elements = n_elements;
  /* The first report creates the (instance_id, src_port) stream and writes
   * its index here; the second report reuses that stream and sequence space. */
  a.stream_indexp = runtime->stream_indexp;
  rv = vnet_flow_report_add_del (exp, &a, template_id);
  if (!rv)
    {
      *report_index = a.flow_report_index;
      runtime->stream_index = exp->reports[a.flow_report_index].stream_index;
      ASSERT (exp->reports[a.flow_report_index].data_record_size ==
	      (kind == CGNAT_IPFIX_REPORT_SESSION ?
		 CGNAT_IPFIX_SESSION_RECORD_SIZE : CGNAT_IPFIX_PBA_RECORD_SIZE));
    }
  return rv;
}

static void
cgnat_ipfix_report_del (ipfix_exporter_t *exp,
			cgnat_ipfix_runtime_t *runtime, u16 src_port, uword kind)
{
  vnet_flow_report_add_del_args_t a;

  cgnat_ipfix_report_args (&a, 0, runtime->instance_id, src_port, kind);
  (void) vnet_flow_report_add_del (exp, &a, 0);
}

void
cgnat_ipfix_init (cgnat_main_t *cm)
{
  cm->ipfix_runtimes = 0;
}

int
cgnat_ipfix_exporter_create (u32 instance_index,
			     cgnat_ipfix_exporter_t *config)
{
  cgnat_main_t *cm = &cgnat_main;
  cgnat_instance_t *instance;
  cgnat_ipfix_runtime_t *runtime;
  vnet_ipfix_exporter_params_t params;
  ipfix_exporter_t *exp;
  u32 runtime_index;
  int rv;

  if (!config || !config->collector_address.as_u32 ||
      !config->src_address.as_u32 || !config->collector_port ||
      !config->src_port)
    return VNET_API_ERROR_INVALID_VALUE;

  instance = cgnat_instance_get_by_index (cm, instance_index);
  if (!instance)
    return VNET_API_ERROR_NO_SUCH_ENTRY;

  /* Configuration is persistent and user-facing; this runtime object owns
   * all transient flow-report resources created for one collector. */
  pool_get_zero (cm->ipfix_runtimes, runtime);
  runtime_index = runtime - cm->ipfix_runtimes;
  runtime->instance_index = instance_index;
  runtime->instance_id = instance->instance_id;
  runtime->exporter_index = CGNAT_INVALID_INDEX;
  runtime->session_report_index = CGNAT_INVALID_INDEX;
  runtime->pba_report_index = CGNAT_INVALID_INDEX;
  runtime->stream_indexp = clib_mem_alloc (sizeof (*runtime->stream_indexp));
  if (!runtime->stream_indexp)
    {
      pool_put (cm->ipfix_runtimes, runtime);
      return VNET_API_ERROR_UNSPECIFIED;
    }
  *runtime->stream_indexp = CGNAT_INVALID_INDEX;

  /* One VPP exporter represents the destination/source/FIB/MTU tuple.  Its
   * index is returned directly, avoiding the legacy address-only lookup. */
  clib_memset (&params, 0, sizeof (params));
  ip_address_set (&params.collector, &config->collector_address, AF_IP4);
  ip_address_set (&params.src_address, &config->src_address, AF_IP4);
  params.collector_port = config->collector_port;
  params.fib_index = instance->outside_fib_index;
  params.path_mtu = CGNAT_IPFIX_PATH_MTU;
  params.template_interval = CGNAT_IPFIX_TEMPLATE_INTERVAL;
  params.udp_checksum = 0;

  rv = vnet_ipfix_exporter_create (&params, &runtime->exporter_index);
  if (rv)
    goto error;
  exp = vnet_ipfix_exporter_get (runtime->exporter_index);

  /* Register two templates on one per-instance stream.  Using instance_id as
   * the domain ID gives each instance an independent sequence number and
   * template-ID namespace within this exporter. */
  rv = cgnat_ipfix_report_add (
    exp, runtime, config->src_port, CGNAT_IPFIX_REPORT_SESSION,
    cgnat_ipfix_session_elements, ARRAY_LEN (cgnat_ipfix_session_elements),
    &runtime->session_report_index, &runtime->session_template_id);
  if (rv)
    goto error;

  rv = cgnat_ipfix_report_add (
    exp, runtime, config->src_port, CGNAT_IPFIX_REPORT_PBA,
    cgnat_ipfix_pba_elements, ARRAY_LEN (cgnat_ipfix_pba_elements),
    &runtime->pba_report_index, &runtime->pba_template_id);
  if (rv)
    goto error;

  /* Send both templates before publishing runtime_index.  Data events cannot
   * select this runtime until collectors have had a chance to learn them. */
  rv = vnet_ipfix_exp_send_template (
    exp, vec_elt_at_index (exp->reports, runtime->session_report_index));
  if (rv)
    goto error;
  rv = vnet_ipfix_exp_send_template (
    exp, vec_elt_at_index (exp->reports, runtime->pba_report_index));
  if (rv)
    goto error;

  config->runtime_index = runtime_index;
  return 0;

error:
  /* Unwind in reverse registration order.  Exporters may only be deleted
   * after all reports have released their streams. */
  if (runtime->exporter_index != CGNAT_INVALID_INDEX)
    {
      exp = vnet_ipfix_exporter_get (runtime->exporter_index);
      if (exp && runtime->pba_report_index != CGNAT_INVALID_INDEX)
	cgnat_ipfix_report_del (exp, runtime, config->src_port,
				CGNAT_IPFIX_REPORT_PBA);
      if (exp && runtime->session_report_index != CGNAT_INVALID_INDEX)
	cgnat_ipfix_report_del (exp, runtime, config->src_port,
				CGNAT_IPFIX_REPORT_SESSION);
      (void) vnet_ipfix_exporter_delete (runtime->exporter_index);
    }
  clib_mem_free (runtime->stream_indexp);
  pool_put (cm->ipfix_runtimes, runtime);
  return rv;
}

void
cgnat_ipfix_exporter_destroy (cgnat_ipfix_exporter_t *config)
{
  cgnat_main_t *cm = &cgnat_main;
  cgnat_ipfix_runtime_t *runtime;
  ipfix_exporter_t *exp;

  if (!config || config->runtime_index == CGNAT_INVALID_INDEX ||
      pool_is_free_index (cm->ipfix_runtimes, config->runtime_index))
    return;

  runtime = pool_elt_at_index (cm->ipfix_runtimes, config->runtime_index);
  exp = vnet_ipfix_exporter_get (runtime->exporter_index);
  if (exp)
    {
      u32 thread_index = cm->vlib_main->thread_index;
      flow_report_t *fr;
      flow_report_stream_t *stream;

      /* Preserve already encoded records before deleting their reports. */
      if (runtime->pba_report_index < vec_len (exp->reports))
	{
	  fr = vec_elt_at_index (exp->reports,
				 runtime->pba_report_index);
	  stream = &exp->streams[fr->stream_index];
	  vnet_ipfix_exp_send_buffer (
	    cm->vlib_main, exp, fr, stream, thread_index,
	    fr->per_thread_data[thread_index].buffer);
	}
      if (runtime->session_report_index < vec_len (exp->reports))
	{
	  fr = vec_elt_at_index (exp->reports,
				 runtime->session_report_index);
	  stream = &exp->streams[fr->stream_index];
	  vnet_ipfix_exp_send_buffer (
	    cm->vlib_main, exp, fr, stream, thread_index,
	    fr->per_thread_data[thread_index].buffer);
	}

      /* PBA is registered second, so remove it before the report vector
       * shifts the session entry. */
      cgnat_ipfix_report_del (exp, runtime, config->src_port,
			    CGNAT_IPFIX_REPORT_PBA);
      cgnat_ipfix_report_del (exp, runtime, config->src_port,
			    CGNAT_IPFIX_REPORT_SESSION);
      (void) vnet_ipfix_exporter_delete (runtime->exporter_index);
    }

  clib_mem_free (runtime->stream_indexp);
  pool_put (cm->ipfix_runtimes, runtime);
  config->runtime_index = CGNAT_INVALID_INDEX;
}

int
cgnat_ipfix_instance_enable (u32 instance_index)
{
  cgnat_main_t *cm = &cgnat_main;
  cgnat_instance_t *instance;
  cgnat_ipfix_exporter_t *config;
  int rv;

  instance = cgnat_instance_get_by_index (cm, instance_index);
  if (!instance)
    return VNET_API_ERROR_NO_SUCH_ENTRY;

  /* Enabling is transactional across the instance's collector list. */
  vec_foreach (config, instance->ipfix_exporters)
    if (config->runtime_index == CGNAT_INVALID_INDEX)
      {
	rv = cgnat_ipfix_exporter_create (instance_index, config);
	if (rv)
	  {
	    cgnat_ipfix_instance_disable (instance);
	    return rv;
	  }
      }
  return 0;
}

void
cgnat_ipfix_instance_disable (cgnat_instance_t *instance)
{
  cgnat_ipfix_exporter_t *config;

  if (!instance)
    return;
  vec_foreach (config, instance->ipfix_exporters)
    cgnat_ipfix_exporter_destroy (config);
}

static_always_inline void
cgnat_ipfix_put_u16 (u8 **p, u16 value)
{
  /* IPFIX integer fields are encoded in network byte order. */
  value = clib_host_to_net_u16 (value);
  clib_memcpy_fast (*p, &value, sizeof (value));
  *p += sizeof (value);
}

static_always_inline void
cgnat_ipfix_put_u32 (u8 **p, u32 value)
{
  value = clib_host_to_net_u32 (value);
  clib_memcpy_fast (*p, &value, sizeof (value));
  *p += sizeof (value);
}

static_always_inline void
cgnat_ipfix_put_u64 (u8 **p, u64 value)
{
  value = clib_host_to_net_u64 (value);
  clib_memcpy_fast (*p, &value, sizeof (value));
  *p += sizeof (value);
}

static_always_inline void
cgnat_ipfix_put_ip4 (u8 **p, const ip4_address_t *address)
{
  clib_memcpy_fast (*p, address, sizeof (*address));
  *p += sizeof (*address);
}

static void
cgnat_ipfix_encode_session (u8 *p, const cgnat_log_event_t *event)
{
  /* Keep this serialization order synchronized with
   * cgnat_ipfix_session_elements[]. */
  cgnat_ipfix_put_u64 (&p, event->timestamp_ms);
  *p++ = event->ipfix_event;
  cgnat_ipfix_put_u32 (&p, event->instance_id);
  cgnat_ipfix_put_ip4 (&p, &event->session.private_ip);
  cgnat_ipfix_put_u16 (&p, event->session.private_port);
  cgnat_ipfix_put_ip4 (&p, &event->session.public_ip);
  cgnat_ipfix_put_u16 (&p, event->session.public_port);
  cgnat_ipfix_put_ip4 (&p, &event->session.remote_ip);
  cgnat_ipfix_put_u16 (&p, event->session.remote_port);
  *p++ = event->session.protocol;
  cgnat_ipfix_put_u32 (&p, event->inside_vrf_id);
}

static void
cgnat_ipfix_encode_pba (u8 *p, const cgnat_log_event_t *event)
{
  /* Keep this serialization order synchronized with
   * cgnat_ipfix_pba_elements[]. */
  cgnat_ipfix_put_u64 (&p, event->timestamp_ms);
  *p++ = event->ipfix_event;
  cgnat_ipfix_put_u32 (&p, event->instance_id);
  cgnat_ipfix_put_ip4 (&p, &event->block.private_ip);
  cgnat_ipfix_put_ip4 (&p, &event->block.public_ip);
  cgnat_ipfix_put_u16 (&p, event->block.public_port_start);
  cgnat_ipfix_put_u16 (&p, event->block.public_port_end);
}

void
cgnat_ipfix_emit (cgnat_log_event_t *event)
{
  cgnat_main_t *cm = &cgnat_main;
  cgnat_instance_t *instance;
  cgnat_ipfix_exporter_t *config;
  cgnat_ipfix_runtime_t *runtime;
  ipfix_exporter_t *exp;
  flow_report_t *fr;
  flow_report_per_thread_t *ptd;
  vlib_buffer_t *b;
  u32 thread_index = cm->vlib_main->thread_index;

  /* Events can wait in the FIFO while configuration changes.  Match both
   * pool index and stable instance ID before dereferencing collector state. */
  instance = cgnat_instance_get_by_index (cm, event->instance_index);
  if (!instance || instance->instance_id != event->instance_id)
    {
      cm->ipfix_no_runtime++;
      return;
    }

  if (!vec_len (instance->ipfix_exporters))
    {
      cm->ipfix_no_runtime++;
      return;
    }

  /* Fan one immutable event out to every collector configured on the
   * instance.  A failed collector does not suppress the remaining sinks. */
  vec_foreach (config, instance->ipfix_exporters)
    {
      if (config->runtime_index == CGNAT_INVALID_INDEX ||
	  pool_is_free_index (cm->ipfix_runtimes, config->runtime_index))
	{
	  cm->ipfix_no_runtime++;
	  continue;
	}
      runtime = pool_elt_at_index (cm->ipfix_runtimes,
				   config->runtime_index);
      exp = vnet_ipfix_exporter_get (runtime->exporter_index);
      if (!exp)
	{
	  cm->ipfix_no_runtime++;
	  continue;
	}

      fr = event->kind == CGNAT_LOG_EVENT_KIND_SESSION ?
	     vec_elt_at_index (exp->reports, runtime->session_report_index) :
	     vec_elt_at_index (exp->reports, runtime->pba_report_index);
      /* The framework flushes a full MTU-sized buffer before returning room
       * for this fixed-size record and maintains one pending buffer/report. */
      b = vnet_ipfix_exp_get_buffer (cm->vlib_main, exp, fr, thread_index);
      if (!b)
	{
	  cm->ipfix_no_buffer++;
	  continue;
	}
      ptd = &fr->per_thread_data[thread_index];
      if (event->kind == CGNAT_LOG_EVENT_KIND_SESSION)
	cgnat_ipfix_encode_session (b->data + ptd->next_data_offset, event);
      else
	cgnat_ipfix_encode_pba (b->data + ptd->next_data_offset, event);
      ptd->next_data_offset += fr->data_record_size;
      ptd->n_data_records++;
      b->current_length += fr->data_record_size;
      cm->ipfix_records_encoded++;
    }
}

void
cgnat_ipfix_flush (void)
{
  /* Wake flow-report-process: its data callback finalizes pending records and
   * the same process also handles periodic template refresh. */
  vlib_process_signal_event (cgnat_main.vlib_main,
			     flow_report_process_node.index, 1, 0);
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
