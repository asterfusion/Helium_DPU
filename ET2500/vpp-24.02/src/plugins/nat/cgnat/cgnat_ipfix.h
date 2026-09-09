/*
 * cgnat_ipfix.h - CGNAT IPFIX event export
 */
#ifndef __included_cgnat_ipfix_h__
#define __included_cgnat_ipfix_h__

#include <nat/cgnat/cgnat.h>

/* Keep exported datagrams below the normal Ethernet path MTU.  Templates are
 * refreshed periodically because IPFIX runs over unreliable UDP transport. */
#define CGNAT_IPFIX_PATH_MTU 1450
#define CGNAT_IPFIX_TEMPLATE_INTERVAL 20

/* Distinct opaque values make the flow-report framework treat the two
 * templates as separate reports even though they share callbacks and stream. */
typedef enum
{
  CGNAT_IPFIX_REPORT_SESSION = 1,
  CGNAT_IPFIX_REPORT_PBA = 2,
} cgnat_ipfix_report_kind_t;

typedef struct cgnat_ipfix_runtime
{
  /* Identity snapshot used to reject stale queued events after an instance
   * pool slot has been deleted and reused. */
  u32 instance_index;
  u32 instance_id;

  /* Indices belong to the VPP flow-report exporter selected below.  The
   * stream owns the observation domain, source port and sequence counter;
   * each report owns one template and its pending data buffer. */
  u32 exporter_index;
  u32 stream_index;
  u32 session_report_index;
  u32 pba_report_index;
  u16 session_template_id;
  u16 pba_template_id;

  /* vnet_flow_report_add_del() retains this pointer in each report.  Keep it
   * separately allocated so its address remains stable if the runtime pool
   * itself grows or moves.  Both reports use the value to join one stream. */
  u32 *stream_indexp;
} cgnat_ipfix_runtime_t;

void cgnat_ipfix_flush (void);

#endif /* __included_cgnat_ipfix_h__ */
