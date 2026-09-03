/*
 * Copyright (c) 2024 Cisco and/or its affiliates.
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

#include <vlib/vlib.h>
#include <vnet/buffer.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/ip/ip.h>
#include <vnet/ip/ip6_inlines.h>
#include <vnet/ip/ip6_packet.h>
#include <vnet/tcp/tcp_packet.h>
#include <vnet/udp/udp_packet.h>

#include <linux-cp/lcp_match.h>
#include <linux-cp/lcp_punt.h>
#include <linux-cp/lcp_policy.h>
#include <linux-cp/lcp_stats.h>

#ifdef LCP_COPP_UNIT_TEST
/* Lightweight per-trap counters for unit tests.  The main plugin registers
 * the real /lcp/copp/ stat-segment counters; the unittest plugin must not
 * register a second set, so it uses this local stub instead. */
static u64 lcp_test_stats[LCP_STATS_N_COUNTERS][LCP_POLICY_N_TRAPS];

void
lcp_stats_increment (vlib_main_t *vm, vl_api_lcp_trap_type_t trap_id,
		     lcp_stats_counter_t counter)
{
  lcp_test_stats[counter][trap_id]++;
}

u64
lcp_stats_get (vl_api_lcp_trap_type_t trap_id, lcp_stats_counter_t counter)
{
  return lcp_test_stats[counter][trap_id];
}
#endif /* LCP_COPP_UNIT_TEST */

static const char *lcp_copp_action_names[] = {
  [LCP_COPP_ACTION_DROP] = "drop",
  [LCP_COPP_ACTION_FORWARD] = "forward",
  [LCP_COPP_ACTION_COPY] = "copy",
  [LCP_COPP_ACTION_TRAP] = "trap",
};

static const char *
lcp_copp_action_name (u8 action)
{
  if (action < ARRAY_LEN (lcp_copp_action_names))
    return lcp_copp_action_names[action];
  return "invalid";
}

static clib_error_t *
lcp_copp_policy_add_command_fn (vlib_main_t *vm, unformat_input_t *input,
				vlib_cli_command_t *cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  u32 trap_id = ~0;
  u32 action = ~0;
  u32 priority = 0;
  u32 policer_index = ~0;
  int rv;

  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "trap_id %u", &trap_id))
	;
      else if (unformat (line_input, "action %u", &action))
	;
      else if (unformat (line_input, "priority %u", &priority))
	;
      else if (unformat (line_input, "policer %u", &policer_index))
	;
      else
	return clib_error_return (0, "unknown input `%U'",
				  format_unformat_error, line_input);
    }
  unformat_free (line_input);

  if (trap_id == ~0)
    return clib_error_return (0, "trap_id required");

  if (action == ~0)
    return clib_error_return (0, "action required");

  vlib_worker_thread_barrier_sync (vm);
  rv = lcp_policy_add ((vl_api_lcp_trap_type_t) trap_id, (u8) action, priority,
		       policer_index);
  vlib_worker_thread_barrier_release (vm);

  if (rv)
    return clib_error_return (0, "lcp_policy_add failed (%d)", rv);

  return 0;
}

VLIB_CLI_COMMAND (lcp_copp_policy_add_command, static) = {
  .path = "test lcp copp policy add",
  .short_help = "test lcp copp policy add trap_id <id> action <0..3> "
		"priority <n> policer <index>",
  .function = lcp_copp_policy_add_command_fn,
};

static clib_error_t *
lcp_copp_policy_del_command_fn (vlib_main_t *vm, unformat_input_t *input,
				vlib_cli_command_t *cmd)
{
  u32 trap_id = ~0;
  int rv;

  if (!unformat (input, "trap_id %u", &trap_id))
    return clib_error_return (0, "trap_id required");

  vlib_worker_thread_barrier_sync (vm);
  rv = lcp_policy_delete ((vl_api_lcp_trap_type_t) trap_id);
  vlib_worker_thread_barrier_release (vm);

  if (rv)
    return clib_error_return (0, "lcp_policy_delete failed (%d)", rv);

  return 0;
}

VLIB_CLI_COMMAND (lcp_copp_policy_del_command, static) = {
  .path = "test lcp copp policy del",
  .short_help = "test lcp copp policy del trap_id <id>",
  .function = lcp_copp_policy_del_command_fn,
};

static clib_error_t *
lcp_copp_match_arbitration_command_fn (vlib_main_t *vm,
			       unformat_input_t *input,
			       vlib_cli_command_t *cmd)
{
  CLIB_UNUSED (unformat_input_t *unused_input) = input;
  CLIB_UNUSED (vlib_cli_command_t *unused_cmd) = cmd;
  const vl_api_lcp_trap_type_t traps[] = {
    LCP_TRAP_IP2ME,
    LCP_TRAP_SSH,
    LCP_TRAP_BGP,
  };
  lcp_packet_view_t view = {
    .context = LCP_MATCH_CTX_LOCAL4,
    .valid_fields = LCP_MATCH_FIELD_IP_PROTOCOL |
		    LCP_MATCH_FIELD_L4_PORTS |
		    LCP_MATCH_FIELD_HOST_BOUND,
    .state = LCP_MATCH_STATE_HOST_BOUND,
    .ip_protocol = IP_PROTOCOL_TCP,
    .l4_src_port = 179,
    .l4_dst_port = 22,
  };
  lcp_match_result_t result = { 0 };
  clib_error_t *err = 0;

  for (u32 i = 0; i < ARRAY_LEN (traps); i++)
    lcp_policy_delete (traps[i]);

  if (!lcp_match_select (&view, &result) || result.trap_type != LCP_TRAP_BGP ||
      result.evidence_rule_id != 1)
    {
      err = clib_error_return (0, "default priority arbitration failed");
      goto done;
    }

  for (u32 i = 0; i < ARRAY_LEN (traps); i++)
    if (lcp_policy_add (traps[i], LCP_COPP_ACTION_TRAP, 100,
			LCP_POLICY_INDEX_INVALID))
      {
	err = clib_error_return (0, "equal priority setup failed");
	goto done;
      }

  if (!lcp_match_select (&view, &result) ||
      result.trap_type != LCP_TRAP_IP2ME || result.evidence_rule_id != 7)
    {
      err = clib_error_return (0, "trap type fallback failed");
      goto done;
    }

  if (lcp_policy_update (LCP_TRAP_SSH, LCP_COPP_ACTION_TRAP, 200,
			 LCP_POLICY_INDEX_INVALID) ||
      !lcp_match_select (&view, &result) || result.trap_type != LCP_TRAP_SSH ||
      result.evidence_rule_id != 3)
    err = clib_error_return (0, "runtime priority arbitration failed");

  if (err)
    goto done;

  view.context = LCP_MATCH_CTX_IP4;
  view.valid_fields = LCP_MATCH_FIELD_IP_PROTOCOL |
		      LCP_MATCH_FIELD_L4_PORTS;
  view.state = 0;
  view.ip_protocol = IP_PROTOCOL_UDP;
  view.l4_src_port = 68;
  view.l4_dst_port = 67;
  if (!lcp_match_select (&view, &result) ||
      result.trap_type != LCP_TRAP_DHCP)
    {
      err = clib_error_return (0, "routed DHCP context isolation failed");
      goto done;
    }

  view.context = LCP_MATCH_CTX_L2_IP4;
  if (!lcp_match_select (&view, &result) ||
      result.trap_type != LCP_TRAP_DHCP_L2)
    {
      err = clib_error_return (0, "L2 DHCP context isolation failed");
      goto done;
    }

  view.context = LCP_MATCH_CTX_IP6;
  view.l4_src_port = 547;
  view.l4_dst_port = 546;
  if (!lcp_match_select (&view, &result) ||
      result.trap_type != LCP_TRAP_DHCPV6)
    {
      err = clib_error_return (0, "routed DHCPv6 context isolation failed");
      goto done;
    }

  view.context = LCP_MATCH_CTX_L2_IP6;
  if (!lcp_match_select (&view, &result) ||
      result.trap_type != LCP_TRAP_DHCPV6_L2)
    err = clib_error_return (0, "L2 DHCPv6 context isolation failed");

  /* IS-IS LLC classification must keep SNP and ordinary IS-IS PDUs
   * mutually exclusive. */
  view = (lcp_packet_view_t) {
    .context = LCP_MATCH_CTX_L2_DIRECT,
    .valid_fields = LCP_MATCH_FIELD_MAC | LCP_MATCH_FIELD_LLC |
                    LCP_MATCH_FIELD_ISIS_PDU,
    .dst_mac = 0x0180c2000014ULL,
    .llc_dsap = 0xfe,
    .llc_ssap = 0xfe,
    .llc_control = 0x03,
    .osi_protocol = 0x83,
    .isis_pdu_type = 24,
  };
  if (!lcp_match_select (&view, &result) || result.trap_type != LCP_TRAP_SNP)
    {
      err = clib_error_return (0, "IS-IS CSNP classification failed");
      goto done;
    }
  view.isis_pdu_type = 15;
  if (!lcp_match_select (&view, &result) || result.trap_type != LCP_TRAP_ISIS)
    err = clib_error_return (0, "IS-IS non-SNP classification failed");

done:
  for (u32 i = 0; i < ARRAY_LEN (traps); i++)
    lcp_policy_delete (traps[i]);

  if (!err)
    vlib_cli_output (vm, "match arbitration passed");
  return err;
}

VLIB_CLI_COMMAND (lcp_copp_match_arbitration_command, static) = {
  .path = "test lcp copp match arbitration",
  .short_help = "test lcp copp match arbitration",
  .function = lcp_copp_match_arbitration_command_fn,
};

static clib_error_t *
lcp_copp_legacy_actions_command_fn (vlib_main_t *vm,
				    unformat_input_t *input,
				    vlib_cli_command_t *cmd)
{
  CLIB_UNUSED (unformat_input_t *unused_input) = input;
  CLIB_UNUSED (vlib_cli_command_t *unused_cmd) = cmd;
  const vl_api_lcp_trap_type_t forward_traps[] = {
    LCP_TRAP_IGMP_QUERY,
    LCP_TRAP_IGMP_LEAVE,
    LCP_TRAP_IGMP_V1_REPORT,
    LCP_TRAP_IGMP_V2_REPORT,
    LCP_TRAP_IGMP_V3_REPORT,
    LCP_TRAP_DHCP_L2,
    LCP_TRAP_DHCPV6_L2,
    LCP_TRAP_ICCP,
    LCP_TRAP_ARP_REQUEST,
    LCP_TRAP_ARP_RESPONSE,
    LCP_TRAP_DHCP,
    LCP_TRAP_OSPF,
    LCP_TRAP_PIM,
    LCP_TRAP_VRRP,
    LCP_TRAP_DHCPV6,
    LCP_TRAP_OSPFV6,
    LCP_TRAP_VRRPV6,
    LCP_TRAP_IPV6_NEIGHBOR_DISCOVERY,
    LCP_TRAP_IPV6_MLD_V1_V2,
    LCP_TRAP_IPV6_MLD_V1_REPORT,
    LCP_TRAP_IPV6_MLD_V1_DONE,
    LCP_TRAP_MLD_V2_REPORT,
    LCP_TRAP_IPV6_NEIGHBOR_SOLICITATION,
    LCP_TRAP_IPV6_NEIGHBOR_ADVERTISEMENT,
    LCP_TRAP_ISIS,
  };
  const vl_api_lcp_trap_type_t drop_traps[] = {
    LCP_TRAP_STP,
    LCP_TRAP_LACP,
    LCP_TRAP_LLDP,
    LCP_TRAP_PTP,
    LCP_TRAP_PTP_TX_EVENT,
    LCP_TRAP_LDP,
    LCP_TRAP_IP2ME,
    LCP_TRAP_SSH,
    LCP_TRAP_SNMP,
    LCP_TRAP_BGP,
    LCP_TRAP_BGPV6,
    LCP_TRAP_BFD,
    LCP_TRAP_BFDV6,
    LCP_TRAP_BFD_MICRO,
    LCP_TRAP_BFDV6_MICRO,
    LCP_TRAP_GNMI,
    LCP_TRAP_P4RT,
    LCP_TRAP_NTPCLIENT,
    LCP_TRAP_NTPSERVER,
    LCP_TRAP_HTTPCLIENT,
    LCP_TRAP_HTTPSERVER,
    LCP_TRAP_STATIC_FDB_MOVE,
    LCP_TRAP_UNKNOWN_L3_MULTICAST,
    LCP_TRAP_SNAT_MISS,
    LCP_TRAP_DNAT_MISS,
    LCP_TRAP_NAT_HAIRPIN,
  };

  for (u32 i = 0; i < ARRAY_LEN (forward_traps); i++)
    if (lcp_legacy_action (forward_traps[i]) != LCP_COPP_ACTION_FORWARD)
      return clib_error_return (0, "trap %u does not default to FORWARD",
				forward_traps[i]);

  for (u32 i = 0; i < ARRAY_LEN (drop_traps); i++)
    if (lcp_legacy_action (drop_traps[i]) != LCP_COPP_ACTION_DROP)
      return clib_error_return (0, "trap %u does not default to DROP",
				drop_traps[i]);

  vlib_cli_output (vm, "legacy default actions passed");
  return 0;
}

VLIB_CLI_COMMAND (lcp_copp_legacy_actions_command, static) = {
  .path = "test lcp copp legacy actions",
  .short_help = "test lcp copp legacy actions",
  .function = lcp_copp_legacy_actions_command_fn,
};

static void
lcp_copp_l2_test_packet_reset (vlib_buffer_t *b, u8 vlan_count, u8 subtype,
			       u32 current_advance, u32 frame_length)
{
  ethernet_header_t *eh;
  ethernet_vlan_header_t *vlan;
  u8 *payload;
  u32 header_size;
  static const u8 dst[6] = { 0x01, 0x80, 0xc2, 0x00, 0x00, 0x02 };
  static const u8 src[6] = { 0x02, 0x00, 0x00, 0x00, 0x00, 0x01 };

  vlib_buffer_reset (b);
  clib_memset (b->data, 0, VLIB_BUFFER_DEFAULT_DATA_SIZE);
  b->flags &= ~VNET_BUFFER_FLAGS_VLAN_BITS;
  b->flags |= VNET_BUFFER_F_L2_HDR_OFFSET_VALID;
  vnet_buffer (b)->l2_hdr_offset = b->current_data;
  ethernet_buffer_set_vlan_count (b, vlan_count);

  eh = vlib_buffer_get_current (b);
  clib_memcpy_fast (eh->dst_address, dst, sizeof (dst));
  clib_memcpy_fast (eh->src_address, src, sizeof (src));
  if (vlan_count == 0)
    eh->type = clib_host_to_net_u16 (ETHERNET_TYPE_SLOW_PROTOCOLS);
  else
    {
      eh->type = clib_host_to_net_u16 (ETHERNET_TYPE_VLAN);
      vlan = (ethernet_vlan_header_t *) (eh + 1);
      for (u32 i = 0; i < vlan_count; i++)
	{
	  vlan[i].priority_cfi_and_id = clib_host_to_net_u16 (i + 1);
	  vlan[i].type = clib_host_to_net_u16 (
	    i + 1 < vlan_count ? ETHERNET_TYPE_VLAN :
				   ETHERNET_TYPE_SLOW_PROTOCOLS);
	}
    }

  header_size = sizeof (*eh) + vlan_count * sizeof (*vlan);
  payload = (u8 *) eh + header_size;
  payload[0] = subtype;
  payload[1] = 1;

  b->current_length = frame_length;
  vlib_buffer_advance (b, current_advance);
}

static clib_error_t *
lcp_copp_l2_parse_command_fn (vlib_main_t *vm, unformat_input_t *input,
			      vlib_cli_command_t *cmd)
{
  CLIB_UNUSED (unformat_input_t *unused_input) = input;
  CLIB_UNUSED (vlib_cli_command_t *unused_cmd) = cmd;
  static const struct
  {
    const char *name;
    u8 vlan_count;
    u8 subtype;
    u16 current_advance;
    u16 frame_length;
    bool expect_lacp;
    bool expect_ethertype;
    bool expect_subtype;
  } cases[] = {
    { "untagged-current-l2", 0, 1, 0, 16, true, true, true },
    { "untagged-current-payload", 0, 1, 14, 16, true, true, true },
    { "untagged-current-after-version", 0, 1, 16, 16, true, true, true },
    { "single-vlan", 1, 1, 18, 20, true, true, true },
    { "double-vlan", 2, 1, 22, 24, true, true, true },
    { "marker", 0, 2, 14, 16, false, true, true },
    { "missing-subtype", 0, 1, 14, 14, false, true, false },
    { "truncated-ethernet", 0, 1, 0, 13, false, false, false },
    { "unknown-vlan-depth", 3, 1, 26, 28, false, false, false },
  };
  u32 bi;
  vlib_buffer_t *b;
  clib_error_t *err = 0;

  if (vlib_buffer_alloc (vm, &bi, 1) != 1)
    return clib_error_return (0, "buffer allocation failed");
  b = vlib_get_buffer (vm, bi);

  for (u32 i = 0; i < ARRAY_LEN (cases); i++)
    {
      lcp_packet_view_t view;
      lcp_match_result_t result = { 0 };
      bool matched;

      lcp_copp_l2_test_packet_reset (
	b, cases[i].vlan_count, cases[i].subtype,
	cases[i].current_advance, cases[i].frame_length);
      if (!lcp_packet_parse (vm, b, LCP_MATCH_CTX_L2_DIRECT, false, &view))
	{
	  err = clib_error_return (0, "%s: packet parse failed",
				   cases[i].name);
	  goto done;
	}

      if (!!(view.valid_fields & LCP_MATCH_FIELD_ETHERTYPE) !=
	  cases[i].expect_ethertype)
	{
	  err = clib_error_return (0, "%s: unexpected ethertype validity",
				   cases[i].name);
	  goto done;
	}
      if (!!(view.valid_fields & LCP_MATCH_FIELD_SLOW_SUBTYPE) !=
	  cases[i].expect_subtype)
	{
	  err = clib_error_return (0, "%s: unexpected subtype validity",
				   cases[i].name);
	  goto done;
	}
      if (cases[i].expect_ethertype &&
	  view.ethertype != ETHERNET_TYPE_SLOW_PROTOCOLS)
	{
	  err = clib_error_return (0, "%s: ethertype 0x%x",
				   cases[i].name, view.ethertype);
	  goto done;
	}
      if (cases[i].expect_subtype && view.slow_subtype != cases[i].subtype)
	{
	  err = clib_error_return (0, "%s: subtype %u",
				   cases[i].name, view.slow_subtype);
	  goto done;
	}

      matched = lcp_match_select (&view, &result);
      if (cases[i].expect_lacp &&
	  (!matched || result.trap_type != LCP_TRAP_LACP ||
	   result.evidence_rule_id != 102))
	{
	  err = clib_error_return (0, "%s: LACP rule not selected",
				   cases[i].name);
	  goto done;
	}
      if (!cases[i].expect_lacp && matched &&
	  result.trap_type == LCP_TRAP_LACP)
	{
	  err = clib_error_return (0, "%s: unexpectedly selected LACP",
				   cases[i].name);
	  goto done;
	}
    }

done:
  vlib_buffer_free_one (vm, bi);
  if (!err)
    vlib_cli_output (vm, "L2 direct parsing passed");
  return err;
}

VLIB_CLI_COMMAND (lcp_copp_l2_parse_command, static) = {
  .path = "test lcp copp l2 parse",
  .short_help = "test lcp copp l2 parse",
  .function = lcp_copp_l2_parse_command_fn,
};

static clib_error_t *
lcp_copp_punt_command_fn (vlib_main_t *vm, unformat_input_t *input,
			  vlib_cli_command_t *cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  u32 trap_id = ~0;
  u32 action = ~0;
  u32 policer_index = ~0;
  u32 bi;
  vlib_buffer_t *b;
  lcp_action_result_t result;
  u64 before[LCP_STATS_N_COUNTERS];
  u64 after[LCP_STATS_N_COUNTERS];
  lcp_stats_counter_t c;

  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "trap_id %u", &trap_id))
	;
      else if (unformat (line_input, "action %u", &action))
	;
      else if (unformat (line_input, "policer %u", &policer_index))
	;
      else
	return clib_error_return (0, "unknown input `%U'",
				  format_unformat_error, line_input);
    }
  unformat_free (line_input);

  if (trap_id == ~0)
    return clib_error_return (0, "trap_id required");
  if (action == ~0)
    return clib_error_return (0, "action required");

  /* Ensure a policy exists for the requested action. */
  vlib_worker_thread_barrier_sync (vm);
  lcp_policy_delete ((vl_api_lcp_trap_type_t) trap_id);
  lcp_policy_add ((vl_api_lcp_trap_type_t) trap_id, (u8) action, 100,
		  policer_index);
  vlib_worker_thread_barrier_release (vm);

  if (vlib_buffer_alloc (vm, &bi, 1) != 1)
    return clib_error_return (0, "buffer allocation failed");

  b = vlib_get_buffer (vm, bi);
  vlib_buffer_reset (b);
  b->current_length = 64;
  if (!lcp_buffer_set_trap_id (b, (vl_api_lcp_trap_type_t) trap_id))
    {
      vlib_buffer_free_one (vm, bi);
      return clib_error_return (0, "invalid trap_id %u", trap_id);
    }

  for (c = 0; c < LCP_STATS_N_COUNTERS; c++)
    before[c] = lcp_stats_get ((vl_api_lcp_trap_type_t) trap_id, c);

  result = lcp_punt_process (vm, b);
  if (result.disposition == LCP_DISPOSITION_TRAP &&
      !lcp_cpu_branch_pass (vm, b))
    result.disposition = LCP_DISPOSITION_DROP;
  else if (result.disposition == LCP_DISPOSITION_COPY &&
	   result.cpu_bi != LCP_PUNT_BUFFER_INVALID &&
	   !lcp_cpu_branch_pass (vm, vlib_get_buffer (vm, result.cpu_bi)))
    {
      vlib_buffer_free_one (vm, result.cpu_bi);
      result.cpu_bi = LCP_PUNT_BUFFER_INVALID;
    }

  for (c = 0; c < LCP_STATS_N_COUNTERS; c++)
    after[c] = lcp_stats_get ((vl_api_lcp_trap_type_t) trap_id, c);

  vlib_cli_output (vm, "trap_id %u action %s disposition %u cpu_bi %u",
		   trap_id, lcp_copp_action_name ((u8) action),
		   result.disposition, result.cpu_bi);
  vlib_cli_output (vm, "trap_hit %+lld punt_required %+lld punt_pass %+lld "
			"punt_drop %+lld delivery_drop %+lld",
		   (long long) (after[LCP_STATS_TRAP_HIT] -
				before[LCP_STATS_TRAP_HIT]),
		   (long long) (after[LCP_STATS_PUNT_REQUIRED] -
				before[LCP_STATS_PUNT_REQUIRED]),
		   (long long) (after[LCP_STATS_PUNT_PASS] -
				before[LCP_STATS_PUNT_PASS]),
		   (long long) (after[LCP_STATS_PUNT_DROP] -
				before[LCP_STATS_PUNT_DROP]),
		   (long long) (after[LCP_STATS_DELIVERY_DROP] -
				before[LCP_STATS_DELIVERY_DROP]));

  if (result.cpu_bi != LCP_PUNT_BUFFER_INVALID)
    vlib_buffer_free_one (vm, result.cpu_bi);
  vlib_buffer_free_one (vm, bi);

  /* Clean up the transient policy. */
  vlib_worker_thread_barrier_sync (vm);
  lcp_policy_delete ((vl_api_lcp_trap_type_t) trap_id);
  vlib_worker_thread_barrier_release (vm);

  return 0;
}

VLIB_CLI_COMMAND (lcp_copp_punt_command, static) = {
  .path = "test lcp copp punt",
  .short_help = "test lcp copp punt trap_id <id> action <0..3> "
		"[policer <index>]",
  .function = lcp_copp_punt_command_fn,
};

static clib_error_t *
lcp_copp_punt_all_command_fn (vlib_main_t *vm, unformat_input_t *input,
			      vlib_cli_command_t *cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  u32 trap_id = ~0;
  u32 bi;
  vlib_buffer_t *b;
  lcp_action_result_t result;
  u64 before[LCP_STATS_N_COUNTERS];
  u64 after[LCP_STATS_N_COUNTERS];
  lcp_stats_counter_t c;
  int action;
  static const struct
  {
    u8 action;
    lcp_disposition_t expected_disposition;
    int expect_copy;
    u64 expected_hit;
    u64 expected_required;
    u64 expected_pass;
    u64 expected_drop;
  } cases[] = {
    { LCP_COPP_ACTION_DROP, LCP_DISPOSITION_DROP, 0, 1, 0, 0, 1 },
    { LCP_COPP_ACTION_FORWARD, LCP_DISPOSITION_FORWARD, 0, 1, 0, 0, 0 },
    { LCP_COPP_ACTION_COPY, LCP_DISPOSITION_COPY, 1, 1, 1, 1, 0 },
    { LCP_COPP_ACTION_TRAP, LCP_DISPOSITION_TRAP, 0, 1, 1, 1, 0 },
  };

  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "trap_id %u", &trap_id))
	;
      else
	return clib_error_return (0, "unknown input `%U'",
				  format_unformat_error, line_input);
    }
  unformat_free (line_input);

  if (trap_id == ~0)
    return clib_error_return (0, "trap_id required");

  if (lcp_policy_get (LCP_TRAP_INVALID) != 0 ||
      lcp_policy_get ((vl_api_lcp_trap_type_t) 255) != 0 ||
      lcp_policy_is_configured (LCP_TRAP_INVALID) ||
      lcp_policy_is_configured ((vl_api_lcp_trap_type_t) 255))
    return clib_error_return (0, "invalid trap boundary is not fail-closed");

  if (vlib_buffer_alloc (vm, &bi, 1) != 1)
    return clib_error_return (0, "buffer allocation failed");

  b = vlib_get_buffer (vm, bi);
  if (!lcp_buffer_set_trap_id (b, LCP_TRAP_DEFAULT))
    {
      vlib_buffer_free_one (vm, bi);
      return clib_error_return (0, "valid trap_id rejected by setter");
    }
  if (lcp_buffer_set_trap_id (b, (vl_api_lcp_trap_type_t) 255) ||
      vnet_buffer2 (b)->trap_id != LCP_TRAP_DEFAULT)
    {
      vlib_buffer_free_one (vm, bi);
      return clib_error_return (
	0, "invalid trap_id accepted or changed buffer metadata");
    }

  /* Simulate corrupted producer metadata and verify dataplane fail-closed. */
  vnet_buffer2 (b)->trap_id = 255;
  result = lcp_punt_process (vm, b);
  if (result.disposition != LCP_DISPOSITION_DROP ||
      result.cpu_bi != LCP_PUNT_BUFFER_INVALID)
    {
      vlib_buffer_free_one (vm, bi);
      return clib_error_return (0, "invalid trap_id did not fail closed");
    }

  for (action = 0; action < ARRAY_LEN (cases); action++)
    {
      vlib_worker_thread_barrier_sync (vm);
      lcp_policy_delete ((vl_api_lcp_trap_type_t) trap_id);
      lcp_policy_add ((vl_api_lcp_trap_type_t) trap_id, cases[action].action,
		      100, LCP_POLICY_INDEX_INVALID);
      vlib_worker_thread_barrier_release (vm);

      b = vlib_get_buffer (vm, bi);
      vlib_buffer_reset (b);
      b->current_length = 78;
      clib_memset (vlib_buffer_get_current (b), 0xa5, 14);
      vlib_buffer_advance (b, 14);
      b->flags |= VNET_BUFFER_F_L2_HDR_OFFSET_VALID;
      vnet_buffer (b)->l2_hdr_offset = b->current_data - 14;
      if (!lcp_buffer_set_trap_id (b,
				   (vl_api_lcp_trap_type_t) trap_id))
	{
	  vlib_buffer_free_one (vm, bi);
	  return clib_error_return (0, "invalid trap_id %u", trap_id);
	}

      for (c = 0; c < LCP_STATS_N_COUNTERS; c++)
	before[c] = lcp_stats_get ((vl_api_lcp_trap_type_t) trap_id, c);

      result = lcp_punt_process (vm, b);

      if (b->current_data !=
	  vnet_buffer (b)->l2_hdr_offset + 14)
	{
	  vlib_buffer_free_one (vm, bi);
	  return clib_error_return (
	    0, "action %s: original buffer offset changed",
	    lcp_copp_action_name (cases[action].action));
	}

      for (c = 0; c < LCP_STATS_N_COUNTERS; c++)
	after[c] = lcp_stats_get ((vl_api_lcp_trap_type_t) trap_id, c);

      if (result.disposition != cases[action].expected_disposition)
	{
	  vlib_buffer_free_one (vm, bi);
	  return clib_error_return (
	    0, "action %s: disposition mismatch (expected %u, got %u)",
	    lcp_copp_action_name (cases[action].action),
	    cases[action].expected_disposition, result.disposition);
	}

      if (cases[action].expect_copy)
	{
	  if (result.cpu_bi == LCP_PUNT_BUFFER_INVALID)
	    {
	      vlib_buffer_free_one (vm, bi);
	      return clib_error_return (0, "action %s: expected copy buffer",
					lcp_copp_action_name (
					  cases[action].action));
	    }
	  if (vlib_get_buffer (vm, result.cpu_bi)->current_data !=
	      b->current_data)
	    {
	      vlib_buffer_free_one (vm, result.cpu_bi);
	      vlib_buffer_free_one (vm, bi);
	      return clib_error_return (0,
		"action %s: copy buffer offset differs from original",
		lcp_copp_action_name (cases[action].action));
	    }
	  if (memcmp (vlib_buffer_get_current (
			 vlib_get_buffer (vm, result.cpu_bi)) - 14,
		      vlib_buffer_get_current (b) - 14, 14) != 0)
	    {
	      vlib_buffer_free_one (vm, result.cpu_bi);
	      vlib_buffer_free_one (vm, bi);
	      return clib_error_return (
		0, "action %s: copy buffer L2 headroom differs from original",
		lcp_copp_action_name (cases[action].action));
	    }
	  if (!lcp_cpu_branch_pass (
		vm, vlib_get_buffer (vm, result.cpu_bi)))
	    {
	      vlib_buffer_free_one (vm, result.cpu_bi);
	      vlib_buffer_free_one (vm, bi);
	      return clib_error_return (
		0, "action %s: CPU copy unexpectedly failed policer",
		lcp_copp_action_name (cases[action].action));
	    }
	  vlib_buffer_free_one (vm, result.cpu_bi);
	}
      else if (result.cpu_bi != LCP_PUNT_BUFFER_INVALID)
	{
	  vlib_buffer_free_one (vm, result.cpu_bi);
	  vlib_buffer_free_one (vm, bi);
	  return clib_error_return (0, "action %s: unexpected copy buffer",
				    lcp_copp_action_name (
				      cases[action].action));
	}
      else if (result.disposition == LCP_DISPOSITION_TRAP &&
	       !lcp_cpu_branch_pass (vm, b))
	{
	  vlib_buffer_free_one (vm, bi);
	  return clib_error_return (
	    0, "action %s: TRAP unexpectedly failed policer",
	    lcp_copp_action_name (cases[action].action));
	}

#define LCP_CHECK_COUNTER(name, field)                                        \
  if (after[field] - before[field] != cases[action].expected_##name)          \
    {                                                                         \
      vlib_buffer_free_one (vm, bi);                                          \
      return clib_error_return (                                              \
	0, "action %s: " #name " mismatch (expected %llu, got %llu)",        \
	lcp_copp_action_name (cases[action].action),                          \
	(long long) cases[action].expected_##name,                            \
	(long long) (after[field] - before[field]));                          \
    }

      LCP_CHECK_COUNTER (hit, LCP_STATS_TRAP_HIT);
      LCP_CHECK_COUNTER (required, LCP_STATS_PUNT_REQUIRED);
      LCP_CHECK_COUNTER (pass, LCP_STATS_PUNT_PASS);
      LCP_CHECK_COUNTER (drop, LCP_STATS_PUNT_DROP);
#undef LCP_CHECK_COUNTER
    }

  vlib_buffer_free_one (vm, bi);

  vlib_worker_thread_barrier_sync (vm);
  lcp_policy_delete ((vl_api_lcp_trap_type_t) trap_id);
  vlib_worker_thread_barrier_release (vm);

  vlib_cli_output (vm, "all actions passed for trap_id %u", trap_id);
  return 0;
}

VLIB_CLI_COMMAND (lcp_copp_punt_all_command, static) = {
  .path = "test lcp copp punt all",
  .short_help = "test lcp copp punt all trap_id <id>",
  .function = lcp_copp_punt_all_command_fn,
};

static clib_error_t *
lcp_copp_ip6_ext_command_fn (vlib_main_t *vm, unformat_input_t *input,
			     vlib_cli_command_t *cmd)
{
  CLIB_UNUSED (unformat_input_t *uinput) = input;
  CLIB_UNUSED (vlib_cli_command_t *ucmd) = cmd;
  static const ip6_address_t src = {
    .as_u8 = { 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0,
	       0, 0, 0, 0, 0, 0, 0, 0x01 },
  };
  static const ip6_address_t dst = {
    .as_u8 = { 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0,
	       0, 0, 0, 0, 0, 0, 0, 0x02 },
  };
  u32 bi;
  vlib_buffer_t *b;
  ip6_header_t *ip6;
  lcp_packet_view_t view;
  clib_error_t *err = 0;
  u8 *p;

  if (vlib_buffer_alloc (vm, &bi, 1) != 1)
    return clib_error_return (0, "buffer allocation failed");
  b = vlib_get_buffer (vm, bi);

#define IP6_RESET(_payload_len)                                               \
  do {                                                                        \
    vlib_buffer_reset (b);                                                    \
    clib_memset (b->data, 0, VLIB_BUFFER_DEFAULT_DATA_SIZE);                  \
    ip6 = (ip6_header_t *) (b->data + b->current_data);                       \
    ip6->ip_version_traffic_class_and_flow_label =                            \
      clib_host_to_net_u32 (0x60000000);                                      \
    ip6->payload_length = clib_host_to_net_u16 (_payload_len);                \
    ip6->hop_limit = 64;                                                      \
    ip6->src_address = src;                                                   \
    ip6->dst_address = dst;                                                   \
    b->current_length = sizeof (*ip6) + (_payload_len);                       \
  } while (0)

#define CHECK_FIELD(_field, _expected, _fmt)                                  \
  do {                                                                        \
    if ((_field) != (_expected))                                              \
      {                                                                       \
        err = clib_error_return (0, _fmt, (_field), (_expected));             \
        goto done;                                                            \
      }                                                                       \
  } while (0)

  /* IPv6 + UDP: hdr_chain.length == 1, last protocol UDP, eh[last].offset
   * points at the UDP header. */
  IP6_RESET (8);
  ip6->protocol = IP_PROTOCOL_UDP;
  p = (u8 *) (ip6 + 1);
  p[0] = 0xc3;
  p[1] = 0x50; /* src port 50000 */
  p[2] = 0x00;
  p[3] = 0xa1; /* dst port 161 */
  if (!lcp_packet_parse (vm, b, LCP_MATCH_CTX_IP6, false, &view))
    {
      err = clib_error_return (0, "IPv6+UDP parse failed");
      goto done;
    }
  CHECK_FIELD (view.ip_protocol, IP_PROTOCOL_UDP,
	       "IPv6+UDP: protocol %u != %u");
  CHECK_FIELD (view.valid_fields & LCP_MATCH_FIELD_L4_PORTS,
	       LCP_MATCH_FIELD_L4_PORTS,
	       "IPv6+UDP: L4 ports not parsed (valid_fields %u != %u)");
  CHECK_FIELD (view.l4_dst_port, 161, "IPv6+UDP: dst port %u != %u");
  CHECK_FIELD (view.state & LCP_MATCH_STATE_TRUSTED_L4,
	       LCP_MATCH_STATE_TRUSTED_L4,
	       "IPv6+UDP: not trusted L4 (state %u != %u)");

  /* IPv6 + TCP: hdr_chain.length == 1, last protocol TCP. */
  IP6_RESET (20);
  ip6->protocol = IP_PROTOCOL_TCP;
  p = (u8 *) (ip6 + 1);
  p[0] = 0xc3;
  p[1] = 0x50; /* src port 50000 */
  p[2] = 0x00;
  p[3] = 0x16; /* dst port 22 */
  if (!lcp_packet_parse (vm, b, LCP_MATCH_CTX_IP6, false, &view))
    {
      err = clib_error_return (0, "IPv6+TCP parse failed");
      goto done;
    }
  CHECK_FIELD (view.ip_protocol, IP_PROTOCOL_TCP,
	       "IPv6+TCP: protocol %u != %u");
  CHECK_FIELD (view.l4_dst_port, 22, "IPv6+TCP: dst port %u != %u");

  /* IPv6 + Hop-by-Hop + UDP: chain walks HBH, last protocol UDP. */
  IP6_RESET (16);
  ip6->protocol = IP_PROTOCOL_IP6_HOP_BY_HOP_OPTIONS;
  p = (u8 *) (ip6 + 1);
  p[0] = IP_PROTOCOL_UDP; /* HBH next header */
  p[1] = 0;		      /* HBH length: 8 bytes total */
  p += 8;
  p[0] = 0xc3;
  p[1] = 0x50;
  p[2] = 0x00;
  p[3] = 0xa1;
  if (!lcp_packet_parse (vm, b, LCP_MATCH_CTX_IP6, false, &view))
    {
      err = clib_error_return (0, "IPv6+HBH+UDP parse failed");
      goto done;
    }
  CHECK_FIELD (view.ip_protocol, IP_PROTOCOL_UDP,
	       "IPv6+HBH+UDP: protocol %u != %u");
  CHECK_FIELD (view.l4_dst_port, 161, "IPv6+HBH+UDP: dst port %u != %u");

  /* IPv6 + Routing + UDP: chain walks Routing, last protocol UDP. */
  IP6_RESET (16);
  ip6->protocol = IP_PROTOCOL_IPV6_ROUTE;
  p = (u8 *) (ip6 + 1);
  p[0] = IP_PROTOCOL_UDP; /* Routing next header */
  p[1] = 0;		      /* Routing length: 8 bytes total */
  p += 8;
  p[0] = 0xc3;
  p[1] = 0x50;
  p[2] = 0x00;
  p[3] = 0xa1;
  if (!lcp_packet_parse (vm, b, LCP_MATCH_CTX_IP6, false, &view))
    {
      err = clib_error_return (0, "IPv6+Routing+UDP parse failed");
      goto done;
    }
  CHECK_FIELD (view.ip_protocol, IP_PROTOCOL_UDP,
	       "IPv6+Routing+UDP: protocol %u != %u");
  CHECK_FIELD (view.l4_dst_port, 161, "IPv6+Routing+UDP: dst port %u != %u");

  /* IPv6 + Destination Options + UDP: chain walks DestOpt, last protocol UDP. */
  IP6_RESET (16);
  ip6->protocol = IP_PROTOCOL_IP6_DESTINATION_OPTIONS;
  p = (u8 *) (ip6 + 1);
  p[0] = IP_PROTOCOL_UDP; /* DestOpt next header */
  p[1] = 0;		      /* DestOpt length: 8 bytes total */
  p += 8;
  p[0] = 0xc3;
  p[1] = 0x50;
  p[2] = 0x00;
  p[3] = 0xa1;
  if (!lcp_packet_parse (vm, b, LCP_MATCH_CTX_IP6, false, &view))
    {
      err = clib_error_return (0, "IPv6+DestOpt+UDP parse failed");
      goto done;
    }
  CHECK_FIELD (view.ip_protocol, IP_PROTOCOL_UDP,
	       "IPv6+DestOpt+UDP: protocol %u != %u");
  CHECK_FIELD (view.l4_dst_port, 161, "IPv6+DestOpt+UDP: dst port %u != %u");

  /* IPv6 first fragment + UDP: fragment_index >= 0, fragment offset == 0,
   * last protocol UDP, L4 ports parsed. */
  IP6_RESET (16);
  ip6->protocol = IP_PROTOCOL_IPV6_FRAGMENTATION;
  p = (u8 *) (ip6 + 1);
  p[0] = IP_PROTOCOL_UDP; /* Fragment next header */
  p[1] = 0;		      /* reserved */
  /* fragment_offset_and_more: offset=0, M=1 */
  p[2] = 0x00;
  p[3] = 0x01;
  p[4] = 0;
  p[5] = 0;
  p[6] = 0;
  p[7] = 1; /* identification */
  p += 8;
  p[0] = 0xc3;
  p[1] = 0x50;
  p[2] = 0x00;
  p[3] = 0xa1;
  if (!lcp_packet_parse (vm, b, LCP_MATCH_CTX_IP6, false, &view))
    {
      err = clib_error_return (0, "IPv6+frag0+UDP parse failed");
      goto done;
    }
  CHECK_FIELD (view.ip_protocol, IP_PROTOCOL_UDP,
	       "IPv6+frag0+UDP: protocol %u != %u");
  CHECK_FIELD (view.l4_dst_port, 161, "IPv6+frag0+UDP: dst port %u != %u");
  CHECK_FIELD (view.state & LCP_MATCH_STATE_FRAGMENT, LCP_MATCH_STATE_FRAGMENT,
	       "IPv6+frag0+UDP: not marked fragment (state %u != %u)");

  vnet_buffer (b)->ip.reass.ip_proto = IP_PROTOCOL_UDP;
  vnet_buffer (b)->ip.reass.l4_src_port = clib_host_to_net_u16 (50000);
  vnet_buffer (b)->ip.reass.l4_dst_port = clib_host_to_net_u16 (161);
  vnet_buffer (b)->ip.reass.l4_layer_truncated = 0;
  vnet_buffer (b)->ip.reass.is_non_first_fragment = 0;
  if (!lcp_packet_parse (vm, b, LCP_MATCH_CTX_IP6, true, &view))
    {
      err = clib_error_return (0, "IPv6+frag0 metadata parse failed");
      goto done;
    }
  CHECK_FIELD (view.l4_dst_port, 161,
	       "IPv6+frag0 metadata: dst port %u != %u");

  /* IPv6 non-first fragment: fragment_index >= 0, fragment offset != 0.
   * The fragment next header is UDP but L4 ports must not be parsed. */
  IP6_RESET (16);
  ip6->protocol = IP_PROTOCOL_IPV6_FRAGMENTATION;
  p = (u8 *) (ip6 + 1);
  p[0] = IP_PROTOCOL_UDP; /* Fragment next header */
  p[1] = 0;		      /* reserved */
  /* fragment_offset_and_more: offset=1 (8 bytes), M=1 */
  p[2] = 0x00;
  p[3] = 0x09;
  p[4] = 0;
  p[5] = 0;
  p[6] = 0;
  p[7] = 1; /* identification */
  p += 8;
  clib_memset (p, 0, 8);
  if (!lcp_packet_parse (vm, b, LCP_MATCH_CTX_IP6, false, &view))
    {
      err = clib_error_return (0, "IPv6+fragN parse failed");
      goto done;
    }
  CHECK_FIELD (view.ip_protocol, IP_PROTOCOL_UDP,
	       "IPv6+fragN: protocol %u != %u");
  CHECK_FIELD (view.state & LCP_MATCH_STATE_NON_FIRST_FRAGMENT,
	       LCP_MATCH_STATE_NON_FIRST_FRAGMENT,
	       "IPv6+fragN: not marked non-first fragment (state %u != %u)");
  CHECK_FIELD (view.valid_fields & LCP_MATCH_FIELD_L4_PORTS, 0,
	       "IPv6+fragN: unexpectedly parsed L4 ports (valid_fields %u != %u)");

  /* The same non-first fragment can use shallow-reassembly metadata only
   * when its producer has explicitly proved that the feature ran. */
  vnet_buffer (b)->ip.reass.ip_proto = IP_PROTOCOL_UDP;
  vnet_buffer (b)->ip.reass.l4_src_port = clib_host_to_net_u16 (50000);
  vnet_buffer (b)->ip.reass.l4_dst_port = clib_host_to_net_u16 (161);
  vnet_buffer (b)->ip.reass.l4_layer_truncated = 0;
  vnet_buffer (b)->ip.reass.is_non_first_fragment = 1;
  if (!lcp_packet_parse (vm, b, LCP_MATCH_CTX_IP6, false, &view))
    {
      err = clib_error_return (0, "IPv6+fragN stale metadata parse failed");
      goto done;
    }
  CHECK_FIELD (view.valid_fields & LCP_MATCH_FIELD_L4_PORTS, 0,
	       "IPv6+fragN stale metadata: L4 fields %u != %u");

  if (!lcp_packet_parse (vm, b, LCP_MATCH_CTX_IP6, true, &view))
    {
      err = clib_error_return (0, "IPv6+fragN metadata parse failed");
      goto done;
    }
  CHECK_FIELD (view.l4_dst_port, 161,
	       "IPv6+fragN metadata: dst port %u != %u");

  /* Truncated metadata preserves safe L3 classification but never exposes
   * ports. */
  vnet_buffer (b)->ip.reass.l4_layer_truncated = 1;
  if (!lcp_packet_parse (vm, b, LCP_MATCH_CTX_IP6, true, &view))
    {
      err = clib_error_return (0, "IPv6+fragN truncated parse failed");
      goto done;
    }
  CHECK_FIELD (view.valid_fields & LCP_MATCH_FIELD_L4_PORTS, 0,
	       "IPv6+fragN truncated: L4 fields %u != %u");

  /* IPv6 malformed extension chain: HBH next header points to a non-
   * extension protocol (IPv4).  The chain terminates at the bogus next
   * header, eh[last].protocol == IPv4, and UDP is never reached. */
  IP6_RESET (16);
  ip6->protocol = IP_PROTOCOL_IP6_HOP_BY_HOP_OPTIONS;
  p = (u8 *) (ip6 + 1);
  p[0] = 4; /* HBH next header = IPv4, not an extension header */
  p[1] = 0;
  p += 8;
  p[0] = 0xc3;
  p[1] = 0x50;
  p[2] = 0x00;
  p[3] = 0xa1;
  if (!lcp_packet_parse (vm, b, LCP_MATCH_CTX_IP6, false, &view))
    {
      err = clib_error_return (0, "IPv6+malformed parse failed");
      goto done;
    }
  CHECK_FIELD (view.ip_protocol, 4, "IPv6+malformed: protocol %u != %u");
  CHECK_FIELD (view.valid_fields & LCP_MATCH_FIELD_L4_PORTS, 0,
	       "IPv6+malformed: unexpectedly parsed L4 ports (valid_fields %u != %u)");

  /* IPv6 truncated extension header: HBH length claims 64 bytes but only
   * 2 bytes follow.  ip6_ext_header_walk returns fragment_index < 0,
   * lcp_parse_ip6 bails out without IP_PROTOCOL. */
  IP6_RESET (2);
  ip6->protocol = IP_PROTOCOL_IP6_HOP_BY_HOP_OPTIONS;
  p = (u8 *) (ip6 + 1);
  p[0] = IP_PROTOCOL_UDP;
  p[1] = 7; /* length claims 64 bytes, but only 2 bytes available */
  if (!lcp_packet_parse (vm, b, LCP_MATCH_CTX_IP6, false, &view))
    {
      err = clib_error_return (0, "IPv6+truncated parse failed");
      goto done;
    }
  CHECK_FIELD (view.valid_fields & LCP_MATCH_FIELD_IP_PROTOCOL, 0,
	       "IPv6+truncated: unexpectedly set IP_PROTOCOL (valid_fields %u != %u)");

#undef IP6_RESET
#undef CHECK_FIELD

done:
  vlib_buffer_free_one (vm, bi);
  if (err)
    return err;
  vlib_cli_output (vm, "IPv6 extension header parse tests passed");
  return 0;
}

VLIB_CLI_COMMAND (lcp_copp_ip6_ext_command, static) = {
  .path = "test lcp copp ip6 ext",
  .short_help = "test lcp copp ip6 ext",
  .function = lcp_copp_ip6_ext_command_fn,
};

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
