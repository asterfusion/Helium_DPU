#!/usr/bin/env python3
from pathlib import Path
import re
import unittest


PLUGIN = Path(__file__).resolve().parents[1]


class IpoePluginContractTest(unittest.TestCase):
    def source(self, name):
        return (PLUGIN / name).read_text()

    def test_plugin_registers_focused_sources(self):
        cmake = self.source("CMakeLists.txt")
        self.assertIn("add_vpp_plugin(ipoe", cmake)
        for source in (
            "ipoe.c", "ipoe_session.c", "ipoe_timer.c", "ipoe_cli.c",
            "ipoe_api.c",
        ):
            self.assertIn(source, cmake)
        self.assertIn("ipoe.api", cmake)

    def test_binary_api_configures_interfaces_and_sessions_only(self):
        api = self.source("ipoe.api")
        handler = self.source("ipoe_api.c")
        header = self.source("ipoe.h")
        for message in (
            "ipoe_interface_enable_disable",
            "ipoe_session_set_state",
        ):
            self.assertIn(f"autoreply define {message}", api)
            self.assertIn(f"vl_api_{message}_t_handler", handler)
        self.assertIn("define ipoe_session_add_del", api)
        self.assertIn("define ipoe_session_add_del_reply", api)
        for field in (
            "bool has_qinq",
            "vl_api_mac_address_t local_mac",
            "vl_api_interface_index_t parent_sw_if_index",
            "u16 outer_tpid",
            "u16 outer_vlan",
            "u16 inner_tpid",
            "u16 inner_vlan",
        ):
            self.assertIn(field, api)
        self.assertIn("u32 counter_index", api)
        self.assertIn("rmp->counter_index = htonl (counter_index)", handler)
        for token in (
            "ipoe_interface_enable_disable",
            "ipoe_session_add",
            "ipoe_session_del",
            "ipoe_session_set_state",
            "ip4_address_decode",
            "mac_address_decode",
            "setup_message_id_table",
        ):
            self.assertIn(token, handler)
        self.assertIn("ipoe_session_set_state", header)
        for unsupported in (
            "ipoe_interface_dump",
            "ipoe_session_dump",
            "ipoe_session_stats_dump",
        ):
            self.assertNotIn(unsupported, api)

    def test_batch_session_apis_bound_work_and_preserve_item_identity(self):
        api = self.source("ipoe.api")
        handler = self.source("ipoe_api.c")
        header = self.source("ipoe.h")
        session = self.source("ipoe_session.c")

        for message in (
            "ipoe_session_add_batch",
            "ipoe_session_quiesce_snapshot_batch",
        ):
            self.assertIn(f"define {message}", api)
            self.assertIn(f"vl_api_{message}_t_handler", handler)
        self.assertIn("IPOE_SESSION_ADD_BATCH_MAX 64", header)
        self.assertIn("IPOE_SESSION_SNAPSHOT_BATCH_MAX 128", header)
        self.assertIn("ipoe_session_add_locked", session)
        self.assertIn("session->generation != generations[i]", session)
        self.assertIn(
            "vl_api_ipoe_session_quiesce_entry_t entries[count]",
            api)
        self.assertNotIn("u64 indices[count]", api)
        snapshot = api.split("typedef ipoe_session_snapshot_result", 1)[1]
        snapshot = snapshot.split("};", 1)[0]
        self.assertNotIn("upstream_forward_packets", snapshot)

    def test_session_control_plane_boundary_validates_user_identity(self):
        session = self.source("ipoe_session.c")
        cli = self.source("ipoe_cli.c")
        for token in (
            "user_ip4->as_u32 == 0",
            "ip4_address_is_multicast (user_ip4)",
            "ip4_address_is_global_broadcast (user_ip4)",
            "admin_state = !!admin_state",
        ):
            self.assertIn(token, session)
        self.assertIn("admin_state=%u", cli)

    def test_core_models_and_lifecycle_api_exist(self):
        header = self.source("ipoe.h")
        for token in (
            "ipoe_interface_t", "ipoe_session_t", "ipoe_main_t",
            "ipoe_interface_enable_disable", "ipoe_session_add",
            "ipoe_session_del", "session_by_index", "session_by_user",
        ):
            self.assertIn(token, header)

    def test_external_session_index_is_distinct_from_pool_index(self):
        header = self.source("ipoe.h")
        session = self.source("ipoe_session.c")
        cli = self.source("ipoe_cli.c")
        self.assertIn("u64 external_index;", header)
        self.assertIn("u32 session_index;", session)
        self.assertIn('unformat (input, "index %llu"', cli)
        self.assertIn('"IPoE session %llu"', cli)
        for obsolete in ("session_handle", "session_by_handle"):
            self.assertNotIn(obsolete, header)
            self.assertNotIn(obsolete, session)
        self.assertNotIn('unformat (input, "handle %llu"', cli)

    def test_vpp_symbol_declaration_headers_are_explicit(self):
        header = self.source("ipoe.h")
        plugin = self.source("ipoe.c")
        self.assertIn("#include <vnet/ip/format.h>", header)
        self.assertIn("#include <vpp/app/version.h>", plugin)

    def test_gate_interface_identity_does_not_duplicate_vlan_classification(self):
        header = self.source("ipoe.h")
        core = self.source("ipoe.c")
        cli = self.source("ipoe_cli.c")
        for obsolete in ("IPOE_BIND_", "bind_type", "vlan_id"):
            self.assertNotIn(obsolete, header)
            self.assertNotIn(obsolete, core)
        self.assertNotIn('unformat (input, "bind ', cli)
        self.assertNotIn('unformat (input, "vlan ', cli)
        self.assertIn('enable mode <l2|l3>', cli)
        self.assertIn('input <l2-input|ip4-input>', cli)

    def test_timer_wheel_drives_expiration_without_hash_scan(self):
        header = self.source("ipoe.h")
        timer = self.source("ipoe_timer.c")
        self.assertIn("tw_timer_wheel_1t_3w_1024sl_ov_t", header)
        self.assertIn("tw_timer_expire_timers_1t_3w_1024sl_ov", timer)
        self.assertIn("ipoe_session_expire", timer)
        self.assertIn("IPOE_TIMER_INDEX_BITS", timer)
        self.assertRegex(
            timer,
            re.compile(r"timer_generation\s*!=\s*\n?\s*\(session->timer_generation"),
        )
        self.assertIn("VLIB_REGISTER_NODE", timer)
        self.assertNotIn("hash_foreach", timer)

    def test_timer_process_is_started_by_vpp_after_core_init(self):
        timer = self.source("ipoe_timer.c")
        self.assertNotIn("VLIB_NODE_STATE_DISABLED", timer)
        self.assertNotIn("vlib_start_process", timer)

    def test_standalone_cli_paths_and_show_fields_exist(self):
        cli = self.source("ipoe_cli.c")
        for path in (
            '"set ipoe interface"', '"set ipoe session"',
            '"show ipoe interface"', '"show ipoe session"',
        ):
            self.assertIn(path, cli)
        for field in (
            "IPoE interface %U", "access mode:", "input path:",
            "IPoE session %llu", "user IPv4:", "counter index:",
        ):
            self.assertIn(field, cli)

    def test_session_counters_have_stable_stats_paths_and_show_command(self):
        header = self.source("ipoe.h")
        core = self.source("ipoe.c")
        session = self.source("ipoe_session.c")
        cli = self.source("ipoe_cli.c")
        for token in (
            "IPOE_SESSION_COUNTER_UPSTREAM_FORWARD",
            "IPOE_SESSION_COUNTER_DOWNSTREAM_FORWARD",
            "IPOE_SESSION_COUNTER_UPSTREAM_GATE_DROP",
            "IPOE_SESSION_COUNTER_DOWNSTREAM_GATE_DROP",
            "counter_index",
        ):
            self.assertIn(token, header)
        for path in (
            "/ipoe/session/upstream-forward",
            "/ipoe/session/downstream-forward",
            "/ipoe/session/upstream-gate-drop",
            "/ipoe/session/downstream-gate-drop",
        ):
            self.assertIn(path, core)
        for token in (
            "vlib_validate_combined_counter",
            "vlib_zero_combined_counter",
            "vlib_increment_combined_counter",
            "vlib_get_combined_counter",
            "ipoe_session_counter_allocate",
            "ipoe_session_counter_release",
        ):
            self.assertIn(token, session)
        self.assertIn('"show ipoe session stats"', cli)
        self.assertIn("IPoE session %llu statistics", cli)
        self.assertIn("gate-drop:", cli)

    def test_data_plane_counter_points_use_complete_l2_frame_length(self):
        l2_input = self.source("ipoe_l2_input_node.c")
        l3_input = self.source("ipoe_ip4_input_node.c")
        output = self.source("ipoe_output_node.c")
        for node in (l2_input, l3_input):
            self.assertIn("IPOE_SESSION_COUNTER_UPSTREAM_FORWARD", node)
            self.assertIn("IPOE_SESSION_COUNTER_UPSTREAM_GATE_DROP", node)
        self.assertIn("IPOE_SESSION_COUNTER_DOWNSTREAM_FORWARD", output)
        self.assertIn("IPOE_SESSION_COUNTER_DOWNSTREAM_GATE_DROP", output)
        self.assertIn("u32 frame_bytes = vlib_buffer_length_in_chain (vm, b)",
                      l2_input)
        self.assertIn("*packet_bytes = frame_bytes", l2_input)
        self.assertIn("ipoe_ip4_get_l2_header_bytes", l3_input)
        self.assertIn("*packet_bytes = l2_header_bytes + view.packet_ip4_bytes",
                      l3_input)
        self.assertIn("*packet_bytes = vlib_buffer_length_in_chain (vm, b)",
                      output)

    def test_expiry_deletes_session_and_releases_counter(self):
        session = self.source("ipoe_session.c")
        expire = session[session.index("ipoe_session_expire") :]
        self.assertIn("ipoe_session_remove_index (session_index, 0)", expire)

    def test_binding_change_does_not_delete_existing_session(self):
        session = self.source("ipoe_session.c")
        add = session[session.index("ipoe_session_add") :
                      session.index("ipoe_session_del")]
        self.assertIn("return IPOE_ERROR_ALREADY_EXISTS", add)
        self.assertNotIn("ipoe_session_remove_index (session_index, 1)", add)

    def test_session_update_replaces_user_index_atomically(self):
        api = self.source("ipoe.api")
        handler = self.source("ipoe_api.c")
        header = self.source("ipoe.h")
        session = self.source("ipoe_session.c")
        cli = self.source("ipoe_cli.c")

        self.assertIn("autoreply define ipoe_session_update", api)
        self.assertIn("vl_api_ipoe_session_update_t_handler", handler)
        self.assertIn("int ipoe_session_update", header)
        self.assertIn('unformat (input, "update")', cli)
        update = session[session.index("ipoe_session_update_locked") :]
        for token in (
            "generation < session->generation",
            "IPOE_ERROR_IP_CONFLICT",
            "hash_unset (im->session_by_user",
            "hash_set (im->session_by_user",
            "ipoe_timer_update",
            "vlib_worker_thread_barrier_sync",
            "vlib_worker_thread_barrier_release",
        ):
            self.assertIn(token, update)

    def test_renewal_advances_generation_monotonically(self):
        session = self.source("ipoe_session.c")
        update = session[
            session.index("p = hash_get (im->session_by_index"):
            session.index("return IPOE_ERROR_ALREADY_EXISTS", session.index(
                "p = hash_get (im->session_by_index"))
        ]

        self.assertIn("generation < session->generation", update)
        self.assertIn("session->generation = generation", update)

    def test_qinq_dpo_binds_stable_session_identity(self):
        header = self.source("ipoe.h")
        dpo = self.source("ipoe_qinq_dpo.c")
        output = self.source("ipoe_qinq_output_node.c")
        session = self.source("ipoe_session.c")

        self.assertIn("u64 external_index;", header)
        self.assertIn(
            "context->external_index = session->external_index", dpo)
        self.assertIn("context->external_index, 1", output)
        self.assertIn(
            "session->external_index != expected_external_index", session)
        lookup = session.split(
            "ipoe_session_lookup_downstream", 1)[1].split(
                "static void", 1)[0]
        self.assertNotIn("clib_warning", lookup)

    def test_l2_input_node_enforces_session_and_dhcp_whitelist(self):
        cmake = self.source("CMakeLists.txt")
        node = self.source("ipoe_l2_input_node.c")
        self.assertIn("ipoe_l2_input_node.c", cmake)
        for token in (
            'VLIB_REGISTER_NODE (ipoe_l2_input_node)',
            '.arc_name = "l2-input-ip4"',
            '.node_name = "ipoe-l2-input"',
            'vnet_feature_next',
            'session_by_user',
            'IPOE_L2_ERROR_NO_SESSION',
            'IPOE_L2_ERROR_MAC_MISMATCH',
            'IPOE_L2_RESULT_DHCP_WHITELIST',
            'UDP_DST_PORT_dhcp_to_server',
            'external_index',
        ):
            self.assertIn(token, node)
        self.assertNotIn("input_path != IPOE_INPUT_L2", node)

    def test_input_nodes_do_not_gate_packets_by_input_path(self):
        l2_input = self.source("ipoe_l2_input_node.c")
        l3_input = self.source("ipoe_ip4_input_node.c")
        for node in (l2_input, l3_input):
            self.assertNotIn("MODE_MISMATCH", node)
            self.assertNotIn("input_path !=", node)

    def test_trace_converts_ethernet_mac_bytes_to_mac_address(self):
        node = self.source("ipoe_l2_input_node.c")
        self.assertIn(
            "mac_address_from_bytes (&t->src_mac, eth->src_address)", node
        )
        self.assertNotIn("t->src_mac = eth->src_address", node)

    def test_l2_interface_lifecycle_controls_feature_arc(self):
        header = self.source("ipoe.h")
        core = self.source("ipoe.c")
        self.assertIn("IPOE_ERROR_FEATURE_FAILED", header)
        self.assertIn("vnet_l2_feature_enable_disable", core)
        self.assertGreaterEqual(core.count('"l2-input-ip4"'), 1)
        self.assertGreaterEqual(core.count('"ipoe-l2-input"'), 1)
        self.assertRegex(
            core,
            re.compile(
                r"ipoe_l2_feature_enable_disable\s*\([^)]*enable[^)]*\)"
            ),
        )

    def test_control_plane_mutations_protect_worker_readers(self):
        core = self.source("ipoe.c")
        session = self.source("ipoe_session.c")
        for token in (
            "vlib_worker_thread_barrier_sync",
            "vlib_worker_thread_barrier_release",
        ):
            self.assertIn(token, core)
            self.assertIn(token, session)

    def test_l3_input_node_uses_rx_interface_and_source_ip(self):
        cmake = self.source("CMakeLists.txt")
        core = self.source("ipoe.c")
        node = self.source("ipoe_ip4_input_node.c")
        self.assertIn("ipoe_ip4_input_node.c", cmake)
        for token in (
            'VLIB_REGISTER_NODE (ipoe_ip4_input_node)',
            '.arc_name = "ip4-unicast"',
            '.node_name = "ipoe-ip4-input"',
            'sw_if_index[VLIB_RX]',
            'ip4->src_address',
            'session_by_user',
            'IPOE_IP4_RESULT_DHCP_WHITELIST',
            'IPOE_IP4_ERROR_NO_SESSION',
            'vnet_feature_next',
            'VNET_BUFFER_F_L2_HDR_OFFSET_VALID',
            'IPOE_IP4_ERROR_MAC_MISMATCH',
            'memcmp (session->user_mac.bytes, eth->src_address',
        ):
            self.assertIn(token, node)
        self.assertNotIn(
            "input_path == IPOE_INPUT_IP4 && access_mode != IPOE_ACCESS_MODE_L3",
            core,
        )
        self.assertNotIn("intf->access_mode != IPOE_ACCESS_MODE_L3", node)

    def test_output_node_uses_exact_tx_interface_and_destination_ip(self):
        cmake = self.source("CMakeLists.txt")
        node = self.source("ipoe_output_node.c")
        self.assertIn("ipoe_output_node.c", cmake)
        for token in (
            'VLIB_REGISTER_NODE (ipoe_output_node)',
            '.arc_name = "l2-output-ip4"',
            '.arc_name = "ip4-output"',
            '.node_name = "ipoe-output"',
            'sw_if_index[VLIB_TX]',
            'ip4->dst_address',
            'session_by_user',
            'IPOE_OUTPUT_RESULT_DHCP_WHITELIST',
            'IPOE_OUTPUT_RESULT_NON_IP4_BYPASS',
            'IPOE_OUTPUT_ERROR_UNSUPPORTED_VLAN_DEPTH',
            'vnet_feature_next',
        ):
            self.assertIn(token, node)
        self.assertNotIn('.arc_name = "interface-output"', node)
        for forbidden in ("sup_sw_if_index", "get_sup", "parent_sw_if"):
            self.assertNotIn(forbidden, node)

    def test_packet_helpers_define_directional_dhcp_whitelists(self):
        packet = self.source("ipoe_packet.h")
        for token in (
            "ipoe_ip4_is_dhcp_client",
            "ipoe_ip4_is_dhcp_relay",
            "ipoe_ip4_is_dhcp_ingress",
            "ipoe_ip4_is_dhcp_downstream",
            "UDP_DST_PORT_dhcp_to_client",
            "UDP_DST_PORT_dhcp_to_server",
            "dhcp->gateway_ip_address.as_u32 != 0",
            "dhcp->magic_cookie.as_u32 == DHCP_MAGIC",
            "ip4_is_fragment",
            "ETHERNET_TYPE_VLAN",
            "ETHERNET_TYPE_DOT1AD",
            "IPOE_MAX_VLAN_DEPTH",
        ):
            self.assertIn(token, packet)

        for node_name in ("ipoe_l2_input_node.c", "ipoe_ip4_input_node.c"):
            node = self.source(node_name)
            self.assertIn("#include <ipoe/ipoe_packet.h>", node)
            self.assertIn("ipoe_ip4_is_dhcp_ingress", node)

    def test_disable_flushes_sessions_and_controls_both_features(self):
        header = self.source("ipoe.h")
        core = self.source("ipoe.c")
        session = self.source("ipoe_session.c")
        self.assertIn("ipoe_session_flush_interface", header)
        self.assertIn("ipoe_session_flush_interface", core)
        self.assertIn("ipoe_session_flush_interface", session)
        self.assertIn('"ip4-unicast", "ipoe-ip4-input"', core)
        self.assertIn('"l2-output-ip4", "ipoe-output"', core)
        self.assertIn('"ip4-output", "ipoe-output"', core)
        self.assertNotIn('"interface-output", "ipoe-output"', core)
        disable = core[core.index("if (!enable)"):core.index("if ((access_mode")]
        self.assertNotIn("IPOE_ERROR_OBJECT_IN_USE", disable)
        self.assertIn("ipoe_session_flush_interface", disable)


if __name__ == "__main__":
    unittest.main()
