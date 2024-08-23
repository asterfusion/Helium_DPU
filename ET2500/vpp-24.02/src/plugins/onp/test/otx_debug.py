def otx_func_name(self):
    import sys

    return sys._getframe(1).f_code.co_name


def stats_across_cores(arr, subArrIndex=0):
    total = 0
    for instance in arr:
        if isinstance(instance, list):
            total += instance[subArrIndex]
        else:
            total += instance
    return total


def stats_across_cores_intf_packets(intf_arr):
    packets = 0
    for interface in intf_arr:
        packets += interface["packets"]
    return packets


def stats_across_cores_intf_drops(intf_arr):
    drops = 0
    for drop in intf_arr:
        drops += drop
    return drops


def otx_ipsec_dump(testclass, saId):
    sa_list = testclass.vapi.ipsec_sa_v3_dump()
    for sa in sa_list:
        if sa.entry.sad_id == saId:
            testclass.stats_ipsec_dump_last_seq = sa.last_seq_inbound


def otx_intf_stats(testclass, intf):
    intf_rx = testclass.statistics.get_counter("/interfaces/%s/rx" % intf)
    testclass.intf_rx_packets = stats_across_cores_intf_packets(intf_rx)

    intf_tx = testclass.statistics.get_counter("/interfaces/%s/tx" % intf)
    testclass.intf_tx_packets = stats_across_cores_intf_packets(intf_tx)

    intf_drops = testclass.statistics.get_counter("/interfaces/%s/drops" % intf)
    testclass.intf_drops = stats_across_cores(intf_drops)


def otx_onp_stats(testclass):
    testclass.esp4_decrypt_frame_recv_counters = stats_across_cores(
        testclass.statistics.get_counter("/onp/esp4-decrypt-frame-recv_counters"), 0
    )
    testclass.esp4_decrypt_frame_submit_counters = stats_across_cores(
        testclass.statistics.get_counter("/onp/esp4-decrypt-frame-submit_counters"), 0
    )
    testclass.esp4_decrypt_pkts_noop_counters = stats_across_cores(
        testclass.statistics.get_counter("/onp/esp4-decrypt-pkts-noop_counters"), 0
    )
    testclass.esp4_decrypt_pkts_recv_counters = stats_across_cores(
        testclass.statistics.get_counter("/onp/esp4-decrypt-pkts-recv_counters"), 0
    )
    testclass.esp4_decrypt_pkts_submit_counters = stats_across_cores(
        testclass.statistics.get_counter("/onp/esp4-decrypt-pkts-submit_counters"), 0
    )
    testclass.esp4_decrypt_result_fail_counters = stats_across_cores(
        testclass.statistics.get_counter("/onp/esp4-decrypt-result-fail_counters"), 0
    )
    # testclass.esp4_encrypt_frame_recv_counters = stats_across_cores(
    #        testclass.statistics.get_counter(
    #            '/onp/esp4-encrypt-frame-recv_counters'), 0)
    # testclass.esp4_encrypt_frame_submit_counters = stats_across_cores(
    #        testclass.statistics.get_counter(
    #            '/onp/esp4-encrypt-frame-submit_counters'), 0)
    # testclass.esp4_encrypt_pkts_noop_counters = stats_across_cores(
    #        testclass.statistics.get_counter(
    #            "/onp/esp4-encrypt-pkts-noop_counters"), 0)
    # testclass.esp4_encrypt_pkts_recv_counters = stats_across_cores(
    #        testclass.statistics.get_counter(
    #            '/onp/esp4-encrypt-pkts-recv_counters'), 0)
    # testclass.esp4_encrypt_pkts_submit_counters = stats_across_cores(
    #        testclass.statistics.get_counter(
    #            '/onp/esp4-encrypt-pkts-submit_counters'), 0)
    testclass.esp4_encrypt_result_fail_counters = stats_across_cores(
        testclass.statistics.get_counter("/onp/esp4-encrypt-result-fail_counters"), 0
    )
    testclass.esp4_encrypt_tun_pkts_noop_counters = stats_across_cores(
        testclass.statistics.get_counter("/onp/esp4-encrypt-tun-pkts-noop_counters"), 0
    )
    testclass.esp4_encrypt_tun_pkts_counters = stats_across_cores(
        testclass.statistics.get_counter("/onp/esp4-encrypt-tun-pkts_counters"), 0
    )
    testclass.esp4_encrypt_tun_pkts_submit_counters = stats_across_cores(
        testclass.statistics.get_counter("/onp/esp4-encrypt-tun-pkts-submit_counters"),
        0,
    )
    testclass.esp4_encrypt_post_tun_pkts_recv_counters = stats_across_cores(
        testclass.statistics.get_counter(
            "/onp/esp4-encrypt-post-tun-pkts-recv_counters"
        ),
        0,
    )
    # testclass.esp4_encrypt_tun_prep_pkts_counters = stats_across_cores(
    #        testclass.statistics.get_counter(
    #            '/onp/esp4-encrypt-tun-prep-pkts_counters'), 0)
    #    testclass.eth_tx_send_pkts_counters = stats_across_cores(
    #            testclass.statistics.get_counter(
    #                '/onp/eth-tx-send-pkts_counters'), 0)
    #    testclass.esp6_decrypt_frame_recv_counters = stats_across_cores(
    #            testclass.statistics.get_counter(
    #                '/onp/esp6-decrypt-frame-recv_counters'), 0)
    #    testclass.esp6_decrypt_frame_submit_counters = stats_across_cores(
    #            testclass.statistics.get_counter(
    #                '/onp/esp6-decrypt-frame-submit_counters'), 0)
    #    testclass.esp6_decrypt_pkts_noop_counters = stats_across_cores(
    #            testclass.statistics.get_counter(
    #                '/onp/esp6-decrypt-pkts-noop_counters'), 0)
    #    testclass.esp6_decrypt_pkts_recv_counters = stats_across_cores(
    #            testclass.statistics.get_counter(
    #                '/onp/esp6-decrypt-pkts-recv_counters'), 0)
    #    testclass.esp6_decrypt_pkts_submit_counters = stats_across_cores(
    #            testclass.statistics.get_counter(
    #                '/onp/esp6-decrypt-pkts-submit_counters'), 0)
    #    testclass.esp6_decrypt_result_fail_counters = stats_across_cores(
    #            testclass.statistics.get_counter(
    #                '/onp/esp6-decrypt-result-fail_counters'), 0)
    #    testclass.esp6_encrypt_frame_recv_counters = stats_across_cores(
    #            testclass.statistics.get_counter(
    #                '/onp/esp6-encrypt-frame-recv_counters'), 0)
    #    testclass.esp6_encrypt_frame_submit_counters = stats_across_cores(
    #            testclass.statistics.get_counter(
    #                '/onp/esp6-encrypt-frame-submit_counters'), 0)
    #    testclass.esp6_encrypt_pkts_noop_counters = stats_across_cores(
    #            testclass.statistics.get_counter(
    #                "/onp/esp6-encrypt-pkts-noop_counters"), 0)
    #    testclass.esp6_encrypt_pkts_recv_counters = stats_across_cores(
    #            testclass.statistics.get_counter(
    #                '/onp/esp6-encrypt-pkts-recv_counters'), 0)
    #    testclass.esp6_encrypt_pkts_submit_counters = stats_across_cores(
    #            testclass.statistics.get_counter(
    #                '/onp/esp6-encrypt-pkts-submit_counters'), 0)
    testclass.esp6_encrypt_result_fail_counters = stats_across_cores(
        testclass.statistics.get_counter("/onp/esp6-encrypt-result-fail_counters"), 0
    )


#    testclass.sched_handoff_frame_enq_counters = stats_across_cores(
#            testclass.statistics.get_counter(
#                '/onp/sched-handoff-frame-enq_counters'), 0)
#    testclass.sched_handoff_frame_recv_counters = stats_across_cores(
#            testclass.statistics.get_counter(
#                '/onp/sched-handoff-frame-recv_counters'), 0)
#    testclass.sched_handoff_pkts_enq_counters = stats_across_cores(
#            testclass.statistics.get_counter(
#                '/onp/sched-handoff-pkts-enq_counters'), 0)
#    testclass.sched_handoff_pkts_recv_counters = stats_across_cores(
#            testclass.statistics.get_counter(
#                '/onp/sched-handoff-pkts-recv_counters'), 0)
#    testclass.sched_order_lock_count_counters = stats_across_cores(
#            testclass.statistics.get_counter(
#                '/onp/sched-order-lock-count_counters'), 0)


def otx_ipsec_replay_window_dump(testclass):
    replay_window_dump = testclass.vapi.api(
        testclass.vapi.onp_ipsec_replay_window_size_dump
    )
    replay_window_dump.replay_window_size


def otx_ipsec_sa_stats(testclass, saId):
    for sa in testclass.ipsecObj.ipsec_sa:
        testclass.sa_stats_packets = sa.get_stats()["packets"]
        testclass.sa_stats_bytes = sa.get_stats()["bytes"]


def otx_ipsec_spd_stats(testclass, spiId, policyType="protect"):
    testclass.spd_stats_packets = testclass.ipsecObj.ipsec_spd[policyType].get_stats()[
        "packets"
    ]
    testclass.spd_stats_bytes = testclass.ipsecObj.ipsec_spd[policyType].get_stats()[
        "bytes"
    ]


def otx_ipsec_tun_stats(testclass, tun):
    ret = testclass.vapi.ipsec_tunnel_protect_dump(
        sw_if_index=tun.ipsec_intf.sw_if_index
    )
    return ret


# Error counters are not being reset to 0, even in case of clear errors command.
# So, set value, run test case and verify.


def set_ipsec_policy_match_errors(self, count):
    self.ipsec_policy_match_errors = (
        stats_across_cores(
            self.get_packet_counter("/err/ipsec4-input-feature/IPSec policy match")
        )
        + count
    )


def set_ipsec_esn_replay_errors(self, count):
    self.ipsec_esn_replay_errors = (
        stats_across_cores(
            self.get_packet_counter("/err/onp-esp4-decrypt/SA replayed packet")
        )
        + count
    )


def set_ipsec_esn_mac_errors(self, count):
    self.ipsec_esn_mac_errors = (
        stats_across_cores(
            self.get_packet_counter(
                "/err/onp-esp4-decrypt-post-drop/MAC compare failed"
            )
        )
        + count
    )


def set_ipsec_policy_bypass_errors(self, count):
    self.ipsec_policy_bypass_errors = (
        stats_across_cores(
            self.get_packet_counter("/err/ipsec4-output-feature/IPSec policy bypass")
        )
        + count
    )


def set_ipsec_policy_protect_errors(self, count):
    self.ipsec_policy_protect_errors = (
        stats_across_cores(
            self.get_packet_counter("/err/ipsec4-output-feature/IPSec policy protect")
        )
        + count
    )


def set_ipsec_tun_esp_packets(self, node, count):
    self.ipsec_tun_esp_packets[node] = (
        stats_across_cores(
            self.get_packet_counter("/err/" + node + "/ESP pkts received")
        )
        + count
    )


def verify_ipsec_policy_match_errors(self):
    ipsec_policy_match_errors = stats_across_cores(
        self.get_packet_counter("/err/ipsec4-input-feature/IPSec policy match")
    )
    self.assert_equal(ipsec_policy_match_errors, self.ipsec_policy_match_errors)


def verify_ipsec_esn_replay_errors(self):
    ipsec_esn_replay_errors = stats_across_cores(
        self.get_packet_counter("/err/onp-esp4-decrypt/SA replayed packet")
    )
    self.assert_equal(ipsec_esn_replay_errors, self.ipsec_esn_replay_errors)


def verify_ipsec_esn_mac_errors(self):
    ipsec_esn_mac_errors = stats_across_cores(
        self.get_packet_counter("/err/onp-esp4-decrypt-post-drop/MAC compare failed")
    )
    self.assert_equal(ipsec_esn_mac_errors, self.ipsec_esn_mac_errors)


def verify_ipsec_policy_bypass_errors(self):
    ipsec_policy_bypass_errors = stats_across_cores(
        self.get_packet_counter("/err/ipsec4-output-feature/IPSec policy bypass")
    )
    self.assert_equal(ipsec_policy_bypass_errors, self.ipsec_policy_bypass_errors)


def verify_ipsec_policy_protect_errors(self):
    ipsec_policy_protect_errors = stats_across_cores(
        self.get_packet_counter("/err/ipsec4-output-feature/IPSec policy protect")
    )
    self.assert_equal(ipsec_policy_protect_errors, self.ipsec_policy_protect_errors)


def verify_ipsec_tun_esp_packets(self, node):
    ipsec_tun_esp_packets = stats_across_cores(
        self.get_packet_counter("/err/" + node + "/ESP pkts received")
    )
    self.assert_equal(ipsec_tun_esp_packets, self.ipsec_tun_esp_packets[node])
