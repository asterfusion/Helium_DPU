/*
 * Copyright (c) 2020 Doc.ai and/or its affiliates.
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

#include <vnet/adj/adj_midchain.h>
#include <vnet/fib/fib_table.h>
#include <vnet/fib/ip4_fib.h>
#include <vnet/fib/ip6_fib.h>
#include <vnet/dpo/load_balance.h>
#include <vnet/dpo/load_balance_map.h>
#include <wireguard/wireguard_peer.h>
#include <wireguard/wireguard_if.h>
#include <wireguard/wireguard_messages.h>
#include <wireguard/wireguard_key.h>
#include <wireguard/wireguard_send.h>
#include <wireguard/wireguard.h>
#include <vnet/tunnel/tunnel_dp.h>


static uword sf_wireguard_thread_fn(vlib_main_t *vm,
                                 vlib_node_runtime_t *rt,
                                 vlib_frame_t *f0)
{
    wg_peer_t *peer;
    u32 out_sw_if_index;
    u8 is_ip4 = 0;

    while(1)
    {
        vlib_process_wait_for_event_or_clock(vm, 5);

        pool_foreach (peer, wg_peer_pool)
        {
            if (peer->config_dst.addr.ip4.data_u32 != 0 && peer->config_dst.port != 0)
            {
                out_sw_if_index = wg_peer_get_output_interface(&peer->config_dst);
                memcpy(&peer->dst, &peer->config_dst, sizeof(wg_peer_endpoint_t));
            }

            else
            {
                out_sw_if_index = wg_peer_get_output_interface(&peer->dst);
            }
            is_ip4 = ip46_address_is_ip4(&peer->dst.addr);
            if (out_sw_if_index == peer->output_sw_index || 1 == out_sw_if_index)
            {
                continue;
            }

            else
            {
                if (is_ip4)
                {
                    ip4_main_t *im4 = &ip4_main;
                    ip_lookup_main_t *lm4 = &im4->lookup_main;
                    ip_interface_address_t *ia = NULL;
                    ip4_address_t *r4 = NULL;

                    foreach_ip_interface_address (lm4, ia, out_sw_if_index, 1,
                    ({
                      r4 = ip_interface_address_get_address (lm4, ia);
                     }));

                    if (r4)
                    {
                        peer->src.addr.ip4.data_u32 = r4->data_u32;
                        peer->output_sw_index = out_sw_if_index;
                    }
                }

                else
                {
                    ip6_main_t *im6 = &ip6_main;
                    ip_lookup_main_t *lm6 = &im6->lookup_main;
                    ip_interface_address_t *ia = NULL;
                    ip6_address_t *r6 = NULL;

                    foreach_ip_interface_address (lm6, ia, out_sw_if_index, 1,
                    ({
                     r6 = ip_interface_address_get_address (lm6, ia);
                     }));

                    if (r6)
                    {
                        peer->src.addr.ip6.as_u64[0] = r6->as_u64[0];
                        peer->src.addr.ip6.as_u64[1] = r6->as_u64[1];
                        peer->output_sw_index = out_sw_if_index;
                    }
                }

                peer->rewrite = wg_build_rewrite (&peer->src.addr, peer->src.port,
                                    &peer->dst.addr, peer->dst.port, is_ip4);
                wg_timers_send_first_handshake (peer);
            }
        }
    }

    return 0;
}


VLIB_REGISTER_NODE(sf_wireguard_process_node, static) = {
    .function = sf_wireguard_thread_fn,
    .type = VLIB_NODE_TYPE_PROCESS,
    .name = "sf_wireguard_process",
    .process_log2_n_stack_bytes = 18,
};



