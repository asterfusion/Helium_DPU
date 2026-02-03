/*
 * Copyright 2024-2027 Asterfusion Network
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

#include <hqos/hqos.h>

u8 *
format_hqos_preprocess_trace(u8 *s, va_list *args)
{
    CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
    CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
    hqos_preprocess_trace_t *t = va_arg (*args, hqos_preprocess_trace_t *);

    s = format (s, "\tCurrent Pkt [%s]: tc %u, color %u, len %u\n", hqos_error_counters[t->state].name, 
                t->tc, t->color, t->pkt_len);
    if (t->user_id == ~0)
        s = format (s, "\t                  user unknown\n");
    else
        s = format (s, "\t                  user %u\n", t->user_id);

    if (t->user_group_id == ~0)
        s = format (s, "\t                  user group unknown\n");
    else
        s = format (s, "\t                  user group %u\n", t->user_group_id);

    if (t->hqos_port_id == ~0)
        s = format (s, "\t                  hqos-port-id unknown\n");
    else
        s = format (s, "\t                  hqos-port-id %d\n", t->hqos_port_id);

    if (t->hqos_subport_id == ~0)
        s = format (s, "\t                  hqos-subport-id unknown\n");
    else
        s = format (s, "\t                  hqos-subport-id %d\n", t->hqos_subport_id);

    if (t->hqos_pipe_id == ~0)
        s = format (s, "\t                  hqos-pipe-id unknown\n");
    else
        s = format (s, "\t                  hqos-pipe-id %d\n", t->hqos_pipe_id);

    if (t->hqos_queue_id == ~0)
        s = format (s, "\t                  hqos-queue-id unknown\n");
    else
        s = format (s, "\t                  hqos-queue-id %d\n", t->hqos_queue_id);

    return s;
}

u8 *
format_hqos_postprocess_trace(u8 *s, va_list *args)
{
    CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
    CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
    hqos_postprocess_trace_t *t = va_arg (*args, hqos_postprocess_trace_t *);
    vnet_main_t *vnm = vnet_get_main ();

    s = format (s, "\tCurrent Pkt :  output-tx %U, use_tc %u, tc %u\n", 
            format_vnet_sw_if_index_name, vnm, t->sw_if_index, t->use_tc, t->tc);
    return s;
}

u8 *
format_hqos_tc_queue_mode(u8 *s, va_list *args)
{
    hqos_tc_queue_mode_e *mode = va_arg (*args, hqos_tc_queue_mode_e *);

    switch(*mode)
    {
    case HQOS_TC_QUEUE_MODE_SP:
        s = format (s, "SP");
        break;
    case HQOS_TC_QUEUE_MODE_DWRR:
        s = format (s, "DWRR");
        break;
    case HQOS_TC_QUEUE_MODE_CNT:
    default:
        s = format (s, "BUG! unexpected BUG!");
        break;
    }
    return s;
}

u8 *
format_hqos_port(u8 *s, va_list *args)
{
    uword hqos_port_id = va_arg (*args, uword);
    hqos_sched_port *hqos_port = va_arg (*args, hqos_sched_port *);
    s = format(s, "Hqos Port %u:\n", hqos_port_id);
    s = format(s, "\tBasic:\n");
    s = format(s, "\t\tRate = %llu bytes/second\n", hqos_port->rate);
    s = format(s, "\t\tMTU = %u bytes\n", hqos_port->mtu);
    s = format(s, "\t\tFrame overhead = %u bytes\n", hqos_port->frame_overhead);
    s = format(s, "\t\tNumber of subports = %u\n", hqos_port->n_subports_per_port);
    s = format(s, "\t\tNumber of pipes per subport = %u\n", hqos_port->n_pipes_per_subport);
    s = format(s, "\t\tNumber of max subport profiles = %u\n", hqos_port->n_max_subport_profiles);
    s = format(s, "\t\tNumber of current subport profiles = %u\n", hqos_port->n_subport_profiles);
    s = format(s, "\t\tTc queue size = %u\n", hqos_port->n_queue_size);
    return s;
}

u8 *
format_hqos_port_detail(u8 *s, va_list *args)
{
    hqos_main_t *hm = &hqos_main;
    uword hqos_port_id = va_arg (*args, uword);
    hqos_sched_port *hqos_port = va_arg (*args, hqos_sched_port *);

    u32 subport_id;
    hqos_sched_subport *hqos_subport = NULL;
    hqos_sched_subport_profile *subport_profile = NULL;

    u32 pipe_id;
    hqos_sched_pipe *hqos_pipe = NULL;
    hqos_sched_pipe_profile *pipe_profile = NULL;

    u64 *counter;
    u64 enqueue_drop_pkts = 0;
    u64 dequeue_drop_pkts = 0;

    s = format(s, "Hqos Port %u:\n", hqos_port_id);
    s = format(s, "\tBasic:\n");
    s = format(s, "\t\tRate = %llu bytes/second\n", hqos_port->rate);
    s = format(s, "\t\tMTU = %u bytes\n", hqos_port->mtu);
    s = format(s, "\t\tFrame overhead = %u bytes\n", hqos_port->frame_overhead);
    s = format(s, "\t\tNumber of subports = %u\n", hqos_port->n_subports_per_port);
    s = format(s, "\t\tNumber of pipes per subport = %u\n", hqos_port->n_pipes_per_subport);
    s = format(s, "\t\tNumber of max subport profiles = %u\n", hqos_port->n_max_subport_profiles);
    s = format(s, "\t\tNumber of current subport profiles = %u\n", hqos_port->n_subport_profiles);
    s = format(s, "\t\tTc queue size = %u\n", hqos_port->n_queue_size);

    s = format(s, "\tSubport:\n");
    for (subport_id = 0; subport_id < hqos_port->n_subports_per_port; subport_id++)
    {
        hqos_subport = hqos_port->subports[subport_id];
        if (hqos_subport != NULL)
        {
            subport_profile =  hqos_port->subport_profiles + hqos_subport->profile;
            s = format(s, "\t\tSubport %u:\n", subport_id);
            s = format(s, "\t\t\tRate = %llu bytes/second\n", hqos_port->subport_profiles[hqos_subport->profile].orig_tb_rate);
            s = format(s, "\t\t\tNumber of enable pipes per subport = %u\n", hqos_subport->n_pipes_per_subport_enabled);
            s = format(s, "\t\t\tNumber of max pipe profiles = %u\n", hqos_subport->n_max_pipe_profiles);
            s = format(s, "\t\t\tNumber of current pipe profiles = %u\n", hqos_subport->n_pipe_profiles);
            s = format(s, "\t\t\tSubport Profile %u\n", hqos_subport->profile);
            s = format(s, "\t\t\tToken bucket size = %u bytes\n", hqos_port->subport_profiles[hqos_subport->profile].tb_size);
            s = format(s, "\t\t\tTraffic class rate:\n");
            s = format(s, "\t\t\t\tTC0 = %llu, TC1 = %llu, TC2 = %llu, TC3 = %llu bytes/second\n",
                    hqos_sched_time_ms_to_rate(
                        hqos_port->subport_profiles[hqos_subport->profile].orig_tc_period, 
                        subport_profile->tc_credits_per_period[0]),
                    hqos_sched_time_ms_to_rate(
                        hqos_port->subport_profiles[hqos_subport->profile].orig_tc_period, 
                        subport_profile->tc_credits_per_period[1]),
                    hqos_sched_time_ms_to_rate(
                        hqos_port->subport_profiles[hqos_subport->profile].orig_tc_period, 
                        subport_profile->tc_credits_per_period[2]),
                    hqos_sched_time_ms_to_rate(
                        hqos_port->subport_profiles[hqos_subport->profile].orig_tc_period, 
                        subport_profile->tc_credits_per_period[3]));
            s = format(s, "\t\t\t\tTC4 = %llu, TC5 = %llu, TC6 = %llu, TC7 = %llu bytes/second\n",
                    hqos_sched_time_ms_to_rate(
                        hqos_port->subport_profiles[hqos_subport->profile].orig_tc_period, 
                        subport_profile->tc_credits_per_period[4]),
                    hqos_sched_time_ms_to_rate(
                        hqos_port->subport_profiles[hqos_subport->profile].orig_tc_period, 
                        subport_profile->tc_credits_per_period[5]),
                    hqos_sched_time_ms_to_rate(
                        hqos_port->subport_profiles[hqos_subport->profile].orig_tc_period, 
                        subport_profile->tc_credits_per_period[6]),
                    hqos_sched_time_ms_to_rate(
                        hqos_port->subport_profiles[hqos_subport->profile].orig_tc_period, 
                        subport_profile->tc_credits_per_period[7]));
            s = format(s, "\t\t\t\tTC_BE = %llu bytes/second\n",
                    hqos_sched_time_ms_to_rate(
                        hqos_port->subport_profiles[hqos_subport->profile].orig_tc_period, 
                        subport_profile->tc_credits_per_period[8]));
            s = format(s, "\t\t\tTC period = %llu milliseconds\n", 
                    hqos_port->subport_profiles[hqos_subport->profile].orig_tc_period);
            //PIPE
            s = format(s, "\t\t\tPipe:\n");
            for (pipe_id = 0; pipe_id < hqos_subport->n_pipes_per_subport_enabled; pipe_id++)
            {
                hqos_pipe = hqos_subport->pipe + pipe_id;
                if (hqos_pipe->tb_credits) 
                {
                    pipe_profile = hqos_subport->pipe_profiles + hqos_pipe->profile;
                    s = format(s, "\t\tPipe %u:\n", pipe_id);
                    s = format(s, "\t\t\t\tPipe profile %u:\n", hqos_pipe->profile);
                    s = format(s, "\t\t\t\tRate = %llu bytes/second\n", pipe_profile->orig_tb_rate);
                    s = format(s, "\t\t\t\tToken bucket size = %u bytes\n", pipe_profile->tb_size);
                    s = format(s, "\t\t\t\tTraffic class rate:\n");
                    s = format(s, "\t\t\t\t\tTC0 = %llu, TC1 = %llu, TC2 = %llu, TC3 = %llu bytes/second\n",
                        hqos_sched_time_ms_to_rate( pipe_profile->orig_tc_period, pipe_profile->tc_credits_per_period[0]),
                        hqos_sched_time_ms_to_rate( pipe_profile->orig_tc_period, pipe_profile->tc_credits_per_period[1]),
                        hqos_sched_time_ms_to_rate( pipe_profile->orig_tc_period, pipe_profile->tc_credits_per_period[2]),
                        hqos_sched_time_ms_to_rate( pipe_profile->orig_tc_period, pipe_profile->tc_credits_per_period[3]));
                    s = format(s, "\t\t\t\t\tTC4 = %llu, TC5 = %llu, TC6 = %llu, TC7 = %llu bytes/second\n",
                        hqos_sched_time_ms_to_rate( pipe_profile->orig_tc_period, pipe_profile->tc_credits_per_period[4]),
                        hqos_sched_time_ms_to_rate( pipe_profile->orig_tc_period, pipe_profile->tc_credits_per_period[5]),
                        hqos_sched_time_ms_to_rate( pipe_profile->orig_tc_period, pipe_profile->tc_credits_per_period[6]),
                        hqos_sched_time_ms_to_rate( pipe_profile->orig_tc_period, pipe_profile->tc_credits_per_period[7]));
                    s = format(s, "\t\t\t\t\tTC_BE = %llu bytes/second\n",
                        hqos_sched_time_ms_to_rate( pipe_profile->orig_tc_period, pipe_profile->tc_credits_per_period[8]));
                    s = format(s, "\t\t\t\t\tTC_BE WRR weights: TC_BE_0 = %u, TC_BE_1 = %u, TC_BE_2 = %u, TC_BE_3 = %u\n",
                                pipe_profile->wrr_weights[0], pipe_profile->wrr_weights[1], 
                                pipe_profile->wrr_weights[2], pipe_profile->wrr_weights[3]);
                    s = format(s, "\t\t\t\t\tTC_BE WRR weights: TC_BE_4 = %u, TC_BE_5 = %u, TC_BE_6 = %u, TC_BE_7 = %u\n",
                                pipe_profile->wrr_weights[4], pipe_profile->wrr_weights[5],
                                pipe_profile->wrr_weights[6], pipe_profile->wrr_weights[7]);
                    s = format(s, "\t\t\t\t\tTC_BT oversubscription_weight = %u\n", pipe_profile->tc_ov_weight);
                    s = format(s, "\t\t\t\t\tTC period = %u milliseconds\n", pipe_profile->orig_tc_period);
                }
            }
        }
    }

    s = format(s, "\tThread:\n");
    s = format(s, "\t\tscheduler worker index = %u\n", hm->hqos_port_sched_mapping_worker[hqos_port_id]);
    if (hm->hqos_sched_thread_num > 0)
        s = format(s, "\t\tscheduler private thread index = %u\n", hm->hqos_port_sched_mapping_thread[hqos_port_id]);
    else
        s = format(s, "\t\tscheduler private thread inactive\n");
    s = format(s, "\tProc Fifo:\n");
    s = format(s, "\t\tIn Hqos fifo count: %u\n", hqos_fifo_count(hm->hqos_port_fifo_vec[hqos_port_id].in_fifo));
    s = format(s, "\t\tOut Hqos fifo count: %u\n", hqos_fifo_count(hm->hqos_port_fifo_vec[hqos_port_id].out_fifo));

    vec_foreach(counter, hm->hqos_port_enqueue_drop[hqos_port_id].counters)
    {
        enqueue_drop_pkts += *counter;
    }
    vec_foreach(counter, hm->hqos_port_dequeue_drop[hqos_port_id].counters)
    {
        dequeue_drop_pkts += *counter;
    }

    s = format(s, "\tDrop Counter:\n");
    s = format(s, "\t\tHqos enqueue drop: %llu pkts\n", enqueue_drop_pkts);
    s = format(s, "\t\tHqos dequeue drop: %llu pkts\n", dequeue_drop_pkts);

    return s;
}
