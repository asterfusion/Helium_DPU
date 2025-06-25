/**
 * @file
 * @brief ONP pktio implementation.
 */

#include <onp/onp.h>
#include <onp/drv/modules/pktio/pktio_priv.h>

#define ONP_PKTIO_TM_USER_TREE_ROOT_NODE_ID(queue_num)        (queue_num);
#define ONP_PKTIO_TM_USER_TREE_L2_NODE_ID(queue_num)          (queue_num + 1);
#define ONP_PKTIO_TM_USER_TREE_L3_NODE_ID(queue_num)          (queue_num + 2);
#define ONP_PKTIO_TM_USER_TREE_L4_NODE_ID(queue_num)          (queue_num + 3);
#define ONP_PKTIO_TM_USER_TREE_MDQ_NODE_ID(queue_num, qid)   (queue_num + 4 + qid);

static int
onp_pktio_shaping_profile_add(struct roc_nix *nix, onp_pktio_scheduler_shaping_profile_t *profile)
{
    int rv = 0;
    struct roc_nix_tm_shaper_profile *tmp_profile = NULL;
    tmp_profile = roc_nix_tm_shaper_profile_get(nix, profile->tm_shaper_profile.id);
    if (tmp_profile == NULL)
    {
        rv = roc_nix_tm_shaper_profile_add(nix, &profile->tm_shaper_profile);
        if (rv)
        {
            onp_pktio_warn ("roc_nix_tm_shaper_profile_add failed with rv %s", roc_error_msg_get(rv));
            return -1;
        }
    }
    else
    {
        //update
        rv = roc_nix_tm_shaper_profile_update(nix, &profile->tm_shaper_profile);
        if (rv)
        {
            onp_pktio_warn ("roc_nix_tm_shaper_profile_update failed with rv %s", roc_error_msg_get(rv));
            return -1;
        }
    }
    return 0;
}

static int
onp_pktio_shaping_profile_del(struct roc_nix *nix, u32 profile_id)
{
    int rv = 0;
    struct roc_nix_tm_shaper_profile *tmp_profile = NULL;
    tmp_profile = roc_nix_tm_shaper_profile_get(nix, profile_id);
    if (tmp_profile == NULL)
    {
        return 0;
    }
    rv = roc_nix_tm_shaper_profile_delete(nix, profile_id);
    if (rv != 0 && rv != NIX_ERR_TM_SHAPER_PROFILE_IN_USE)
    {
        onp_pktio_warn ("roc_nix_tm_shaper_profile_delete failed with rv %s", roc_error_msg_get(rv));
        return -1;
    }
    return 0;
}

int
onp_pktio_scheduler_profile_add_del(vlib_main_t *vm, onp_main_t *om, onp_pktio_scheduler_profile_t *profile, bool is_delete)
{
    onp_pktio_scheduler_profile_t *tmp_profile = NULL;
    if (is_delete)
    {
        if (profile->id == ONP_PKTIO_SCHEDULER_PROFILE_NONE)
        {
            //not need delete
            return 0;
        }

        if (pool_is_free_index(om->scheduler_profile_pool, profile->id))
        {
            //not found
            return 0;
        }
        pool_put_index(om->scheduler_profile_pool, profile->id);
    }
    else
    {
        if (profile->id != ONP_PKTIO_SCHEDULER_PROFILE_NONE)
        {
            //update
            if (pool_is_free_index(om->scheduler_profile_pool, profile->id))
            {
                clib_warning("scheduler profile %u not exist\n", profile->id);
                return 1;
            }
            tmp_profile = pool_elt_at_index(om->scheduler_profile_pool, profile->id);
        }
        else
        {
            pool_get_zero(om->scheduler_profile_pool, tmp_profile);
            tmp_profile->id = tmp_profile - om->scheduler_profile_pool;
        }

        tmp_profile->type = profile->type;
        tmp_profile->weight = profile->weight;

        tmp_profile->shaping_flag = profile->shaping_flag;
        if (tmp_profile->shaping_flag)
        {
            tmp_profile->shaping_profile.tm_shaper_profile.id = tmp_profile->id;
            tmp_profile->shaping_profile.tm_shaper_profile.pkt_mode = profile->shaping_profile.tm_shaper_profile.pkt_mode;
            tmp_profile->shaping_profile.tm_shaper_profile.accuracy = profile->shaping_profile.tm_shaper_profile.accuracy;
            tmp_profile->shaping_profile.tm_shaper_profile.red_algo = profile->shaping_profile.tm_shaper_profile.red_algo;

            tmp_profile->shaping_profile.tm_shaper_profile.commit_sz = profile->shaping_profile.tm_shaper_profile.commit_sz;
            tmp_profile->shaping_profile.tm_shaper_profile.peak_sz = profile->shaping_profile.tm_shaper_profile.peak_sz;

            if (tmp_profile->shaping_profile.tm_shaper_profile.pkt_mode)
            {
                tmp_profile->shaping_profile.tm_shaper_profile.commit_rate = profile->shaping_profile.tm_shaper_profile.commit_rate;
                tmp_profile->shaping_profile.tm_shaper_profile.peak_rate = profile->shaping_profile.tm_shaper_profile.peak_rate;
                tmp_profile->shaping_profile.tm_shaper_profile.pkt_len_adj = 0;
            }
            else
            {
                //bytes to bits
                tmp_profile->shaping_profile.tm_shaper_profile.commit_rate = profile->shaping_profile.tm_shaper_profile.commit_rate * 8;
                tmp_profile->shaping_profile.tm_shaper_profile.peak_rate = profile->shaping_profile.tm_shaper_profile.peak_rate * 8;
                tmp_profile->shaping_profile.tm_shaper_profile.pkt_len_adj = profile->shaping_profile.tm_shaper_profile.pkt_len_adj;
            }


            if (!tmp_profile->shaping_profile.tm_shaper_profile.commit_rate && !tmp_profile->shaping_profile.tm_shaper_profile.commit_sz)
            {
                tmp_profile->shaping_profile.tm_shaper_profile.commit_rate = tmp_profile->shaping_profile.tm_shaper_profile.peak_rate;
                tmp_profile->shaping_profile.tm_shaper_profile.commit_sz = tmp_profile->shaping_profile.tm_shaper_profile.peak_sz;
            }
        }
        else
        {
            tmp_profile->shaping_profile.tm_shaper_profile.id = ONP_PKTIO_SHAPER_PROFILE_NONE;
        }

        //fiil profileid to call
        profile->id = tmp_profile->id;
    }
    return 0;
}

int
onp_pktio_root_node_scheduler_shaping_update(vlib_main_t *vm, onp_main_t *om, u32 sw_if_index, u32 scheduler_profile_id, bool force_update)
{
    int rv = 0;

    vnet_hw_interface_t *hw = NULL;
    onp_pktio_t *od = NULL;
    cnxk_pktio_ops_map_t *ops_map = NULL;
    cnxk_pktio_t *pktio = NULL;

    u32 root_node_id;
    struct roc_nix *nix = NULL;
    struct nix_tm_node *tm_node = NULL;;

    onp_pktio_scheduler_profile_t *profile = NULL;
    u32 shaping_profile_id = ROC_NIX_TM_SHAPER_PROFILE_NONE;
    u32 old_shaping_profile_id = ROC_NIX_TM_SHAPER_PROFILE_NONE;

    if (pool_is_free_index(om->scheduler_profile_pool, scheduler_profile_id) && scheduler_profile_id != ONP_PKTIO_SCHEDULER_PROFILE_NONE)
    {
        onp_pktio_warn("invaild scheduler profile id %u", scheduler_profile_id);
        return -1;
    }

    hw = vnet_get_hw_interface_or_null (om->vnet_main, sw_if_index);

    if (!hw) return -1;

    od = onp_get_pktio (hw->dev_instance);
    ops_map = cnxk_pktio_get_pktio_ops (od->cnxk_pktio_index);
    pktio = &ops_map->pktio;
    nix = &pktio->nix;

    root_node_id = ONP_PKTIO_TM_USER_TREE_ROOT_NODE_ID(pktio->n_tx_queues);

    tm_node = (struct nix_tm_node *)roc_nix_tm_node_get(nix, root_node_id); //Must be converted to nix_tm_node

    if (tm_node == NULL)
    {
        onp_pktio_warn("invaild roc nix tm node id %u", root_node_id);
        return -1;
    }

    if (scheduler_profile_id != ONP_PKTIO_SCHEDULER_PROFILE_NONE)
    {
        profile = pool_elt_at_index(om->scheduler_profile_pool, scheduler_profile_id);
        if (profile->shaping_flag)
        {
            shaping_profile_id = profile->shaping_profile.tm_shaper_profile.id;
        }
    }
    old_shaping_profile_id = tm_node->shaper_profile_id;

    if (old_shaping_profile_id == ONP_PKTIO_SHAPER_PROFILE_NONE &&
        shaping_profile_id == ONP_PKTIO_SHAPER_PROFILE_NONE)
    {
        return 0;
    }

    if (shaping_profile_id != ONP_PKTIO_SHAPER_PROFILE_NONE)
    {
        //add new profile_id for nix
        rv = onp_pktio_shaping_profile_add(nix, &profile->shaping_profile);
        if (rv)
        {
            onp_pktio_warn("onp_pktio_shaping_profile_add profile_id %u failed", shaping_profile_id);
            return rv;
        }
    }

    //attch profile
    rv = roc_nix_tm_node_shaper_update(nix, root_node_id, shaping_profile_id, force_update);
    if (rv)
    {
        onp_pktio_warn("roc_nix_tm_node_shaper_update root_node %u profile_id %u failed", root_node_id, shaping_profile_id);
        return rv;
    }

    if (shaping_profile_id != old_shaping_profile_id)
    {
        //remove old profile_id for nix
        rv = onp_pktio_shaping_profile_del(nix, old_shaping_profile_id);
        if (rv)
        {
            onp_pktio_warn("onp_pktio_shaping_profile_del profile_id %u failed", old_shaping_profile_id);
            return rv;
        }
    }

    return 0;
}

int onp_pktio_mdq_node_scheduler_update(vlib_main_t *vm, onp_main_t *om, u32 sw_if_index, u32 qid, u32 scheduler_profile_id)
{
    int rv = 0;

    vnet_hw_interface_t *hw = NULL;
    onp_pktio_t *od = NULL;
    cnxk_pktio_ops_map_t *ops_map = NULL;
    cnxk_pktio_t *pktio = NULL;
    cnxk_pktio_link_info_t link_info;

    u32 mdq_node_id;
    i32 i;
    struct roc_nix *nix = NULL;

    onp_pktio_scheduler_profile_t *profile = NULL;
    u32 new_shaping_profile_id;
    u32 old_shaping_profile_id;

    struct nix_tm_node **tm_node_list = NULL;;
    uint32_t *tm_node_priority = NULL;
    uint8_t *tm_node_sq = NULL;
    uint32_t current_sq_priority = 0;

    uint64_t txq_mode_bitmap = 0;
    uint32_t dwrr_priority = UINT32_MAX, dwrr_num = 0;

    CLIB_UNUSED(uint32_t) new_weight;
	uint8_t priorities[NIX_TM_TLX_SP_PRIO_MAX];

    if (pool_is_free_index(om->scheduler_profile_pool, scheduler_profile_id) && scheduler_profile_id != ONP_PKTIO_SCHEDULER_PROFILE_NONE)
    {
        onp_pktio_warn("invaild scheduler profile id %u", scheduler_profile_id);
        return -1;
    }

    hw = vnet_get_hw_interface_or_null (om->vnet_main, sw_if_index);

    if (!hw) return -1;

    od = onp_get_pktio (hw->dev_instance);
    ops_map = cnxk_pktio_get_pktio_ops (od->cnxk_pktio_index);
    pktio = &ops_map->pktio;
    nix = &pktio->nix;

    /*
     * In nix scheduler prio following rules need to be followed:
     * 1. Priority must start from 0
     * 2. Only one set of DWRR is allowed
     * 3. The priority must be continuous and there should be no loopholes
     * 4. The lower the priority value, the higher the priority
     *
     * if default node mode is SP, and the priority is consistent with qid.
     * if default node mode is DWRR, and the priority is 0.
     * if qid is greater than NIX_TM_TLX_SP_PRIO-MAX, Now not support.
     *
     * now default node mode is DWRR
     *
     */

    tm_node_list = vec_new(struct nix_tm_node *, pktio->n_tx_queues);
    tm_node_priority = vec_new(uint32_t, pktio->n_tx_queues);
    tm_node_sq = vec_new(uint8_t, pktio->n_tx_queues);

    //get current txq mode
    txq_mode_bitmap = od->txq_mode_bitmap;

    //get current all mdq node priority
    vec_foreach_index(i, tm_node_list)
    {
        mdq_node_id = ONP_PKTIO_TM_USER_TREE_MDQ_NODE_ID(pktio->n_tx_queues, i);
        tm_node_list[i] = (struct nix_tm_node *)roc_nix_tm_node_get(nix, mdq_node_id);
        tm_node_sq[i] = (txq_mode_bitmap & (1ULL << i)) ? 1 : 0;
    }

    //update tm_node mode
    if (scheduler_profile_id == ONP_PKTIO_SCHEDULER_PROFILE_NONE)
    {
        new_shaping_profile_id = ONP_PKTIO_SHAPER_PROFILE_NONE;
        new_weight = NIX_TM_DFLT_RR_WT;

        tm_node_sq[qid] = 0;
        txq_mode_bitmap &= ~(1ULL << qid);
    }
    else
    {
        profile = pool_elt_at_index(om->scheduler_profile_pool, scheduler_profile_id);

        if (profile->shaping_flag)
            new_shaping_profile_id = profile->shaping_profile.tm_shaper_profile.id;
        else
            new_shaping_profile_id = ONP_PKTIO_SHAPER_PROFILE_NONE;

        if (profile->type == ONP_PKTIO_SCHEDULER_STRICT)
        {
            tm_node_sq[qid] = 1;
            txq_mode_bitmap |= (1ULL << qid);
            new_weight = NIX_TM_DFLT_RR_WT;
        }
        else //DWRR
        {
            tm_node_sq[qid] = 0;
            txq_mode_bitmap &= ~(1ULL << qid);
            new_weight = NIX_TM_DFLT_RR_WT * profile->weight;
        }
    }

    //Need to calculate new all tm_node_priority
    vec_foreach_index_backwards(i, tm_node_sq)
    {
        if (tm_node_sq[i] > 0)
        {
            tm_node_priority[i] = current_sq_priority;
        }
        else
        {
            if (dwrr_priority == UINT32_MAX)
            {
                dwrr_priority = current_sq_priority;
            }
            tm_node_priority[i] = dwrr_priority;
        }
        current_sq_priority++;
    }

    /* validate new all node prio */
    //Check sq prioroty max
    if (current_sq_priority >= NIX_TM_TLX_SP_PRIO_MAX)
    {
        vec_free(tm_node_list);
        vec_free(tm_node_priority);
        vec_free(tm_node_sq);
        onp_pktio_warn("scheduler mdq sq exceeds max.");
        return -1;
    }

    //foreach all node
    memset(priorities, 0, sizeof(priorities));
    vec_foreach_index(i, tm_node_list)
    {
        priorities[tm_node_priority[i]]++;
    }
    //Check if there is only one DWRR
    for (i = 0; i < NIX_TM_TLX_SP_PRIO_MAX; i++)
    {
        if (priorities[i] > 1)
            dwrr_num++;
    }
    if (dwrr_num > 1)
    {
        vec_free(tm_node_list);
        vec_free(tm_node_priority);
        vec_free(tm_node_sq);
        onp_pktio_warn("scheduler mdq dwrr exceeds one.");
        return -1;
    }

    // Check current mdq queuq shaping_profile
    old_shaping_profile_id = tm_node_list[qid]->shaper_profile_id;
    if (old_shaping_profile_id != new_shaping_profile_id)
    {
        if (new_shaping_profile_id != ONP_PKTIO_SHAPER_PROFILE_NONE)
        {
            //add new profile_id for nix
            rv = onp_pktio_shaping_profile_add(nix, &profile->shaping_profile);
            if (rv)
            {
                vec_free(tm_node_list);
                vec_free(tm_node_priority);
                vec_free(tm_node_sq);
                onp_pktio_warn("onp_pktio_shaping_profile_add profile_id %u failed", new_shaping_profile_id);
                return rv;
            }
        }
        //attch profile
        rv = roc_nix_tm_node_shaper_update(nix, tm_node_list[qid]->id, new_shaping_profile_id, true);
        if (rv)
        {
            onp_pktio_warn("roc_nix_tm_node_shaper_update mdq_node(%u) %u profile_id %u failed", qid, tm_node_list[qid]->id, new_shaping_profile_id);
            vec_free(tm_node_list);
            vec_free(tm_node_priority);
            vec_free(tm_node_sq);
            return rv;
        }

        //remove old profile_id for nix
        rv = onp_pktio_shaping_profile_del(nix, old_shaping_profile_id);
        if (rv)
        {
            vec_free(tm_node_list);
            vec_free(tm_node_priority);
            vec_free(tm_node_sq);
            onp_pktio_warn("onp_pktio_shaping_profile_del profile_id %u failed", old_shaping_profile_id);
            return rv;
        }
    }
    else
    {
        if (new_shaping_profile_id != ONP_PKTIO_SHAPER_PROFILE_NONE)
        {
            //update profile_id for nix
            rv = onp_pktio_shaping_profile_add(nix, &profile->shaping_profile);
            if (rv)
            {
                vec_free(tm_node_list);
                vec_free(tm_node_priority);
                vec_free(tm_node_sq);
                onp_pktio_warn("onp_pktio_shaping_profile_add profile_id %u failed", new_shaping_profile_id);
                return rv;
            }
            //attch profile
            rv = roc_nix_tm_node_shaper_update(nix, tm_node_list[qid]->id, new_shaping_profile_id, true);
            if (rv)
            {
                onp_pktio_warn("roc_nix_tm_node_shaper_update mdq_node(%u) %u profile_id %u failed", qid, tm_node_list[qid]->id, new_shaping_profile_id);
                vec_free(tm_node_list);
                vec_free(tm_node_priority);
                vec_free(tm_node_sq);
                return rv;
            }
        }
    }

    /* There is an exception in the handling here now */
    //update current node
    tm_node_list[qid]->weight = new_weight;
    tm_node_list[qid]->shaper_profile_id = new_shaping_profile_id;

    //update all mdq node priority
    vec_foreach_index(i, tm_node_list)
    {
        tm_node_list[i]->priority = tm_node_priority[i];
    }

    //update current txq mode
    od->txq_mode_bitmap = txq_mode_bitmap;

    //update HW
    clib_memset(&link_info, 0, sizeof(cnxk_pktio_link_info_t));
    rv = cnxk_drv_pktio_link_info_get (vm, od->cnxk_pktio_index, &link_info);
    if (rv)
    {
        vec_free(tm_node_list);
        vec_free(tm_node_priority);
        vec_free(tm_node_sq);
        onp_pktio_warn("cnxk_drv_pktio_link_info_get sw_if_index %u failed", sw_if_index);
        return rv;
    }
    if (link_info.is_up)
    {
        rv = roc_nix_tm_hierarchy_disable(nix);
        if (rv)
        {
            vec_free(tm_node_list);
            vec_free(tm_node_priority);
            vec_free(tm_node_sq);
            onp_pktio_warn("roc_nix_tm_hierarchy_disable sw_if_index %u failed", sw_if_index);
            return rv;
        }

        rv = roc_nix_tm_hierarchy_enable(nix, ROC_NIX_TM_USER, true);
        if (rv)
        {
            vec_free(tm_node_list);
            vec_free(tm_node_priority);
            vec_free(tm_node_sq);
            onp_pktio_warn("roc_nix_tm_hierarchy_enable sw_if_index %u failed", sw_if_index);
            return rv;
        }
    }
    else
    {
        nix_tm_update_parent_info(roc_nix_to_nix_priv(nix), ROC_NIX_TM_USER);
        rv = nix_tm_txsch_reg_config(roc_nix_to_nix_priv(nix), ROC_NIX_TM_USER);
        if (rv)
        {
            vec_free(tm_node_list);
            vec_free(tm_node_priority);
            vec_free(tm_node_sq);
            onp_pktio_warn("nix_tm_txsch_reg_config sw_if_index %u failed", sw_if_index);
            return rv;
        }
    }
    //Flush all smq queue
    roc_nix_smq_flush(nix);

    vec_free(tm_node_list);
    vec_free(tm_node_priority);
    vec_free(tm_node_sq);

    return 0;
}

void onp_pktio_get_tx_queue_stat(vlib_main_t *vm, onp_main_t *om,
                                u32 sw_if_index, u32 qid,
                                cnxk_pktio_queue_stats_t *qstats)
{
    vnet_hw_interface_t *hw = NULL;
    onp_pktio_t *od = NULL;

    hw = vnet_get_hw_interface_or_null (om->vnet_main, sw_if_index);

    if (!hw) return;

    od = onp_get_pktio (hw->dev_instance);

    if (qid >= od->n_tx_q)
    {
        onp_pktio_warn("invaild qid id %u, tx queue num %u", qid, od->n_tx_q);
        return;
    }

    if (cnxk_drv_pktio_queue_stats_get (vm, od->cnxk_pktio_index, qid, qstats, 0))
    {
        onp_pktio_warn("cnxk_drv_pktio_queue_stats_get sw_if_index %u tx_qid %u failed", sw_if_index, qid);
	    return;
    }
    return;
}

void onp_pktio_get_rx_queue_stat(vlib_main_t *vm, onp_main_t *om,
                                u32 sw_if_index, u32 qid,
                                cnxk_pktio_queue_stats_t *qstats)
{
    vnet_hw_interface_t *hw = NULL;
    onp_pktio_t *od = NULL;

    hw = vnet_get_hw_interface_or_null (om->vnet_main, sw_if_index);

    if (!hw) return;

    od = onp_get_pktio (hw->dev_instance);

    if (qid >= od->n_rx_q)
    {
        onp_pktio_warn("invaild qid id %u, rx queue num %u", qid, od->n_rx_q);
        return;
    }

    if (cnxk_drv_pktio_queue_stats_get (vm, od->cnxk_pktio_index, qid, qstats, 1))
    {
        onp_pktio_warn("cnxk_drv_pktio_queue_stats_get sw_if_index %u rx_qid %u failed", sw_if_index, qid);
	    return;
    }
    return;
}
