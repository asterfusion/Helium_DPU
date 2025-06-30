/*
 * security.c: security check
 *
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

#include <vpp/app/version.h>

#include <vnet/vnet.h>
#include <vnet/plugin/plugin.h>
#include <vnet/l2/l2_input.h>
#include <vnet/l2/feat_bitmap.h>

#include <vlib/threads.h>
#include <uu_policer/l2_uu_policer.h>

l2_uu_policer_main_t l2_uu_policer_main;

int l2_uu_policer_set_interface(u32 sw_if_index, 
                                u32 policer_index)
{
    l2_uu_policer_main_t *uupm = &l2_uu_policer_main;

    vec_validate (uupm->policer_index_by_sw_if_index, sw_if_index);

    if (policer_index != ~0)
    {
        l2input_intf_bitmap_enable (sw_if_index, L2INPUT_FEAT_UU_POLICER, 1);
        clib_bitmap_set(uupm->enable_by_sw_if_index, sw_if_index, 1);
    }
    else 
    {
        l2input_intf_bitmap_enable (sw_if_index, L2INPUT_FEAT_UU_POLICER, 0);
        clib_bitmap_set(uupm->enable_by_sw_if_index, sw_if_index, 0);
    }
    
    uupm->policer_index_by_sw_if_index[sw_if_index] = policer_index;

    return 0;
}

static clib_error_t *
l2_uu_policer_init (vlib_main_t *vm)
{
    clib_error_t *error = 0;
    l2_uu_policer_main_t *uupm = &l2_uu_policer_main;
    vlib_node_t *node = NULL;

    clib_memset (uupm, 0, sizeof (*uupm));

    uupm->vlib_main = vm;
    uupm->vnet_main = vnet_get_main();

    vec_validate (uupm->policer_index_by_sw_if_index, 128);
    clib_bitmap_alloc(uupm->enable_by_sw_if_index, 128);

    node = vlib_get_node_by_name (vm, (u8 *) "l2-uu-policer");

    feat_bitmap_init_next_nodes (vm,
                                node->index,
                                L2INPUT_N_FEAT,
                                l2input_get_feat_names (),
                                uupm->l2_input_feat_next);

    /* api init */
    error = l2_uu_policer_api_hookup (vm);

    return error;
}

VLIB_INIT_FUNCTION (l2_uu_policer_init);
