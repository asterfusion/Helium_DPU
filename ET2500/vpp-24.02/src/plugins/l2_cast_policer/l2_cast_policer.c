/*
 * l2_cast_policer.c: L2 multicast/broadcast policer
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
#include <l2_cast_policer/l2_cast_policer.h>

l2_cast_policer_main_t l2_cast_policer_main;

static int
l2_cast_policer_set_interface (u32 sw_if_index, u32 policer_index,
			       u32 feature_bit, u32 **policer_index_by_sw_if_index,
			       uword **enable_by_sw_if_index)
{
  vec_validate (*policer_index_by_sw_if_index, sw_if_index);

  if (policer_index != ~0)
    {
      l2input_intf_bitmap_enable (sw_if_index, feature_bit, 1);
      clib_bitmap_set (*enable_by_sw_if_index, sw_if_index, 1);
    }
  else
    {
      l2input_intf_bitmap_enable (sw_if_index, feature_bit, 0);
      clib_bitmap_set (*enable_by_sw_if_index, sw_if_index, 0);
    }

  (*policer_index_by_sw_if_index)[sw_if_index] = policer_index;
  return 0;
}

int
l2_mcast_policer_set_interface (u32 sw_if_index, u32 policer_index)
{
  l2_cast_policer_main_t *lcpm = &l2_cast_policer_main;

  return l2_cast_policer_set_interface (
    sw_if_index, policer_index, L2INPUT_FEAT_MCAST_POLICER,
    &lcpm->mcast_policer_index_by_sw_if_index, &lcpm->mcast_enable_by_sw_if_index);
}

int
l2_bcast_policer_set_interface (u32 sw_if_index, u32 policer_index)
{
  l2_cast_policer_main_t *lcpm = &l2_cast_policer_main;

  return l2_cast_policer_set_interface (
    sw_if_index, policer_index, L2INPUT_FEAT_BCAST_POLICER,
    &lcpm->bcast_policer_index_by_sw_if_index, &lcpm->bcast_enable_by_sw_if_index);
}

static clib_error_t *
l2_cast_policer_init (vlib_main_t *vm)
{
  clib_error_t *error = 0;
  l2_cast_policer_main_t *lcpm = &l2_cast_policer_main;
  vlib_node_t *node = NULL;

  clib_memset (lcpm, 0, sizeof (*lcpm));

  lcpm->vlib_main = vm;
  lcpm->vnet_main = vnet_get_main ();

  vec_validate (lcpm->mcast_policer_index_by_sw_if_index, 128);
  vec_validate (lcpm->bcast_policer_index_by_sw_if_index, 128);
  clib_bitmap_alloc (lcpm->mcast_enable_by_sw_if_index, 128);
  clib_bitmap_alloc (lcpm->bcast_enable_by_sw_if_index, 128);

  node = vlib_get_node_by_name (vm, (u8 *) "l2-mcast-policer");
  feat_bitmap_init_next_nodes (vm, node->index, L2INPUT_N_FEAT,
			       l2input_get_feat_names (),
			       lcpm->mcast_l2_input_feat_next);

  node = vlib_get_node_by_name (vm, (u8 *) "l2-bcast-policer");
  feat_bitmap_init_next_nodes (vm, node->index, L2INPUT_N_FEAT,
			       l2input_get_feat_names (),
			       lcpm->bcast_l2_input_feat_next);

  error = l2_cast_policer_api_hookup (vm);
  return error;
}

VLIB_INIT_FUNCTION (l2_cast_policer_init);
