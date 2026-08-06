/*
 * l2_cast_policer.h: types/functions for L2 multicast/broadcast policer
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

#ifndef included_l2_cast_policer_h
#define included_l2_cast_policer_h

#include <vnet/vnet.h>

#include <vppinfra/bitmap.h>

typedef enum
{
  L2_CAST_POLICER_NEXT_DROP,
  L2_CAST_POLICER_N_NEXT,
} l2_cast_policer_next_t;

typedef struct
{
  vlib_main_t *vlib_main;
  vnet_main_t *vnet_main;

  u16 msg_id_base;

  u32 *mcast_policer_index_by_sw_if_index;
  u32 *bcast_policer_index_by_sw_if_index;
  uword *mcast_enable_by_sw_if_index;
  uword *bcast_enable_by_sw_if_index;

  u32 mcast_l2_input_feat_next[32];
  u32 bcast_l2_input_feat_next[32];
} l2_cast_policer_main_t;

extern l2_cast_policer_main_t l2_cast_policer_main;

clib_error_t *l2_cast_policer_api_hookup (vlib_main_t *vm);

int l2_mcast_policer_set_interface (u32 sw_if_index, u32 policer_index);
int l2_bcast_policer_set_interface (u32 sw_if_index, u32 policer_index);

#endif
