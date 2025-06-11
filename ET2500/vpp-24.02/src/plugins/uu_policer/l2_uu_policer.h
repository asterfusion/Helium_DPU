/*
 * security.h: types/functions for security-check.
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

#ifndef included_security_h
#define included_security_h

#include <vnet/vnet.h>

#include <vppinfra/bihash_24_8.h>
#include <vppinfra/bitmap.h>
#include <vppinfra/sparse_vec.h>
#include <vppinfra/pool.h>

typedef enum {
    L2_UU_POLICER_ERROR_DROP,
    L2_UU_POLICER_N_NEXT,
} l2_uu_policer_next_t;

typedef struct
{
    /* convenience */
    vlib_main_t *vlib_main;
    vnet_main_t *vnet_main;

    /* api */
    u16 msg_id_base;
       
     u32 *policer_index_by_sw_if_index;
     uword *enable_by_sw_if_index;

     u32 l2_input_feat_next[32];

} l2_uu_policer_main_t;

extern l2_uu_policer_main_t l2_uu_policer_main;

clib_error_t *l2_uu_policer_api_hookup (vlib_main_t *vm);

int l2_uu_policer_set_interface(u32 sw_if_index, u32 policer_index);

#endif /* included_security_h */
