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

#include <vnet/vnet.h>
#include <vnet/hash/hash.h>
#include <vlibapi/api.h>
#include <vlibmemory/api.h>
#include <vppinfra/xxhash.h>

#include <vnet/hash/hash.api_enum.h>
#include <vnet/hash/hash.api_types.h>

#define REPLY_MSG_ID_BASE vnet_hash_main.msg_id_base
#include <vlibapi/api_helper_macros.h>

static void
vl_api_set_hash_seed_t_handler (vl_api_set_hash_seed_t * mp)
{
  int rv =0;
  vl_api_set_hash_seed_reply_t *rmp;
  u32 seed = ntohl(mp->seed);

  hash_set_global_seed(seed);

  REPLY_MACRO (VL_API_SET_HASH_SEED_REPLY);
}

/* 
 * API message registration 
 */
#include <vnet/hash/hash.api.c>

static clib_error_t *
hash_api_hookup (vlib_main_t * vm)
{
  vnet_hash_main_t *hm = &vnet_hash_main;
  
  /* 
   * Set up the (msg_name, crc, message-id) table
   */
  hm->msg_id_base = setup_message_id_table ();

  return 0;
}

VLIB_API_INIT_FUNCTION (hash_api_hookup);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c_set_style "gnu")
 * End:
 */

