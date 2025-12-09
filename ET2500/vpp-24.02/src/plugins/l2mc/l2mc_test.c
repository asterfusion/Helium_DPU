/*
 * l2mc.c - l2mc vpp-api-test plug-in
 *
 * Copyright (c) <current-year> <your-organization>
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
#include <vat/vat.h>
#include <vlibapi/api.h>
#include <vlibmemory/api.h>
#include <vppinfra/error.h>
#include <stdbool.h>
#include <l2mc/l2mc.h>

#define __plugin_msg_base l2mc_test_main.msg_id_base
#include <vlibapi/vat_helper_macros.h>

uword unformat_sw_if_index (unformat_input_t * input, va_list * args);

/* Declare message IDs */
#include <l2mc/l2mc.api_enum.h>
#include <l2mc/l2mc.api_types.h>

typedef struct
{
  /* API message ID base */
  u16 msg_id_base;
  vat_main_t *vat_main;
} l2mc_test_main_t;

l2mc_test_main_t l2mc_test_main;

int api_bridge_domain_add_del_multicast(vat_main_t * vam)
{
  vl_api_bridge_domain_add_del_multicast_t * mp;
  int ret;

  M(BRIDGE_DOMAIN_ADD_DEL_MULTICAST, mp);
  mp->bd_id = 1;
  mp->is_add = true;
  mp->sw_if_index = ~0;

  /* send it... */
  S(mp);

  /* Wait for a reply... */
  W (ret);
  return ret;
}

/*
 * List of messages that the l2mc test plugin sends,
 * and that the data plane plugin processes
 */
#include <l2mc/l2mc.api_test.c>

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
