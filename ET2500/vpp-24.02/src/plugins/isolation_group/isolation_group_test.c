/*
 * isolation_group.c - isolation_group vpp-api-test plug-in
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

#define __plugin_msg_base isolation_group_test_main.msg_id_base
#include <vlibapi/vat_helper_macros.h>

uword unformat_sw_if_index (unformat_input_t * input, va_list * args);

/* Declare message IDs */
#include <isolation_group/isolation_group.api_enum.h>
#include <isolation_group/isolation_group.api_types.h>

typedef struct
{
  /* API message ID base */
  u16 msg_id_base;
  vat_main_t *vat_main;
} isolation_group_test_main_t;

isolation_group_test_main_t isolation_group_test_main;

static int api_isolation_group_enable_disable (vat_main_t * vam)
{
  unformat_input_t * i = vam->input;
  int enable_disable = 1;
  u32 sw_if_index = ~0;
  vl_api_isolation_group_enable_disable_t * mp;
  int ret;

  /* Parse args required to build the message */
  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "%U", unformat_sw_if_index, vam, &sw_if_index))
          ;
        else if (unformat (i, "sw_if_index %d", &sw_if_index))
          ;
      else if (unformat (i, "disable"))
          enable_disable = 0;
      else
          break;
    }

  if (sw_if_index == ~0)
    {
      errmsg ("missing interface name / explicit sw_if_index number \n");
      return -99;
    }

  /* Construct the API message */
  M(ISOLATION_GROUP_ENABLE_DISABLE, mp);
  mp->sw_if_index = ntohl (sw_if_index);
  mp->enable_disable = enable_disable;

  /* send it... */
  S(mp);

  /* Wait for a reply... */
  W (ret);
  return ret;
}

int api_isolation_group(vat_main_t * vam)
{
    vl_api_isolation_group_t * mp;
    int ret;

    M(ISOLATION_GROUP, mp);
    mp->group_id = 1;
    mp->is_add = true;
    mp->sw_if_index = ~0;

    /* send it... */
    S(mp);

    /* Wait for a reply... */
    W (ret);
    return ret;
}

int api_isolation_group_set_source_port(vat_main_t * vam)
{
    vl_api_isolation_group_set_source_port_t * mp;
    int ret;

    M(ISOLATION_GROUP_SET_SOURCE_PORT, mp);
    mp->group_id = 1;
    mp->is_add = true;
    mp->source_sw_if_index = ~0;

    /* send it... */
    S(mp);

    /* Wait for a reply... */
    W (ret);
    return ret;
}

/*
 * List of messages that the isolation_group test plugin sends,
 * and that the data plane plugin processes
 */
#include <isolation_group/isolation_group.api_test.c>

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
