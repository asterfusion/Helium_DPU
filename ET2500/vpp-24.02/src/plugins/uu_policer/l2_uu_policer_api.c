/*
 * security_check_api.c - security check api
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

#include <vnet/vnet.h>
#include <vnet/interface.h>
#include <vnet/api_errno.h>

#include <vlibmemory/api.h>
#include <vlibapi/api.h>

#include <uu_policer/l2_uu_policer.api_enum.h>
#include <uu_policer/l2_uu_policer.api_types.h>

#define REPLY_MSG_ID_BASE l2_uu_policer_main.msg_id_base
#include <vlibapi/api_helper_macros.h>

#include <uu_policer/l2_uu_policer.h>


static int
api_l2_uu_policer_set_interface(u32 sw_if_index, 
                                u32 policer_index)
{
    return l2_uu_policer_set_interface(sw_if_index, policer_index);
}

static void
vl_api_l2_uu_policer_set_interface_t_handler (vl_api_l2_uu_policer_set_interface_t * mp)
{
    int rv;
    vl_api_l2_uu_policer_set_interface_reply_t *rmp;

    rv = api_l2_uu_policer_set_interface(ntohl (mp->sw_if_index), ntohl (mp->policer_index));

    REPLY_MACRO (VL_API_L2_UU_POLICER_SET_INTERFACE_REPLY);
}

/* API definitions */
#include <vnet/format_fns.h>
#include <uu_policer/l2_uu_policer.api.c>

/* Set up the API message handling tables */
clib_error_t *
l2_uu_policer_api_hookup (vlib_main_t *vm)
{
    l2_uu_policer_main_t *uupm = &l2_uu_policer_main;
    uupm->msg_id_base = setup_message_id_table ();
    return 0;
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
