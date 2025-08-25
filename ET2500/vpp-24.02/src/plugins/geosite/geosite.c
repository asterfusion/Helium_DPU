/*
 * geosite.c - skeleton vpp engine plug-in
 *
 * Copyright (c) <2024-2027> <Asterfusion Network>
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
#include <vnet/plugin/plugin.h>
#include <geosite/geosite.h>

#include <vlibapi/api.h>
#include <vlibmemory/api.h>
#include <vpp/app/version.h>
#include <stdbool.h>

//#include <vlib/unix/unix.h>


#include <geosite/geosite.api_enum.h>
#include <geosite/geosite.api_types.h>

#define REPLY_MSG_ID_BASE gmp->msg_id_base
#include <vlibapi/api_helper_macros.h>

#include <protobuf-c/protobuf-c.h>
#include "common.pb-c.h"

geosite_main_t geosite_main;

/* Action function shared between message handler and debug CLI */

int geosite_enable_disable (geosite_main_t * gmp, u32 sw_if_index,
                                   int enable_disable)
{
  vnet_sw_interface_t * sw;
  int rv = 0;

  /* Utterly wrong? */
  if (pool_is_free_index (gmp->vnet_main->interface_main.sw_interfaces,
                          sw_if_index))
    return VNET_API_ERROR_INVALID_SW_IF_INDEX;

  /* Not a physical port? */
  sw = vnet_get_sw_interface (gmp->vnet_main, sw_if_index);
  if (sw->type != VNET_SW_INTERFACE_TYPE_HARDWARE)
    return VNET_API_ERROR_INVALID_SW_IF_INDEX;

  geosite_create_periodic_process (gmp);

  vnet_feature_enable_disable ("device-input", "geosite",
                               sw_if_index, enable_disable, 0, 0);

  /* Send an event to enable/disable the periodic scanner process */
  vlib_process_signal_event (gmp->vlib_main,
                             gmp->periodic_node_index,
                             GEOSITE_EVENT_PERIODIC_ENABLE_DISABLE,
                            (uword)enable_disable);
  return rv;
}

static clib_error_t *
geosite_enable_disable_command_fn (vlib_main_t * vm,
                                   unformat_input_t * input,
                                   vlib_cli_command_t * cmd)
{
  geosite_main_t * gmp = &geosite_main;
  u32 sw_if_index = ~0;
  int enable_disable = 1;

  int rv;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "disable"))
        enable_disable = 0;
      else if (unformat (input, "%U", unformat_vnet_sw_interface,
                         gmp->vnet_main, &sw_if_index))
        ;
      else
        break;
  }

  if (sw_if_index == ~0)
    return clib_error_return (0, "Please specify an interface...");

  rv = geosite_enable_disable (gmp, sw_if_index, enable_disable);

  switch(rv)
    {
  case 0:
    break;

  case VNET_API_ERROR_INVALID_SW_IF_INDEX:
    return clib_error_return
      (0, "Invalid interface, only works on physical ports");
    break;

  case VNET_API_ERROR_UNIMPLEMENTED:
    return clib_error_return (0, "Device driver doesn't support redirection");
    break;

  default:
    return clib_error_return (0, "geosite_enable_disable returned %d",
                              rv);
    }
  return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (geosite_enable_disable_command, static) =
{
  .path = "geosite enable-disable",
  .short_help =
  "geosite enable-disable <interface-name> [disable]",
  .function = geosite_enable_disable_command_fn,
};
/* *INDENT-ON* */

static clib_error_t *
geosite_lookup_host_command_fn (vlib_main_t * vm, unformat_input_t * input, vlib_cli_command_t * cmd) {
    geosite_main_t * gmp = &geosite_main;
    u8 *host;
    u32 *cc = 0;

    if (!unformat(input, "%v", &host))
        return clib_error_return(0, "Expected host");

    u32 *cc_indices = domain_trie_match(gmp->domain_trie, (char*)host);
    if (cc_indices) {
        vec_foreach(cc, cc_indices) {
            vlib_cli_output(vm, "Matched country: %s", gmp->domain_trie->country_codes[*cc]);
        }
    } else {
        vlib_cli_output(vm, "No match");
    }
    vec_free(cc_indices);
    vec_free (host);
    return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND(geosite_lookup_host_command, static) = {
    .path = "geosite lookup",
    .short_help = "geosite lookup <hostname>",
    .function = geosite_lookup_host_command_fn,
};
/* *INDENT-ON* */

int update_geosite_trie(domain_trie_t *new_trie)
{
    geosite_main_t * gmp = &geosite_main;
    domain_trie_t *old_trie = gmp->domain_trie;

    vlib_worker_thread_barrier_sync (gmp->vlib_main);
    gmp->domain_trie = new_trie;
    vlib_worker_thread_barrier_release (gmp->vlib_main);
    domain_trie_free(old_trie);

    return 0;
}

static clib_error_t *
geosite_load_command_fn(vlib_main_t *vm, unformat_input_t *input, vlib_cli_command_t *cmd)
{
    const char *default_path = "/etc/vpp/geosite.dat";
    const char *path = NULL;
    u8 *filename = 0;
    domain_trie_t *new_trie = NULL;

    while (unformat_check_input(input) != UNFORMAT_END_OF_INPUT)
    {
        if (unformat(input, "%s", &filename))
            path = (const char *)filename;
        else
            return clib_error_return(0, "Invalid input for file path.");
    }

    if (!path)
        path = default_path;

    vlib_cli_output(vm, "Loading geosite from: %s", path);

    new_trie = clib_mem_alloc(sizeof(domain_trie_t));
    if(!new_trie)
    {
        vec_free(filename);
        return clib_error_return(0, "Failed to alloc new trie!\n");
    }
    if (load_geosite_dat(path, new_trie) < 0)
    {
        vec_free(filename);
        clib_mem_free(new_trie);
        return clib_error_return(0, "Failed to load geosite from %s", path);
    }
    if (update_geosite_trie(new_trie) < 0)
    {
        vec_free(filename);
        clib_mem_free(new_trie);
        return clib_error_return(0, "Failed to update geosite from %s", path);
    }

    vec_free(filename);
    vlib_cli_output(vm, "Geosite loaded successfully.");
    return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND(geosite_load_command, static) = {
    .path = "geosite load",
    .short_help = "geosite load [<file-path>]",
    .function = geosite_load_command_fn,
};
/* *INDENT-ON* */

static clib_error_t *
show_geosite_stats_command_fn(vlib_main_t *vm,
                              unformat_input_t *input,
                              vlib_cli_command_t *cmd)
{
    geosite_main_t * gmp = &geosite_main;
    bool show_details = false;
    char **cc;

    if (!gmp->domain_trie)
        return clib_error_return(0, "geosite not loaded");

    while (unformat_check_input(input) != UNFORMAT_END_OF_INPUT)
    {
        if (unformat (input, "details"))
        {
            show_details = true;
        }
    }

    u32 cc_total = pool_elts(gmp->domain_trie->country_codes);
    u32 domain_total = gmp->domain_trie->domain_counts;

    vlib_cli_output(vm, "Geosite Statistics:");
    vlib_cli_output(vm, "  Total Country Codes: %u", cc_total);
    vlib_cli_output(vm, "  Total Domain Rules : %u", domain_total);

    if (show_details)
    {
        pool_foreach(cc, gmp->domain_trie->country_codes) {
            vlib_cli_output(vm, "Country Codes: %s", *cc);
        }
    }

    return NULL;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND(show_geosite_stats_command, static) = {
    .path = "show geosite stats",
    .short_help = "show geosite stats [details]",
    .function = show_geosite_stats_command_fn,
};
/* *INDENT-ON* */

static clib_error_t *
geoip_lookup_command_fn (vlib_main_t *vm,
                         unformat_input_t *input,
                         vlib_cli_command_t *cmd)
{
    geoip_db_t *db = geosite_main.geoip_trie;

    ip4_address_t ip4;
    ip6_address_t ip6;
    u32 *cc = 0;

    if (db == NULL)
    {
        vlib_cli_output(vm, "not load geoip dat");
        return 0;
    }

    if (unformat (input, "%U", unformat_ip4_address, &ip4))
    {
        u32 *cc_indices = geoip_lookup_v4 (db, &ip4);
        if (cc_indices) {
            vec_foreach(cc, cc_indices) {
                vlib_cli_output(vm, "IPv4 %U Matched country: %s", 
                        format_ip4_address, &ip4,
                        db->country_codes[*cc]);
            }
        } else {
            vlib_cli_output(vm, "No match");
        }
        return 0;
    }
    else if (unformat (input, "%U", unformat_ip6_address, &ip6))
    {
        u32 *cc_indices = geoip_lookup_v6 (db, &ip6);
        if (cc_indices) {
            vec_foreach(cc, cc_indices) {
                vlib_cli_output(vm, "IPv6 %U Matched country: %s", 
                        format_ip6_address, &ip6,
                        db->country_codes[*cc]);
            }
        } else {
            vlib_cli_output(vm, "No match");
        }
        return 0;
    }

    return clib_error_return (0, "expected ip4 or ip6 address");
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (geoip_lookup_command, static) = {
    .path = "geoip lookup",
    .short_help = "geoip lookup <ip4|ip6 address>",
    .function = geoip_lookup_command_fn,
};
/* *INDENT-ON* */

int update_geoip_trie(geoip_db_t *new_trie)
{
    geosite_main_t * gmp = &geosite_main;
    geoip_db_t *old_trie = gmp->geoip_trie;

    vlib_worker_thread_barrier_sync (gmp->vlib_main);
    gmp->geoip_trie = new_trie;
    vlib_worker_thread_barrier_release (gmp->vlib_main);
    geoip_db_free(old_trie);

    return 0;
}
static clib_error_t *
geoip_load_command_fn(vlib_main_t *vm, unformat_input_t *input, vlib_cli_command_t *cmd)
{
    const char *default_path = "/etc/vpp/geoip.dat";
    const char *path = NULL;
    u8 *filename = 0;
    geoip_db_t *new_trie = NULL;

    while (unformat_check_input(input) != UNFORMAT_END_OF_INPUT)
    {
        if (unformat(input, "%s", &filename))
            path = (const char *)filename;
        else
            return clib_error_return(0, "Invalid input for file path.");
    }

    if (!path)
        path = default_path;

    vlib_cli_output(vm, "Loading geoip from: %s", path);

    new_trie = geoip_db_load(path);
    if (new_trie == NULL)
    {
        vec_free(filename);
        return clib_error_return(0, "Failed to load geoip from %s", path);
    }
    if (update_geoip_trie(new_trie) < 0)
    {
        vec_free(filename);
        clib_mem_free(new_trie);
        return clib_error_return(0, "Failed to update geoip from %s", path);
    }

    vec_free(filename);
    vlib_cli_output(vm, "Geoip loaded successfully.");
    return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND(geoip_load_command, static) = {
    .path = "geoip load",
    .short_help = "geoip load [<file-path>]",
    .function = geoip_load_command_fn,
};
/* *INDENT-ON* */

static clib_error_t *
show_geoip_stats_command_fn(vlib_main_t *vm,
                              unformat_input_t *input,
                              vlib_cli_command_t *cmd)
{
    geosite_main_t * gmp = &geosite_main;
    bool show_details = false;
    char **cc;

    if (!gmp->geoip_trie)
        return clib_error_return(0, "geoip not loaded");

    while (unformat_check_input(input) != UNFORMAT_END_OF_INPUT)
    {
        if (unformat (input, "details"))
        {
            show_details = true;
        }
    }

    u32 cc_total = pool_elts(gmp->geoip_trie->country_codes);
    u32 ipv4_total = gmp->geoip_trie->ipv4_counts;
    u32 ipv6_total = gmp->geoip_trie->ipv6_counts;

    vlib_cli_output(vm, "Geoip Statistics:");
    vlib_cli_output(vm, "  Total Country Codes: %u", cc_total);
    vlib_cli_output(vm, "  Total IPv4 counts: %u", ipv4_total);
    vlib_cli_output(vm, "  Total IPv6 counts: %u", ipv6_total);

    if (show_details)
    {
        pool_foreach(cc, gmp->geoip_trie->country_codes) {
            vlib_cli_output(vm, "Country Codes: %s", *cc);
        }
    }
    return NULL;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND(show_geoip_stats_command, static) = {
    .path = "show geoip stats",
    .short_help = "show geoip stats [details]",
    .function = show_geoip_stats_command_fn,
};
/* *INDENT-ON* */

#if GEOSITE_DEBUG
static void print_domain_cb(const char *domain, u32 *country_indices, void *ctx)
{
    geosite_main_t * gmp = &geosite_main;
    u8 **out = ctx;
    u8 *s = 0;

    s = format(s, "domain: %s -> countries: ", domain);
    for (int i = 0; i < vec_len(country_indices); i++) {
        s = format(s, "%s ", gmp->domain_trie->country_codes[country_indices[i]]);
    }
    s = format(s, "\n");

    *out = format(*out, "%v", s);
    vec_free(s);
}

static clib_error_t *
show_geosite_trie_command_fn(vlib_main_t *vm,
                              unformat_input_t *input,
                              vlib_cli_command_t *cmd)
{
    geosite_main_t * gmp = &geosite_main;
    u8 *out = 0;

    if (!gmp->domain_trie)
        return clib_error_return(0, "geosite not loaded");


    domain_trie_traverse(gmp->domain_trie, print_domain_cb, &out);

    if (out)
    {
        vlib_cli_output(vm, "%v", out);
        vec_free(out);
    }
    return NULL;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND(show_geosite_trie_command, static) = {
    .path = "show geosite trie",
    .short_help = "show geosite trie",
    .function = show_geosite_trie_command_fn,
};
/* *INDENT-ON* */
#endif


/* API message handler */
static void vl_api_geosite_enable_disable_t_handler
(vl_api_geosite_enable_disable_t * mp)
{
  vl_api_geosite_enable_disable_reply_t * rmp;
  geosite_main_t * gmp = &geosite_main;
  int rv;

  rv = geosite_enable_disable (gmp, ntohl(mp->sw_if_index),
                                      (int) (mp->enable_disable));

  REPLY_MACRO(VL_API_GEOSITE_ENABLE_DISABLE_REPLY);
}

/* API definitions */
#include <geosite/geosite.api.c>

static clib_error_t * geosite_init (vlib_main_t * vm)
{
  geosite_main_t * gmp = &geosite_main;
  clib_error_t * error = 0;

  gmp->vlib_main = vm;
  gmp->vnet_main = vnet_get_main();
  gmp->domain_trie = NULL;

  /* Add our API messages to the global name_crc hash table */
  gmp->msg_id_base = setup_message_id_table ();

  return error;
}

VLIB_INIT_FUNCTION (geosite_init);

/* *INDENT-OFF* */
VNET_FEATURE_INIT (geosite, static) =
{
  .arc_name = "device-input",
  .node_name = "geosite",
  .runs_before = VNET_FEATURES ("ethernet-input"),
};
/* *INDENT-ON */

/* *INDENT-OFF* */
VLIB_PLUGIN_REGISTER () =
{
  .version = VPP_BUILD_VER,
  .description = "geosite plugin description goes here",
};
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
