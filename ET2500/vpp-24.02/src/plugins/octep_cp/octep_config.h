/*
 * Copyright (c) 2023 Marvell.
 * SPDX-License-Identifier: Apache-2.0
 * https://spdx.org/licenses/Apache-2.0.html
 */

#ifndef __OCTEP_CONFIG_H__
#define __OCTEP_CONFIG_H__

#include <stdint.h>

#include <octep_hw.h>
#include "octep_action.h"

#ifndef ETH_ALEN
#define ETH_ALEN 6
#endif

#define MIN_HB_INTERVAL_MSECS	  1000
#define MAX_HB_INTERVAL_MSECS	  15000
#define DEFAULT_HB_INTERVAL_MSECS MIN_HB_INTERVAL_MSECS
#define IF_NAME_MAX_LEN		  256
#define DEFAULT_HB_MISS_COUNT 20

/* Network interface stats */
struct if_stats
{
  struct octep_iface_rx_stats rx_stats;
  struct octep_iface_tx_stats tx_stats;
};

/* Network interface data */
struct if_cfg
{
  u16 idx;
  u16 host_if_id;
  /* Current MTU of the interface */
  u16 mtu;
  /* Max Receive packet length of the interface */
  u16 max_rx_pktlen;
  u8 mac_addr[ETH_ALEN];
  /* Enum octep_ctrl_net_state */
  u16 link_state;
  /* Enum octep_ctrl_net_state */
  u16 rx_state;
  /* OCTEP_LINK_MODE_XXX */
  u8 autoneg;
  /* OCTEP_LINK_MODE_XXX */
  u8 pause_mode;
  /* SPEED_XXX */
  u32 speed;
  /* OCTEP_LINK_MODE_XXX */
  u64 supported_modes;
  /* OCTEP_LINK_MODE_XXX */
  u64 advertised_modes;
  /* Interface name */
  u8 if_name[IF_NAME_MAX_LEN];
};

/* Virtual function configuration */
struct vf_cfg
{
  /* VF index */
  int idx;
  /* Network interface data */
  struct if_cfg iface;
  struct if_stats ifstats;
  struct octep_fw_info info;
  struct vf_cfg *next;
};

/* Physical function configuration */
struct pf_cfg
{
  /* PF index */
  int idx;
  /* Network interface data */
  struct if_cfg iface;
  struct if_stats ifstats;
  struct octep_fw_info info;
  /* Number of vf's */
  int nvf;
  /* Configuration for vf's */
  struct vf_cfg *vfs;
  struct pf_cfg *next;
};

/* PEM configuration */
struct pem_cfg
{
  /* PEM index */
  int idx;
  /* Number of pf's */
  int npf;
  /* Nonfiguration for pf's */
  struct pf_cfg *pfs;
  struct pem_cfg *next;
};

/* App configuration */
struct app_cfg
{
  /* Number of pem's */
  int npem;
  /* Nonfiguration for pem's */
  struct pem_cfg *pems;
};

extern struct app_cfg cfg;

/*
 * Parse file and populate configuration.
 *
 * @param cfg_file_path: Path to configuration file.
 *
 * return value: 0 on success, -errno on failure.
 */
int octep_cp_config_init (const char *cfg_file_path);

/*
 * Get interface based on information in message header.
 *
 * @param ctx_info: non-null pointer to message context info. This is the
 *                  pem->pf context used to poll for messages.
 * @param msg_info: non-null pointer to message info. This is the info from
 *                  received message.
 * @param iface: non-null pointer to struct if_cfg *.
 * @param ifstats: non-null pointer to struct if_stats *.
 * @param info: non-null pointer to struct octep_fw_info *.
 *
 * return value: 0 on success, -errno on failure.
 */
int app_config_get_if_from_msg_info (union octep_cp_msg_info *ctx_info,
				     union octep_cp_msg_info *msg_info,
				     struct if_cfg **iface,
				     struct if_stats **ifstats,
				     struct octep_fw_info **info);

/*
 * Free allocated configuration artifacts.
 * return value: 0 on success, -errno on failure.
 */
int octep_cp_config_uninit ();

#endif /* __OCTEP_CONFIG_H__ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
