/*
 * Copyright (c) 2022 Marvell.
 * SPDX-License-Identifier: Apache-2.0
 * https://spdx.org/licenses/Apache-2.0.html
 */

#include <onp/drv/modules/crypto/crypto_priv.h>
#include <onp/drv/modules/ipsec/ipsec_priv.h>

void
cn10k_ipsec_capability_read (union cpt_eng_caps hw_caps,
			     cnxk_crypto_grp_capability_t *capability)
{
  capability->ipsec_max_num_sa = CNXK_MAX_TOTAL_IPSEC_SA;
  capability->ipsec_max_antireplay_ws = ROC_AR_WIN_SIZE_MAX;
  capability->ipsec_tunnel_mode = 1;
  capability->ipsec_inbound_direction = 1;
  capability->ipsec_outbound_direction = 1;
  capability->ipsec_tunnel_ip_type_v4 = 1;
  capability->ipsec_tunnel_ip_type_v6 = 1;
  capability->ipsec_lookaside_mode = 1;
}

void
cn10k_crypto_group_capability_read (union cpt_eng_caps hw_caps_list[],
				    cnxk_crypto_grp_capability_t *capability,
				    cnxk_crypto_group_t group)
{
  union cpt_eng_caps hw_caps = hw_caps_list[group];

  /*
   * Populate capability structure for CNXK_CRYPTO_GROUP_IE group,
   * SE and AE groups capabilities are not yet supported.
   */
  if (group == CNXK_CRYPTO_GROUP_IE)
    {
      cnxk_crypto_iegroup_capability_read (hw_caps, capability);
      cn10k_ipsec_capability_read (hw_caps, capability);
    }
}

i32
cn10k_crypto_capability_populate (vlib_main_t *vm, u16 cnxk_crypto_index,
				  cnxk_crypto_capability_t *capability)
{
  cnxk_crypto_dev_t *crypto_dev = cnxk_crypto_dev_get (cnxk_crypto_index);
  int i;

  if (!crypto_dev)
    {
      cnxk_crypto_err ("crypto device %u ptr is NULL", cnxk_crypto_index);
      return -1;
    }

  capability->max_crypto_queues = CNXK_CRYPTO_MAX_QUEUES_PER_DEVICE;
  for (i = 0; i < CNXK_CRYPTO_MAX_GROUPS; i++)
    {
      capability->cnxk_crypto_groups++;
      cn10k_crypto_group_capability_read (crypto_dev->cnxk_roc_cpt->hw_caps,
					  &capability->grp_capa[i], i);
    }

  return 0;
}

cnxk_crypto_ops_t crypto_10k_ops = {
  .cnxk_crypto_configure = cnxk_crypto_configure,
  .cnxk_crypto_clear = cnxk_crypto_clear,
  .cnxk_crypto_qpair_init = cnxk_crypto_queue_init,
  .cnxk_crypto_capability_populate = cn10k_crypto_capability_populate,
};

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
