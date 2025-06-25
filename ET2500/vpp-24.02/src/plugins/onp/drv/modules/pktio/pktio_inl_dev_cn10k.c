/*
 * Copyright (c) 2021 Marvell.
 * SPDX-License-Identifier: Apache-2.0
 * https://spdx.org/licenses/Apache-2.0.html
 */

#include <onp/drv/modules/pktio/pktio_priv.h>
#include <onp/drv/modules/pktio/pktio_rx.h>
#include <onp/drv/modules/pktio/pktio_fp_ops.h>

static_always_inline i32
cn10k_pktio_inl_dev_outb_cfg (cnxk_pktio_t *pktio,
			      cnxk_pktio_inl_dev_cfg_t *inl_dev_cfg)
{
  struct roc_nix *nix = &pktio->nix;
  struct roc_cpt_lf *cpt_lf;
  u64 cpt_io_addr;
  int rv;

  nix->outb_nb_desc = inl_dev_cfg->outb_nb_desc;
  nix->outb_nb_crypto_qs = inl_dev_cfg->outb_nb_crypto_qs;
  nix->ipsec_out_max_sa = 0;
  nix->ipsec_out_sso_pffunc = true;

  rv = roc_nix_inl_outb_init (nix);
  if (rv)
    {
      cnxk_pktio_err ("roc_nix_inl_outb_init failed with '%s' error",
		      roc_error_msg_get (rv));
      return -1;
    }
  pktio->fp_ctx.outb_nb_desc = nix->outb_nb_desc;
  pktio->fp_ctx.outb_nb_crypto_qs = nix->outb_nb_crypto_qs;
  pktio->fp_ctx.cached_cpt_pkts = 0;

  cpt_lf = roc_nix_inl_outb_lf_base_get (&pktio->nix);
  pktio->fp_ctx.cpt_lf = cpt_lf;

  cpt_io_addr = cpt_lf->io_addr;
  cpt_io_addr |= (ROC_CN10K_CPT_INST_DW_M1 << 4);
  pktio->fp_ctx.cpt_io_addr = cpt_io_addr;

  return 0;
}

static_always_inline i32
cn10k_pktio_inl_dev_inb_cfg (cnxk_pktio_t *pktio)
{
  struct roc_nix *nix = &pktio->nix;
  cnxk_pktio_main_t *pm;
  u32 min_spi, max_spi;
  int rv;

  nix->ipsec_in_min_spi = CNXK_PKTIO_RX_IPSEC_MIN_SPI;
  nix->ipsec_in_max_spi = CNXK_PKTIO_RX_IPSEC_MAX_SPI;

  rv = roc_nix_inl_inb_init (nix);
  if (rv)
    {
      cnxk_pktio_err ("roc_nix_inl_inb_init failed with '%s' error",
		      roc_error_msg_get (rv));
      return -1;
    }

  pm = cnxk_pktio_get_main ();
  pm->inl_dev.inb_sa_base = roc_nix_inl_inb_sa_base_get (NULL, true);
  if (!pm->inl_dev.inb_sa_base)
    {
      cnxk_pktio_err ("roc_nix_inl_inb_sa_base_get failed");
      return -1;
    }

  pm->inl_dev.inb_spi_mask =
    roc_nix_inl_inb_spi_range (NULL, true, &min_spi, &max_spi);
  if (!pm->inl_dev.inb_spi_mask)
    {
      cnxk_pktio_err ("roc_nix_inl_inb_spi_range returned zero mask");
      return -1;
    }

  pm->inl_dev.is_enabled = 1;
  return 0;
}

i32
cn10k_pktio_inl_dev_cfg (vlib_main_t *vm,
			 cnxk_pktio_inl_dev_cfg_t *inl_dev_cfg,
			 u32 enable_outbound, u32 enable_inbound,
			 u16 *ipsec_offloads)
{
  cnxk_pktio_main_t *pm = cnxk_pktio_get_main ();
  cnxk_pktio_ops_map_t *pktio_ops = NULL;
  struct idev_cfg *idev = idev_get_cfg ();
  struct roc_cpt_rxc_time_cfg rxc_cfg;
  cnxk_pktio_t *pktio = NULL;
  int rv;
  u8 id;

  for (id = 0; id < pm->n_pktios; id++)
    {
      pktio_ops = cnxk_pktio_get_pktio_ops (id);
      pktio = &pktio_ops->pktio;

      if (pktio->is_inline)
	continue;
      if (enable_outbound)
	{
	  rv = cn10k_pktio_inl_dev_outb_cfg (pktio, inl_dev_cfg);
	  if (rv)
	    return rv;
	  *ipsec_offloads |= CNXK_IPSEC_OFFLOAD_FLAG_INL_OUTBOUND;
	}
      /* Use inline dev only when it is probed */
      if (enable_inbound && pm->inl_dev.is_enabled)
	{
	  /* Enable inbound configuration for inline device */
	  rv = cn10k_pktio_inl_dev_inb_cfg (pktio);
	  if (rv)
	    return rv;
	  *ipsec_offloads |= CNXK_IPSEC_OFFLOAD_FLAG_INL_INBOUND;
	  roc_nix_inb_mode_set (&pktio->nix, true);
	  roc_nix_inl_inb_set (&pktio->nix, true);

	  if (inl_dev_cfg->reassembly_conf.max_wait_time_ms)
	    {
	      rxc_cfg.step =
		(inl_dev_cfg->reassembly_conf.max_wait_time_ms * 1000 /
		 inl_dev_cfg->reassembly_conf.active_limit);
	      rxc_cfg.active_limit = inl_dev_cfg->reassembly_conf.active_limit;
	      rxc_cfg.active_thres = inl_dev_cfg->reassembly_conf.active_thres;
	      rxc_cfg.zombie_limit = inl_dev_cfg->reassembly_conf.zombie_limit;
	      rxc_cfg.zombie_thres = inl_dev_cfg->reassembly_conf.zombie_thres;
	      rv = roc_cpt_rxc_time_cfg (idev->cpt, &rxc_cfg);
	      if (rv)
		{
		  cnxk_pktio_err (
		    "roc_nix_reassembly_configure failed with '%s' error",
		    roc_error_msg_get (rv));
		  return rv;
		}
	    }
	}
    }

  return 0;
}

i32
cn10k_pktio_inl_dev_inb_ctx_flush (vlib_main_t *vm, void *sa_cptr)
{
  int rv;

  rv = roc_nix_inl_sa_sync (NULL, sa_cptr, true, ROC_NIX_INL_SA_OP_FLUSH);
  if (rv)
    {
      cnxk_pktio_err (
	"roc_nix_inl_sa_sync flush operation failed with '%s' error",
	roc_error_msg_get (rv));
      return -1;
    }
  return 0;
}

i32
cn10k_pktio_inl_dev_inb_ctx_reload (vlib_main_t *vm, void *sa_cptr)
{
  int rv;

  rv = roc_nix_inl_sa_sync (NULL, sa_cptr, true, ROC_NIX_INL_SA_OP_RELOAD);
  if (rv)
    {
      cnxk_pktio_err (
	"roc_nix_inl_sa_sync reload operation failed with '%s' error",
	roc_error_msg_get (rv));
      return -1;
    }
  return 0;
}

i32
cn10k_pktio_inl_dev_inb_ctx_write (vlib_main_t *vm, void *sa_dptr,
				   void *sa_cptr, u16 sa_len)
{
  int rv;

  rv = roc_nix_inl_ctx_write (NULL, sa_dptr, sa_cptr, true, sa_len);
  if (rv)
    {
      cnxk_pktio_err ("roc_nix_inl_ctx_write failed with '%s' error",
		      roc_error_msg_get (rv));
      return -1;
    }
  return 0;
}

i32
cn10k_pktio_inl_dev_outb_ctx_write (vlib_main_t *vm, void *sa_dptr,
				    void *sa_cptr, u16 sa_len)
{
  cnxk_pktio_main_t *pm = cnxk_pktio_get_main ();
  cnxk_pktio_ops_map_t *pktio_ops = NULL;
  cnxk_pktio_t *pktio = NULL;
  int rv;
  u8 id;

  if (!vec_len (pm->pktio_ops))
    return -1;

  for (id = 0; id < pm->n_pktios; id++)
    {
      pktio_ops = cnxk_pktio_get_pktio_ops (id);
      pktio = &pktio_ops->pktio;

      if (pktio->is_inline)
	continue;

      rv =
	roc_nix_inl_ctx_write (&pktio->nix, sa_dptr, sa_cptr, false, sa_len);
      if (rv)
	{
	  cnxk_pktio_err ("roc_nix_inl_ctx_write failed with '%s' error",
			  roc_error_msg_get (rv));
	  return -1;
	}
    }

  return 0;
}

i32
cn10k_pktio_inl_dev_init (cnxk_pktio_t *pktio, cnxk_plt_pci_device_t *dev)
{
  cnxk_pktio_ops_map_t *pktio_ops;
  cnxk_pktio_main_t *pm;
  int rv;

  pm = cnxk_pktio_get_main ();
  if (pm->inl_dev.is_enabled)
    {
      cnxk_pktio_err ("Inline device is already enabled");
      return -1;
    }
  pm->inl_dev.dev.pci_dev = dev;
  pktio->nix.pci_dev = dev;
  pm->inl_dev.dev.ipsec_in_min_spi = CNXK_PKTIO_RX_IPSEC_MIN_SPI;
  pm->inl_dev.dev.ipsec_in_max_spi = CNXK_PKTIO_RX_IPSEC_MAX_SPI;
  pm->inl_dev.dev.wqe_skip = 0;
  pm->inl_dev.dev.nb_meta_bufs = CNXK_PKTIO_INL_DEF_META_BUFS;
  pm->inl_dev.dev.meta_buf_sz = CNXK_PKTIO_INL_DEF_META_SZ;
  pm->inl_dev.dev.attach_cptlf = true;

  rv = roc_nix_inl_dev_init (&pm->inl_dev.dev);
  if (rv)
    {
      cnxk_pktio_err ("roc_nix_inl_dev_init failed with '%s' error",
		      roc_error_msg_get (rv));
      return -1;
    }

  pktio->is_inline = 1;
  pktio_ops = cnxk_pktio_get_pktio_ops (pktio->pktio_index);
  clib_memcpy (&pktio_ops->fops, &cn10k_inl_dev_pktio_ops,
	       sizeof (cnxk_pktio_ops_t));

  roc_nix_inl_meta_pool_cb_register (cn10k_pool_inl_meta_pool_cb);
  pm->inl_dev.is_enabled = 1;

  return pktio->pktio_index;
}

static_always_inline i32
cn10k_pktio_inl_dev_start (vlib_main_t *vm, cnxk_pktio_t *dev)
{
  return 0;
}

static_always_inline i32
cn10k_pktio_inl_dev_stop (vlib_main_t *vm, cnxk_pktio_t *dev)
{
  return 0;
}

static_always_inline i32
cn10k_pktio_inl_dev_promisc_enable (vlib_main_t *vm, cnxk_pktio_t *dev)
{
  return 0;
}

static_always_inline i32
cn10k_pktio_inl_dev_mtu_set (vlib_main_t *vm, cnxk_pktio_t *dev, u32 mtu)
{
  return 0;
}

static_always_inline i32
cn10k_pktio_inl_dev_mtu_get (vlib_main_t *vm, cnxk_pktio_t *dev, u32 *mtu)
{
  return 0;
}

static_always_inline i32
cn10k_pktio_inl_dev_promisc_disable (vlib_main_t *vm, cnxk_pktio_t *dev)
{
  return 0;
}

static_always_inline i32
cn10k_pktio_inl_dev_mac_addr_set (vlib_main_t *vm, cnxk_pktio_t *dev,
				  char *addr)
{
  return 0;
}

#ifdef VPP_PLATFORM_ET2500
static_always_inline i32
cn10k_pktio_inl_dev_mac_addr_del (vlib_main_t *vm, cnxk_pktio_t *dev,
				  char *addr)
#else
static_always_inline i32
cn10k_pktio_inl_dev_mac_addr_del (vlib_main_t *vm, cnxk_pktio_t *dev)
#endif
{
  return 0;
}

static_always_inline i32
cn10k_pktio_inl_dev_mac_addr_get (vlib_main_t *vm, cnxk_pktio_t *dev,
				  char *addr)
{
  return 0;
}

static_always_inline i32
cn10k_pktio_inl_dev_flowkey_set (vlib_main_t *vm, cnxk_pktio_t *dev,
				 cnxk_pktio_rss_flow_key_t flowkey)
{
  return 0;
}

static_always_inline i32
cn10k_pktio_inl_dev_rss_key_set (vlib_main_t *vm, cnxk_pktio_t *dev,
				 const u8 *rss_key, u8 rss_key_len)
{
  return 0;
}

static_always_inline i32
cn10k_pktio_inl_dev_stats_get (vlib_main_t *vm, cnxk_pktio_t *dev,
			       cnxk_pktio_stats_t *stats)
{
  return 0;
}

static_always_inline i32
cn10k_pktio_inl_dev_link_info_get (vlib_main_t *vm, cnxk_pktio_t *dev,
				   cnxk_pktio_link_info_t *link_info)
{
  return 0;
}

static_always_inline i32
cn10k_pktio_inl_dev_stats_clear (vlib_main_t *vm, cnxk_pktio_t *dev)
{
  return 0;
}

static_always_inline i32
cn10k_pktio_inl_dev_pkts_recv (vlib_main_t *vm, vlib_node_runtime_t *node,
			       u32 rxq, u16 rx_pkts,
			       cnxk_per_thread_data_t *ptd, const u64 fp_flags,
			       const u64 off_flags)
{
  return rx_pkts;
}

static_always_inline i32
cn10k_pktio_inl_dev_pkts_send (vlib_main_t *vm, vlib_node_runtime_t *node,
			       u32 txq, u16 tx_pkts,
			       cnxk_per_thread_data_t *ptd, const u64 fp_flags,
			       const u64 off_flags)
{
  return tx_pkts;
}

static_always_inline i32
cn10k_pktio_inl_dev_config (vlib_main_t *vm, cnxk_pktio_t *dev,
			    cnxk_pktio_config_t *config)
{
  return 0;
}

static_always_inline i32
cn10k_pktio_inl_dev_rxq_setup (vlib_main_t *vm, cnxk_pktio_t *dev,
			       cnxk_pktio_rxq_conf_t *conf)
{
  return 0;
}

static_always_inline i32
cn10k_pktio_inl_dev_txq_setup (vlib_main_t *vm, cnxk_pktio_t *dev,
			       cnxk_pktio_txq_conf_t *conf)
{
  return 0;
}

static_always_inline i32
cn10k_pktio_inl_dev_rxq_fp_set (vlib_main_t *vm, cnxk_pktio_t *dev, u32 rxq_id,
				cnxk_pktio_rxq_fn_conf_t *rxq_fn_conf)
{
  return 0;
}

static_always_inline i32
cn10k_pktio_inl_dev_txq_fp_set (vlib_main_t *vm, cnxk_pktio_t *dev, u32 txq_id,
				cnxk_pktio_txq_fn_conf_t *txq_fn_conf)
{
  return 0;
}

static_always_inline i32
cn10k_pktio_inl_dev_capa_get (vlib_main_t *vm, cnxk_pktio_t *dev,
			      cnxk_pktio_capa_t *capa)
{
  return 0;
}

static_always_inline i32
cn10k_pktio_inl_dev_exit (vlib_main_t *vm, cnxk_pktio_t *dev)
{
  return 0;
}

static_always_inline u32
cn10k_pktio_inl_dev_flow_dump (vlib_main_t *vm, cnxk_pktio_t *dev)
{
  return 0;
}

static_always_inline u32
cn10k_pktio_inl_dev_flow_query (vlib_main_t *vm, cnxk_pktio_t *dev,
				uword flow_index, cnxk_flow_stats_t *stats)
{
  return 0;
}

static_always_inline i32
cn10k_pktio_inl_dev_flow_update (vnet_main_t *vnm, vnet_flow_dev_op_t op,
				 cnxk_pktio_t *dev, vnet_flow_t *flow,
				 uword *private_data)
{
  return 0;
}

static_always_inline u8 *
cn10k_pktio_inl_dev_format_rx_trace (u8 *s, va_list *va)
{
  return s;
}

static_always_inline i32
cn10k_pktio_inl_dev_mac_addr_add (vlib_main_t *vm, cnxk_pktio_t *dev,
				  char *addr)
{
  return 0;
}

cnxk_pktio_ops_t cn10k_inl_dev_pktio_ops = {
  .pktio_format_rx_trace = cn10k_pktio_inl_dev_format_rx_trace,
  .pktio_promisc_disable = cn10k_pktio_inl_dev_promisc_disable,
  .pktio_promisc_enable = cn10k_pktio_inl_dev_promisc_enable,
  .pktio_link_info_get = cn10k_pktio_inl_dev_link_info_get,
  .pktio_mac_addr_set = cn10k_pktio_inl_dev_mac_addr_set,
  .pktio_mac_addr_get = cn10k_pktio_inl_dev_mac_addr_get,
  .pktio_mac_addr_add = cn10k_pktio_inl_dev_mac_addr_add,
  .pktio_mac_addr_del = cn10k_pktio_inl_dev_mac_addr_del,
  .pktio_stats_clear = cn10k_pktio_inl_dev_stats_clear,
  .pktio_flow_update = cn10k_pktio_inl_dev_flow_update,
  .pktio_flowkey_set = cn10k_pktio_inl_dev_flowkey_set,
  .pktio_rss_key_set = cn10k_pktio_inl_dev_rss_key_set,
  .pktio_rxq_fp_set = cn10k_pktio_inl_dev_rxq_fp_set,
  .pktio_txq_fp_set = cn10k_pktio_inl_dev_txq_fp_set,
  .pktio_flow_query = cn10k_pktio_inl_dev_flow_query,
  .pktio_stats_get = cn10k_pktio_inl_dev_stats_get,
  .pktio_pkts_recv = cn10k_pktio_inl_dev_pkts_recv,
  .pktio_pkts_send = cn10k_pktio_inl_dev_pkts_send,
  .pktio_flow_dump = cn10k_pktio_inl_dev_flow_dump,
  .pktio_rxq_setup = cn10k_pktio_inl_dev_rxq_setup,
  .pktio_txq_setup = cn10k_pktio_inl_dev_txq_setup,
  .pktio_capa_get = cn10k_pktio_inl_dev_capa_get,
  .pktio_mtu_set = cn10k_pktio_inl_dev_mtu_set,
  .pktio_mtu_get = cn10k_pktio_inl_dev_mtu_get,
  .pktio_config = cn10k_pktio_inl_dev_config,
  .pktio_is_inl_dev = cn10k_pktio_is_inl_dev,
  .pktio_start = cn10k_pktio_inl_dev_start,
  .pktio_stop = cn10k_pktio_inl_dev_stop,
  .pktio_exit = cn10k_pktio_inl_dev_exit,
};

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
