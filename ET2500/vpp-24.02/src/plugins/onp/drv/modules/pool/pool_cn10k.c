/*
 * Copyright (c) 2021 Marvell.
 * SPDX-License-Identifier: Apache-2.0
 * https://spdx.org/licenses/Apache-2.0.html
 */

#include <onp/drv/modules/pool/pool_priv.h>

#define CNXK_NIX_INL_META_POOL_NAME "CNXK_NIX_INL_META_POOL"

int
cn10k_pool_inl_meta_pool_cb (uint64_t *aura_handle, uintptr_t *mpool,
			     uint32_t buf_sz, uint32_t nb_bufs, bool destroy,
			     const char *mempool_name)
{
  cnxk_drv_pool_params_t params = { 0 };
  vlib_main_t *vm = vlib_get_main ();
  const char *mp_name;
  cnxk_pool_t *cp = NULL;
  u32 index;

  mp_name = mempool_name ? mempool_name : CNXK_NIX_INL_META_POOL_NAME;

  params.elem_size = buf_sz;
  params.n_elem = nb_bufs;
  params.is_inl_meta_pool = true;

  if (cnxk_drv_pool_setup (vm, mp_name, params, &index))
    {
      cnxk_pool_err ("Failed to create inline meta pool");
      return -1;
    }

  cnxk_pool_set_meta_index (index);
  *aura_handle = cnxk_pool_get_aura_handle (index);

  cp = cnxk_pool_get_dev (index);
  *mpool = (uintptr_t) cp;

  return 0;
}

const cnxk_pool_ops_t pool_10k_ops = {
  .info_dump = cnxk_pool_info_dump,
  .range_set = cnxk_pool_range_set,
  .info_get = cnxk_pool_info_get,
  .alloc = cnxk_pool_elem_alloc,
  .free = cnxk_pool_elem_free,
  .create = cnxk_pool_create,
  .setup = cnxk_pool_setup,
};

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
