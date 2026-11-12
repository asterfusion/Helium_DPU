/* SPDX-License-Identifier: Apache-2.0 */

#include <ipoe/ipoe.h>

#include <vnet/dpo/dpo.h>
#include <vnet/fib/fib_source.h>
#include <vnet/fib/fib_table.h>

static dpo_type_t ipoe_qinq_dpo_type;
static fib_source_t ipoe_qinq_fib_source;
static ipoe_qinq_dpo_t *ipoe_qinq_dpo_pool;

const ipoe_qinq_dpo_t *
ipoe_qinq_dpo_get (u32 dpo_index)
{
  if (pool_is_free_index (ipoe_qinq_dpo_pool, dpo_index))
    return 0;
  return pool_elt_at_index (ipoe_qinq_dpo_pool, dpo_index);
}

static void
ipoe_qinq_dpo_lock (dpo_id_t *dpo)
{
  ipoe_qinq_dpo_t *context =
    pool_elt_at_index (ipoe_qinq_dpo_pool, dpo->dpoi_index);

  context->locks++;
  clib_warning ("ipoe qinq dpo lock index=%u locks=%u",
		(u32) dpo->dpoi_index, context->locks);
}

static void
ipoe_qinq_dpo_unlock (dpo_id_t *dpo)
{
  ipoe_qinq_dpo_t *context =
    pool_elt_at_index (ipoe_qinq_dpo_pool, dpo->dpoi_index);

  ASSERT (context->locks > 0);
  context->locks--;
  clib_warning ("ipoe qinq dpo unlock index=%u locks=%u",
		(u32) dpo->dpoi_index, context->locks);
  if (!context->locks)
    {
      clib_warning ("ipoe qinq dpo free index=%u interface=%u fib=%u "
		    "generation=%llu",
		    (u32) dpo->dpoi_index, context->qinq_sw_if_index,
		    context->fib_index, context->generation);
      pool_put (ipoe_qinq_dpo_pool, context);
    }
}

static u8 *
format_ipoe_qinq_dpo (u8 *s, va_list *args)
{
  index_t index = va_arg (*args, index_t);
  CLIB_UNUSED (u32 indent) = va_arg (*args, u32);
  const ipoe_qinq_dpo_t *context = ipoe_qinq_dpo_get (index);

  if (!context)
    return format (s, "ipoe-qinq deleted");

  return format (s, "ipoe-qinq interface:%U fib:%u generation:%llu",
		 format_vnet_sw_if_index_name, vnet_get_main (),
		 context->qinq_sw_if_index, context->fib_index,
		 context->generation);
}

static u32
ipoe_qinq_dpo_get_urpf (const dpo_id_t *dpo)
{
  const ipoe_qinq_dpo_t *context = ipoe_qinq_dpo_get (dpo->dpoi_index);

  return context ? context->qinq_sw_if_index : ~0;
}

static const dpo_vft_t ipoe_qinq_dpo_vft = {
  .dv_lock = ipoe_qinq_dpo_lock,
  .dv_unlock = ipoe_qinq_dpo_unlock,
  .dv_format = format_ipoe_qinq_dpo,
  .dv_get_urpf = ipoe_qinq_dpo_get_urpf,
};

static const char *const ipoe_qinq_ip4_nodes[] = {
  "ipoe-qinq-output",
  0,
};

static const char *const *const ipoe_qinq_nodes[DPO_PROTO_NUM] = {
  [DPO_PROTO_IP4] = ipoe_qinq_ip4_nodes,
};

void
ipoe_qinq_dpo_module_init (void)
{
  ipoe_qinq_dpo_type =
    dpo_register_new_type (&ipoe_qinq_dpo_vft, ipoe_qinq_nodes);
  ipoe_qinq_fib_source = fib_source_allocate (
    "ipoe-qinq", FIB_SOURCE_PRIORITY_HI, FIB_SOURCE_BH_API);
}

__clib_export int
ipoe_qinq_route_add_del (u32 table_id, const ip4_address_t *user_ip4,
			 u32 sw_if_index, u8 is_add)
{
  fib_prefix_t prefix = {
    .fp_proto = FIB_PROTOCOL_IP4,
    .fp_len = 32,
    .fp_addr.ip4 = *user_ip4,
  };
  u32 fib_index;
  ipoe_downstream_lookup_result_t lookup_result;
  ipoe_session_t *session;

  fib_index = fib_table_find (FIB_PROTOCOL_IP4, table_id);
  if (fib_index == ~0)
    return IPOE_ERROR_INVALID_VALUE;

  if (is_add)
    {
      dpo_id_t dpo = DPO_INVALID;
      ipoe_qinq_dpo_t *context;
      u32 context_index;

      if (!qinq_subport_get_by_sw_if_index (sw_if_index))
	return IPOE_ERROR_INVALID_INTERFACE;
      session = ipoe_session_lookup_downstream (
	sw_if_index, user_ip4, 0, 0, &lookup_result);
      if (!session || !session->qinq.enabled)
	{
	  clib_warning ("ipoe qinq route add has no QinQ session fib=%u "
			"interface=%u ip=%U",
			fib_index, sw_if_index, format_ip4_address, user_ip4);
	  return IPOE_ERROR_NO_SUCH_ENTRY;
	}

      pool_get_zero (ipoe_qinq_dpo_pool, context);
      context_index = context - ipoe_qinq_dpo_pool;
      context->qinq_sw_if_index = sw_if_index;
      context->fib_index = fib_index;
      context->generation = session->generation;
      clib_warning ("ipoe qinq dpo allocate index=%u interface=%u fib=%u "
		    "generation=%llu",
		    context_index, sw_if_index, fib_index,
		    context->generation);
      dpo_set (&dpo, ipoe_qinq_dpo_type, DPO_PROTO_IP4, context_index);
      fib_table_entry_special_dpo_add (
	fib_index, &prefix, ipoe_qinq_fib_source,
	FIB_ENTRY_FLAG_EXCLUSIVE, &dpo);
      dpo_reset (&dpo);
      clib_warning ("ipoe qinq route add fib=%u interface=%u ip=%U "
		    "generation=%llu",
		    fib_index, sw_if_index, format_ip4_address, user_ip4,
		    session->generation);
    }
  else
    {
      fib_table_entry_special_remove (fib_index, &prefix,
				      ipoe_qinq_fib_source);
      clib_warning ("ipoe qinq route remove fib=%u ip=%U", fib_index,
		    format_ip4_address, user_ip4);
    }

  return IPOE_OK;
}
