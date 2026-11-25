/* SPDX-License-Identifier: Apache-2.0 */
#include <ipoe/ipoe.h>

STATIC_ASSERT_SIZEOF (ipoe_ip6_binding_key_t, 24);

static void
ipoe_ip6_normalize (ip6_address_t *address, u8 prefix_length)
{
  u32 byte = prefix_length / 8;
  u32 bit = prefix_length % 8;

  if (byte == sizeof (address->as_u8))
    return;
  if (bit)
    address->as_u8[byte++] &= (u8) (0xff << (8 - bit));
  clib_memset (address->as_u8 + byte, 0, sizeof (address->as_u8) - byte);
}

static void
ipoe_ip6_binding_key (ipoe_ip6_binding_key_t *key, u32 sw_if_index,
		      const ip6_address_t *prefix, u8 prefix_length)
{
  clib_memset (key, 0, sizeof (*key));
  key->prefix = *prefix;
  key->sw_if_index = sw_if_index;
  key->prefix_length = prefix_length;
  ipoe_ip6_normalize (&key->prefix, prefix_length);
}

static void
ipoe_ip6_binding_kv (clib_bihash_kv_24_8_t *kv,
		     const ipoe_ip6_binding_key_t *key, u64 value)
{
  clib_memcpy_fast (kv->key, key, sizeof (*key));
  kv->value = value;
}

int
ipoe_ip6_binding_add_del (u32 sw_if_index, const ip6_address_t *prefix,
			  u8 prefix_length, u64 external_index, u8 is_add)
{
  ipoe_main_t *im = &ipoe_main;
  clib_bihash_kv_24_8_t kv, result;
  ipoe_ip6_binding_key_t key;
  ipoe_ip6_binding_t *binding;
  ipoe_session_t *session;
  uword *p;
  int found;

  if (!prefix || !external_index || !prefix_length || prefix_length > 128 ||
      sw_if_index >= vec_len (im->interfaces) ||
      !im->interfaces[sw_if_index].enabled)
    return IPOE_ERROR_INVALID_VALUE;
  p = hash_get (im->session_by_index, (uword) external_index);
  if (!p || pool_is_free_index (im->sessions, p[0]))
    return IPOE_ERROR_NO_SUCH_ENTRY;
  session = pool_elt_at_index (im->sessions, p[0]);
  if (session->sw_if_index != sw_if_index)
    return IPOE_ERROR_INVALID_INTERFACE;

  ipoe_ip6_binding_key (&key, sw_if_index, prefix, prefix_length);
  ipoe_ip6_binding_kv (&kv, &key, external_index);
  found = !clib_bihash_search_24_8 (&im->ip6_binding_hash, &kv, &result);
  if (is_add && found)
    return result.value == external_index ? IPOE_OK : IPOE_ERROR_IP_CONFLICT;
  if (!is_add && (!found || result.value != external_index))
    return found ? IPOE_ERROR_GENERATION_STALE : IPOE_ERROR_NO_SUCH_ENTRY;

  vlib_worker_thread_barrier_sync (im->vlib_main);
  if (clib_bihash_add_del_24_8 (&im->ip6_binding_hash, &kv, is_add))
    {
      vlib_worker_thread_barrier_release (im->vlib_main);
      return IPOE_ERROR_INVALID_VALUE;
    }
  if (is_add)
    {
      pool_get_zero (im->ip6_bindings, binding);
      binding->key = key;
      binding->external_index = external_index;
      session->ip6_binding_count++;
      im->ip6_prefix_length_refcount[prefix_length]++;
    }
  else
    {
      pool_foreach (binding, im->ip6_bindings)
	if (!memcmp (&binding->key, &key, sizeof (key)) &&
	    binding->external_index == external_index)
	  {
	    pool_put (im->ip6_bindings, binding);
	    break;
	  }
      session->ip6_binding_count--;
      im->ip6_prefix_length_refcount[prefix_length]--;
    }
  vlib_worker_thread_barrier_release (im->vlib_main);
  return IPOE_OK;
}

ipoe_session_t *
ipoe_ip6_binding_lookup (u32 sw_if_index, const ip6_address_t *address,
			 u8 *matched_length)
{
  ipoe_main_t *im = &ipoe_main;
  clib_bihash_kv_24_8_t kv, result;
  ipoe_ip6_binding_key_t key;
  i32 bit;
  uword *p;

  for (bit = 128; bit > 0; bit--)
    {
      if (!im->ip6_prefix_length_refcount[bit])
	continue;
      ipoe_ip6_binding_key (&key, sw_if_index, address, (u8) bit);
      ipoe_ip6_binding_kv (&kv, &key, 0);
      if (!clib_bihash_search_24_8 (&im->ip6_binding_hash, &kv, &result))
	{
	  p = hash_get (im->session_by_index, (uword) result.value);
	  if (!p || pool_is_free_index (im->sessions, p[0]))
	    return 0;
	  if (matched_length)
	    *matched_length = bit;
	  return pool_elt_at_index (im->sessions, p[0]);
	}
    }
  return 0;
}

void
ipoe_ip6_binding_flush_interface (u32 sw_if_index)
{
  ipoe_main_t *im = &ipoe_main;
  ipoe_ip6_binding_t *binding;
  ipoe_ip6_binding_t *copy = 0;

  pool_foreach (binding, im->ip6_bindings)
    if (binding->key.sw_if_index == sw_if_index)
      vec_add1 (copy, *binding);
  vec_foreach (binding, copy)
    ipoe_ip6_binding_add_del (sw_if_index, &binding->key.prefix,
			      binding->key.prefix_length,
			      binding->external_index, 0);
  vec_free (copy);
}
