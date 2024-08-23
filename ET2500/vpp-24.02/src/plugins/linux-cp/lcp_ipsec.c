/*
 * Copyright (c) 2022 Cisco and/or its affiliates.
 * Copyright (c) 2022 Marvell Technology, Inc and/or its affiliates.
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

#include <linux-cp/lcp_xfrm.h>

#define NL_XFRM_DBG(...)  vlib_log_debug (lcp_xfrm_logger, __VA_ARGS__)
#define NL_XFRM_INFO(...) vlib_log_notice (lcp_xfrm_logger, __VA_ARGS__)
#define NL_XFRM_WARN(...) vlib_log_warn (lcp_xfrm_logger, __VA_ARGS__)
#define NL_XFRM_ERR(...)  vlib_log_err (lcp_xfrm_logger, __VA_ARGS__)

/* Keeping size in sync with libnl lib */
#define ALGO_NAME	       64
#define INB_PROTECT_POL_PRIO   9999
#define IS_ROUTE_MODE_ENABLED  !!nm->is_route_mode
/* size in bytes */
#define GCM_SALT_SIZE 4

#define cpu_to_be(x, bits)                                                    \
  if ((bits) == 16)                                                           \
    x = clib_host_to_net_u16 (x);                                             \
  else if ((bits) == 32)                                                      \
    x = clib_host_to_net_u32 (x);                                             \
  else                                                                        \
    x = clib_host_to_net_u64 (x);

/* Random seq number */
static u32 g_seq = 0;
static vlib_log_class_t lcp_xfrm_logger;
uword *lifetime_by_sa_id;
static int config_bypass = 0;
uword *tun_idx_by_sel_daddr;

typedef struct sa_life_limits
{
  u64 soft_byte_limit;
  u64 hard_byte_limit;
  u64 soft_packet_limit;
  u64 hard_packet_limit;
  u32 sa_id;

  /* Used in tunnel mode */
  int tun_sw_if_idx;
  u8 sa_in_tunnel;
} sa_life_limits_t;

typedef struct policy_db
{
  int tun_sw_if_idx;
} policy_db_t;

typedef struct sa_expire_req
{
  struct nlmsghdr nlmsg_hdr;
  struct xfrm_user_expire xfrm_expire;
} sa_expire_req_nl_t;

static inline int
lcp_xfrm_is_ipsec_intf_exist (u8 *if_name, u32 *sw_if_index)
{
  vnet_main_t *vnm = vnet_get_main ();
  uword *p;
  vnet_hw_interface_t *hi;

  p = hash_get (vnm->interface_main.hw_interface_by_name, if_name);
  if (!p)
    return 0;

  hi = vnet_get_hw_interface (vnm, p[0]);
  sw_if_index[0] = hi->sw_if_index;

  return 1;
}

u32 *
get_mcast_addr (u32 *ip6addr)
{
  u32 *maddr = malloc (sizeof (ip6_address_t));

  maddr[0] = 0xff020000;
  maddr[1] = 0x0;
  maddr[2] = 0x1;
  maddr[3] = (0xff000000) | (0x00ffffff & clib_net_to_host_u32 (ip6addr[3]));
  for (int i = 0; i < 4; i++)
    cpu_to_be (maddr[i], 32);
  return maddr;
}

static inline u32
lcp_xfrm_ipsec_sa_id_table (u32 spi, ip_address_t *addr)
{
  u32 hash = addr->version ^ spi;

  switch (addr->version)
    {
    case AF_IP4:
      hash ^= addr->ip.ip4.as_u32;
      break;
    case AF_IP6:
      hash ^= addr->ip.ip6.as_u32[0] ^ addr->ip.ip6.as_u32[1] ^
	      addr->ip.ip6.as_u32[2] ^ addr->ip.ip6.as_u32[3];
      break;
    }
  hash ^= (hash >> 16);
  NL_XFRM_DBG ("### sa_id : %x", hash);
  return hash;
}

static inline fib_protocol_t
lcp_xfrm_mk_proto (uint32_t k)
{
  if (AF_INET6 == k)
    return (FIB_PROTOCOL_IP6);
  return (FIB_PROTOCOL_IP4);
}

static inline void
lcp_xfrm_mk_ipaddr (const struct nl_addr *xa, ip_address_t *ia)
{
  fib_protocol_t fproto;

  ip_address_reset (ia);
  fproto = lcp_xfrm_mk_proto (nl_addr_get_family (xa));

  ip_address_set (ia, nl_addr_get_binary_addr (xa),
		  FIB_PROTOCOL_IP4 == fproto ? AF_IP4 : AF_IP6);
}

void
get_auth_algo (char *alg, int len, ipsec_integ_alg_t *val)
{
  if (!strcmp (alg, "hmac(md5)"))
    *val = IPSEC_INTEG_ALG_MD5_96;
  else if (!strcmp (alg, "hmac(sha1)"))
    *val = IPSEC_INTEG_ALG_SHA1_96;
  else if (!strcmp (alg, "hmac(sha256)"))
    *val = IPSEC_INTEG_ALG_SHA_256_128;
  else if (!strcmp (alg, "hmac(sha384)"))
    *val = IPSEC_INTEG_ALG_SHA_384_192;
  else if (!strcmp (alg, "hmac(sha512)"))
    *val = IPSEC_INTEG_ALG_SHA_512_256;
  else
    *val = IPSEC_INTEG_N_ALG;
}

void
get_crypto_algo (char *alg, int len, ipsec_crypto_alg_t *val)
{
  if (!strcmp (alg, "cbc(aes)"))
    {
      if (len == 128)
	*val = IPSEC_CRYPTO_ALG_AES_CBC_128;
      else if (len == 192)
	*val = IPSEC_CRYPTO_ALG_AES_CBC_192;
      else if (len == 256)
	*val = IPSEC_CRYPTO_ALG_AES_CBC_256;
      else
	*val = IPSEC_CRYPTO_N_ALG;
    }

  else if (!strcmp (alg, "rfc4106(gcm(aes))"))
    {
      /*
       * Len includes 4Bsalt as well. So remove it to get actual cipher keylen
       */
      len -= GCM_SALT_SIZE * 8;
      if (len == 128)
	*val = IPSEC_CRYPTO_ALG_AES_GCM_128;
      else if (len == 192)
	*val = IPSEC_CRYPTO_ALG_AES_GCM_192;
      else if (len == 256)
	*val = IPSEC_CRYPTO_ALG_AES_GCM_256;
      else
	*val = IPSEC_CRYPTO_N_ALG;
    }

  else if (!strcmp (alg, "ctr(aes)"))
    {
      if (len == 128)
	*val = IPSEC_CRYPTO_ALG_AES_CTR_128;
      else if (len == 192)
	*val = IPSEC_CRYPTO_ALG_AES_CTR_192;
      else if (len == 256)
	*val = IPSEC_CRYPTO_ALG_AES_CTR_256;
      else
	*val = IPSEC_CRYPTO_N_ALG;
    }

  else if (!strcmp (alg, "cbc(des)"))
    *val = IPSEC_CRYPTO_ALG_DES_CBC;

  else if (!strcmp (alg, "cbc(des3-cede)"))
    *val = IPSEC_CRYPTO_ALG_3DES_CBC;
  else
    *val = IPSEC_CRYPTO_N_ALG;
}

static inline void
update_port_details (ipsec_policy_t *p, u16 sport, u16 dport, u16 sportmask,
		     u16 dportmask)
{
  if (!sportmask)
    {
      p->lport.start = 0;
      p->lport.stop = 65535;
    }
  else if (sportmask == 0xffff)
    {
      /* Linux XFRM doesn't support port ranges */
      p->lport.start = sport;
      p->lport.stop = sport;
    }

  if (!dportmask)
    {
      p->rport.start = 0;
      p->rport.stop = 65535;
    }
  else if (dportmask == 0xffff)
    {
      p->rport.start = dport;
      p->rport.stop = dport;
    }
}

static inline void
update_bypass_policy_addrs (ipsec_policy_t *policy)
{
  ip46_address_t start;
  ip46_address_t stop;

  clib_memset (&start, (u8) 0, sizeof (ip46_address_t));
  clib_memset (&stop, (u8) ~0, sizeof (ip46_address_t));

  clib_memcpy_fast (&policy->laddr.start, &start, sizeof (ip46_address_t));
  clib_memcpy_fast (&policy->laddr.stop, &stop, sizeof (ip46_address_t));
  clib_memcpy_fast (&policy->raddr.start, &start, sizeof (ip46_address_t));
  clib_memcpy_fast (&policy->raddr.stop, &stop, sizeof (ip46_address_t));
}

static inline void
lcp_xfrm_config_bypass_policies (u32 spd_id, u8 is_add, u8 is_ip6)
{
  int rv;
  u32 p_idx;
  vlib_main_t *vm = vlib_get_main ();
  ipsec_policy_t policy, policy1;

  /* Bypass policies configured only once across all connections */
  if (config_bypass == 1 && is_add)
    return;

  /*
   * Adding bypass policy one in inb and one in outb direction
   * allowing all ranges 0.0.0.0 - 255.255.255.255
   */
  update_bypass_policy_addrs (&policy);
  update_port_details (&policy, 0, 65535, 0, 0);
  policy.policy = IPSEC_POLICY_ACTION_BYPASS;
  policy.protocol = 0;
  policy.sa_id = 0;
  policy.is_ipv6 = is_ip6;
  policy.id = spd_id;
  /*
   * Setting the least priority for the bypass, which means in outb
   * if packet doesn't match any PROTECT policies, then it will always
   * hit the BYPASS.
   */
  policy.priority = 0;

  clib_memcpy_fast (&policy1, &policy, sizeof (policy1));
  ipsec_policy_mk_type (1, policy.is_ipv6, policy.policy, &policy.type);

  rv = ipsec_add_del_policy (vm, &policy, is_add, &p_idx);
  if (!rv)
    NL_XFRM_DBG ("bypass policy-index:%d", p_idx);
  else
    NL_XFRM_ERR ("bypass policy error:%d", rv);

  ipsec_policy_mk_type (0, policy1.is_ipv6, policy1.policy, &policy1.type);
  rv = ipsec_add_del_policy (vm, &policy1, is_add, &p_idx);
  if (!rv)
    NL_XFRM_DBG ("bypass policy-index:%d", p_idx);
  else
    NL_XFRM_ERR ("bypass policy error:%d", rv);

  config_bypass = !!is_add;

  NL_XFRM_INFO ("Bypass policies %s successfull",
		(is_add == 1) ? "addition" : "deletion");
}

static inline void
lcp_xfrm_inb_policy_cfg (ip_address_t *t_saddr, ip_address_t *t_daddr,
			 u32 sa_id, u32 spd_id, u8 is_add)
{
  int rv;
  u32 p_idx;
  vlib_main_t *vm = vlib_get_main ();
  ipsec_policy_t policy;

  if (t_saddr->version == AF_IP4)
    {
      clib_memcpy_fast (&policy.laddr.start.ip4.as_u32,
			&t_saddr->ip.ip4.as_u32, sizeof (ip4_address_t));
      clib_memcpy_fast (&policy.laddr.stop.ip4.as_u32, &t_saddr->ip.ip4.as_u32,
			sizeof (ip4_address_t));
      clib_memcpy_fast (&policy.raddr.start.ip4.as_u32,
			&t_daddr->ip.ip4.as_u32, sizeof (ip4_address_t));
      clib_memcpy_fast (&policy.raddr.stop.ip4.as_u32, &t_daddr->ip.ip4.as_u32,
			sizeof (ip4_address_t));
      policy.is_ipv6 = 0;
    }
  else
    {
      clib_memcpy_fast (&policy.laddr.start.ip6.as_u32,
			&t_saddr->ip.ip6.as_u32, sizeof (ip6_address_t));
      clib_memcpy_fast (&policy.laddr.stop.ip6.as_u32, &t_saddr->ip.ip6.as_u32,
			sizeof (ip6_address_t));
      clib_memcpy_fast (&policy.raddr.start.ip6.as_u32,
			&t_daddr->ip.ip6.as_u32, sizeof (ip6_address_t));
      clib_memcpy_fast (&policy.raddr.stop.ip6.as_u32, &t_daddr->ip.ip6.as_u32,
			sizeof (ip6_address_t));
      policy.is_ipv6 = 1;
    }

  policy.policy = IPSEC_POLICY_ACTION_PROTECT;
  /*SA doesn't have details of inner protocol. So set 0 (means accept any)*/
  policy.protocol = 0;
  policy.sa_id = sa_id;
  policy.id = spd_id;
  policy.priority = INB_PROTECT_POL_PRIO;
  update_port_details (&policy, 0, 65535, 0, 0);

  ipsec_policy_mk_type (0, policy.is_ipv6, policy.policy, &policy.type);
  rv = ipsec_add_del_policy (vm, &policy, is_add, &p_idx);
  if (!rv)
    NL_XFRM_INFO ("ipsec inb policy %s success %U -> %U sa_id: %x spd_id: %x",
		  ((is_add) ? "add" : "del"), format_ip_address, t_saddr,
		  format_ip_address, t_daddr, sa_id, spd_id);
  else
    NL_XFRM_ERR (
      "ipsec inb policy %s fail(err: %d) %U -> %U sa_id: %x spd_id: %x",
      ((is_add) ? "add" : "del"), rv, format_ip_address, t_saddr,
      format_ip_address, t_daddr, sa_id, spd_id);
}

static inline int
lcp_xfrm_get_matching_iface (ip46_address_t *addr, u8 is_ipv6)
{
  vnet_main_t *vnm = vnet_get_main ();
  vnet_sw_interface_t *sif;
  u8 iface_found;

  pool_foreach (sif, vnm->interface_main.sw_interfaces)
    {
      iface_found = ip_interface_has_address (sif->sw_if_index, addr, is_ipv6);
      if (iface_found)
	{
	  NL_XFRM_DBG ("Found matching IP on interface index :%u",
		       sif->sw_if_index);
	  return sif->sw_if_index;
	}
    }
  return ~0;
}

static inline u32
lcp_xfrm_create_spd (ip_address_t *saddr, ip_address_t *daddr, u32 spi,
		     int *sw_if_index, u8 is_outb)
{
  vlib_main_t *vm = vlib_get_main ();
  ipsec_main_t *im = &ipsec_main;
  int rv, is_ipv6;
  ipsec_spd_t *spd0;
  u32 spd_id = 0;
  uword *ptr;
  ip46_address_t *ip46 = NULL;

  ip46 = (is_outb) ? (&saddr->ip) : (&daddr->ip);
  is_ipv6 = (saddr->version == AF_IP4) ? 0 : 1;

  *sw_if_index = lcp_xfrm_get_matching_iface (ip46, !is_ipv6);
  if (*sw_if_index == ~0)
    return ~0;

  ptr = hash_get (im->spd_index_by_sw_if_index, *sw_if_index);
  if (ptr)
    {
      spd0 = pool_elt_at_index (im->spds, ptr[0]);
      NL_XFRM_DBG ("Interface already bound to spd_id: %x", spd0->id);
      spd_id = spd0->id;
    }
  else
    {
      spd_id = lcp_xfrm_ipsec_sa_id_table (spi, daddr);
      rv = ipsec_add_del_spd (vm, spd_id, 1);
      if (rv)
	{
	  NL_XFRM_ERR ("spd creation failed");
	  return ~0;
	}
      rv = ipsec_set_interface_spd (vm, *sw_if_index, spd_id, 1);
      switch (rv)
	{
	case VNET_API_ERROR_SYSCALL_ERROR_1:
	  NL_XFRM_ERR ("no such spd-id");
	  return ~0;
	case VNET_API_ERROR_SYSCALL_ERROR_2:
	  NL_XFRM_DBG ("spd already assigned");
	  break;
	}
      NL_XFRM_INFO ("Adding bypass for src %U dst %U", format_ip_address,
		    saddr, format_ip_address, daddr);
      lcp_xfrm_config_bypass_policies (spd_id, 1, is_ipv6);
    }
  return spd_id;
}

static inline void
lcp_xfrm_delete_spd (u32 spd_id, ip_address_t *saddr, ip_address_t *daddr,
		     u8 is_ip6, u8 is_outb)
{
  vlib_main_t *vm = vlib_get_main ();
  ipsec_main_t *im = &ipsec_main;
  u32 spd_index, *policies;
  ipsec_spd_t *spd;
  ipsec_policy_t *p0 = NULL;
  uword *p;

  p = hash_get (im->spd_index_by_spd_id, spd_id);
  if (!p)
    return;
  spd_index = p[0];
  spd = pool_elt_at_index (im->spds, spd_index);
#define _(t, v)                                                               \
  vec_foreach (policies, spd->policies[IPSEC_SPD_POLICY_##t])                 \
    {                                                                         \
      p0 = pool_elt_at_index (im->policies, *policies);                       \
      if (p0)                                                                 \
	{                                                                     \
	  if (IPSEC_POLICY_ACTION_BYPASS != p0->policy)                       \
	    return;                                                           \
	}                                                                     \
    }
  foreach_ipsec_spd_policy_type
#undef _
    if (!p0) return;
  /*
   * There will not be a notification indicating the termination of a
   * tunnel. So once we detect that no more PROTECT policies are left
   * in our database, we delete the bypass policies (which was addded
   * internally by us) and delete the SPD as well.
   */
  lcp_xfrm_config_bypass_policies (spd->id, 0, is_ip6);
  ipsec_add_del_spd (vm, spd->id, 0);
}

static inline u8
lcp_xfrm_get_sa_direction (ip46_address_t *saddr, ip46_address_t *daddr,
			   int *sw_if_index, u8 is_ipv6)
{
  u8 is_outb = 0;

  *sw_if_index = lcp_xfrm_get_matching_iface (saddr, !is_ipv6);
  if (~0 == *sw_if_index)
    {
      *sw_if_index = lcp_xfrm_get_matching_iface (daddr, !is_ipv6);
      if (~0 == *sw_if_index)
	clib_error_return (0, "SA notification doesn't belong to VPP iface");
    }
  else
    is_outb = 1;

  return is_outb;
}

static inline int
find_tunnel_db (ip_address_t *saddr, ip_address_t *daddr, u8 dir, u8 is_ipv6)
{
  ipip_tunnel_key_t key;
  ipip_tunnel_t *tun;

  key.mode = IPIP_MODE_P2P;
  key.fib_index = fib_table_find (fib_ip_proto (is_ipv6), 0);

  if (is_ipv6)
    key.transport = IPIP_TRANSPORT_IP6;
  else
    key.transport = IPIP_TRANSPORT_IP4;

  if (dir)
    {
      clib_memcpy_fast (&key.src, &saddr->ip, sizeof (ip46_address_t));
      clib_memcpy_fast (&key.dst, &daddr->ip, sizeof (ip46_address_t));
    }
  else
    {
      clib_memcpy_fast (&key.src, &daddr->ip, sizeof (ip46_address_t));
      clib_memcpy_fast (&key.dst, &saddr->ip, sizeof (ip46_address_t));
    }

  tun = ipip_tunnel_db_find (&key);
  if (!tun)
    {
      NL_XFRM_ERR ("Tunnel iface not found");
      return ~0;
    }

  NL_XFRM_DBG ("Tunnel iface found in tunnel DB iterface index: %x",
	       tun->sw_if_index);
  return tun->sw_if_index;
}

static inline void
lcp_xfrm_update_tunnel (ip_address_t *saddr, ip_address_t *daddr, u8 dir,
			u32 sa_id, u8 is_ipv6, struct xfrmnl_sa *sa)
{
  u32 sa_out = 0, *sa_ins = NULL;
  ipsec_sa_t *sai = NULL, *sao = NULL;
  index_t itpi;
  u32 sw_if_index = ~0;
  int rv;
  u8 *s = NULL;
  u8 instance = xfrmnl_sa_get_reqid (sa);

  if (dir)
    return;

  if (nm->interface_type == NL_INTERFACE_TYPE_IPIP)
    sw_if_index = find_tunnel_db (saddr, daddr, dir, is_ipv6);
  else
    {
      s = format (s, "ipsec%d", instance);
      lcp_xfrm_is_ipsec_intf_exist (s, &sw_if_index);
      vec_free (s);
    }
  if (sw_if_index == ~0)
    return;

  pool_foreach_index (itpi, ipsec_tun_protect_pool)
    {
      ipsec_tun_protect_t *itp =
	pool_elt_at_index (ipsec_tun_protect_pool, itpi);
      if (!itp || (itp->itp_sw_if_index != sw_if_index))
	continue;
      sao = ipsec_sa_get (itp->itp_out_sa);
      sa_out = sao->id;
      FOR_EACH_IPSEC_PROTECT_INPUT_SA (
	itp, sai, if (sa_id != sai->id) vec_add1 (sa_ins, sai->id);)
    }

  rv = ipsec_tun_protect_update (sw_if_index, NULL, sa_out, sa_ins);
  if (rv)
    {
      NL_XFRM_ERR ("SA del: Tunnel protect update failure (err: %d)", rv);
      return;
    }
  NL_XFRM_INFO ("Tunnel protect update success (index: %x)", sw_if_index);
}

void
nl_xfrm_sa_del (struct xfrmnl_sa *sa)
{
  int is_hard = xfrmnl_sa_is_hardexpiry_reached (sa);
  u8 fam = xfrmnl_sa_get_family (sa);
  u32 spi = xfrmnl_sa_get_spi (sa);
  struct nl_addr *dst = xfrmnl_sa_get_daddr (sa);
  struct nl_addr *src = xfrmnl_sa_get_saddr (sa);
  u8 is_ip6 = (fam == AF_INET) ? 0 : 1;
  ip_address_t daddr, saddr;
  u8 is_outb = 1;
  u32 id = 0;
  int sw_if_index, rv = 0;
  u32 spd_id = ~0;

  /*
   * Dont need to handle EXPIRE due to soft limit as the rekeying will take
   * care of installing new and deleting old one. But for hard limit, we
   * need to delete SA as part of EXPIRE notification
   */
  if ((nl_object_get_msgtype ((struct nl_object *) sa) == XFRM_MSG_EXPIRE) &&
      (!is_hard))
    return;

  lcp_xfrm_mk_ipaddr (dst, &daddr);
  lcp_xfrm_mk_ipaddr (src, &saddr);

  id = lcp_xfrm_ipsec_sa_id_table (spi, &daddr);

  is_outb =
    lcp_xfrm_get_sa_direction (&saddr.ip, &daddr.ip, &sw_if_index, is_ip6);

  if (IS_ROUTE_MODE_ENABLED)
    lcp_xfrm_update_tunnel (&saddr, &daddr, is_outb, id, is_ip6, sa);
  else if ((sw_if_index != ~0) && (is_outb == 0))
    {
      is_outb = 0;
      spd_id = lcp_xfrm_create_spd (&saddr, &daddr, spi, &rv, is_outb);
      lcp_xfrm_inb_policy_cfg (&saddr, &daddr, id, spd_id, 0);
    }

  rv = ipsec_sa_unlock_id (id);
  if (rv)
    {
      NL_XFRM_ERR ("ipsec sa %x del failure(err: %d) %U -> %U", id, rv,
		   format_ip_address, &saddr, format_ip_address, &daddr);
    }
  else
    {
      hash_unset (lifetime_by_sa_id, id);
      NL_XFRM_INFO ("ipsec sa %x del success %U -> %U", id, format_ip_address,
		    &saddr, format_ip_address, &daddr);
    }

  if (!IS_ROUTE_MODE_ENABLED)
    lcp_xfrm_delete_spd (spd_id, &saddr, &daddr, is_ip6, is_outb);
  return;
}

ipsec_sa_t *
get_sa_by_sa_id (u32 sa_id)
{
  ipsec_sa_t *sa;
  u32 sai;

  pool_foreach_index (sai, ipsec_sa_pool)
    {
      sa = ipsec_sa_get (sai);
      if (!sa)
	return NULL;
      if (sa_id == sa->id)
	return sa;
    }
  return NULL;
}

ipsec_sa_t *
get_reverse_sa_by_tun_ip (ip_address_t *saddr, ip_address_t *daddr, u8 is_ipv6,
			  u8 dir)
{
  sa_life_limits_t *life = NULL;
  ipsec_sa_t *sa;
  u8 found = 0;
  uword *p = NULL;
  u32 sai;

  pool_foreach_index (sai, ipsec_sa_pool)
    {
      sa = ipsec_sa_get (sai);
      if (!sa)
	return NULL;

      p = hash_get (lifetime_by_sa_id, sa->id);
      if (!p)
	continue;

      life = (sa_life_limits_t *) p[0];

      if (!is_ipv6 &&
	  !ip4_address_compare (&daddr->ip.ip4, &sa->tunnel.t_src.ip.ip4) &&
	  !ip4_address_compare (&saddr->ip.ip4, &sa->tunnel.t_dst.ip.ip4) &&
	  !life->sa_in_tunnel)
	found = 1;
      else if (!ip6_address_compare (&daddr->ip.ip6,
				     &sa->tunnel.t_src.ip.ip6) &&
	       !ip6_address_compare (&saddr->ip.ip6,
				     &sa->tunnel.t_dst.ip.ip6) &&
	       !life->sa_in_tunnel)
	found = 1;

      if (found)
	{
	  if (dir)
	    life->sa_in_tunnel = !dir;
	  else
	    /* Its enabled only for inb sa */
	    life->sa_in_tunnel = 1;
	  return sa;
	}
    }
  return NULL;
}

static inline int
lcp_xfrm_create_ipsec_tunnel (struct xfrmnl_sa *sa, int *sw_if_index,
			      u32 phy_sw_if_index)
{
  clib_error_t *ret;
  int rv = 0;
  u8 *s = NULL;
  int instance = xfrmnl_sa_get_reqid (sa);

  s = format (s, "ipsec%d", instance);
  rv = lcp_xfrm_is_ipsec_intf_exist (s, (u32 *) sw_if_index);
  vec_free (s);

  if (rv)
    return 0;

  rv = ipsec_itf_create (instance, TUNNEL_MODE_P2P, (u32 *) sw_if_index);
  if (rv == VNET_API_ERROR_INVALID_REGISTRATION)
    {
      NL_XFRM_ERR ("Tunnel instance %x exists sw_if_idx: %x", instance,
		   sw_if_index[0]);
      return 0;
    }

  NL_XFRM_DBG ("Tunnel instance %x created succesfully.. index: %x", instance,
	       *sw_if_index);

  ret = vnet_sw_interface_set_flags (vnet_get_main (), *sw_if_index,
				     VNET_SW_INTERFACE_FLAG_ADMIN_UP);
  if (ret)
    {
      NL_XFRM_ERR ("Error setting flags on tunnel");
      return -1;
    }

  vnet_sw_interface_update_unnumbered (*sw_if_index, phy_sw_if_index, 1);
  return 0;
}

static inline int
lcp_xfrm_create_ipip_tunnel (struct xfrmnl_sa *sa, int *sw_if_index,
			     u8 is_ipv6, u8 dir, ip_address_t *saddr,
			     ip_address_t *daddr, u32 phy_sw_if_index)
{
  tunnel_encap_decap_flags_t tflags = TUNNEL_ENCAP_DECAP_FLAG_NONE;
  u8 fib_index = 0, instance = 0;
  clib_error_t *ret;
  int rv = 0;
  int reqid = xfrmnl_sa_get_reqid (sa);

  /*
   * Reqid will be unique and constant for a given connection.
   * Hence using the same as tunnel instance
   */
  instance = reqid;

  fib_index = fib_table_find (fib_ip_proto (is_ipv6), 0);

  /* If inb sa, then swap the IPs */
  if (!dir)
    rv = ipip_add_tunnel (is_ipv6 ? IPIP_TRANSPORT_IP6 : IPIP_TRANSPORT_IP4,
			  instance, &daddr->ip, &saddr->ip, fib_index, tflags,
			  IP_DSCP_CS0, TUNNEL_MODE_P2P, (u32 *) sw_if_index);

  else
    rv = ipip_add_tunnel (is_ipv6 ? IPIP_TRANSPORT_IP6 : IPIP_TRANSPORT_IP4,
			  instance, &saddr->ip, &daddr->ip, fib_index, tflags,
			  IP_DSCP_CS0, TUNNEL_MODE_P2P, (u32 *) sw_if_index);

  if (rv == VNET_API_ERROR_IF_ALREADY_EXISTS)
    {
      NL_XFRM_DBG ("Tunnel instance %x exists sw_if_idx: %x", instance,
		   sw_if_index[0]);
      return 0;
    }
  else if (rv == VNET_API_ERROR_INSTANCE_IN_USE)
    {
      NL_XFRM_ERR ("Tunnel instance %x already in use", instance);
      return -1;
    }
  else if (rv < 0)
    {
      NL_XFRM_ERR ("Tunnel addition failed(err: %d) for %U->%U", rv,
		   format_ip_address, saddr, format_ip_address, daddr);
      return -1;
    }

  NL_XFRM_INFO ("Tunnel instance %x created succesfully.. index: %x", instance,
		*sw_if_index);
  ret = vnet_sw_interface_set_flags (vnet_get_main (), *sw_if_index,
				     VNET_SW_INTERFACE_FLAG_ADMIN_UP);
  if (ret)
    {
      NL_XFRM_ERR ("Error setting flags on tunnel");
      return -1;
    }

  vnet_sw_interface_update_unnumbered (*sw_if_index, phy_sw_if_index, 1);
  return 0;
}

static inline void
lcp_xfrm_protect_tunnel (int sw_if_index, u8 is_ipv6, u32 sa_id, u8 dir,
			 ip_address_t *saddr, ip_address_t *daddr)
{
  u32 sa_out = 0, sa_in = 0, *sa_ins = NULL;
  ipsec_sa_t *sa;

  if (dir == 0)
    {
      sa_in = sa_id;
      sa = get_reverse_sa_by_tun_ip (saddr, daddr, is_ipv6, dir);
      /* Outb sa is not yet configured */
      if (!sa)
	{
	  return;
	}
      sa_out = sa->id;
    }
  else
    {
      sa_out = sa_id;
      sa = get_reverse_sa_by_tun_ip (saddr, daddr, is_ipv6, dir);
      /* Inb sa is not yet configured */
      if (!sa)
	{
	  return;
	}
      sa_in = sa->id;
    }

  index_t itpi;
  ipsec_sa_t *sai = NULL;
  pool_foreach_index (itpi, ipsec_tun_protect_pool)
    {
      ipsec_tun_protect_t *itp =
	pool_elt_at_index (ipsec_tun_protect_pool, itpi);
      if (!itp || (itp->itp_sw_if_index != sw_if_index))
	continue;
      FOR_EACH_IPSEC_PROTECT_INPUT_SA (
	itp, sai, if (sai && (sa_in != sai->id)) {
	  if (vec_len (sa_ins) < ITP_MAX_N_SA_IN)
	    vec_add1 (sa_ins, sai->id);
	})
    }

  /* Adding the curent inb sa to tunnel */
  vec_add1 (sa_ins, sa_in);

  int rv = ipsec_tun_protect_update (sw_if_index, NULL, sa_out, sa_ins);
  if (rv)
    NL_XFRM_ERR ("Tunnel protect update failure (err: %d)", rv);
  else
    NL_XFRM_INFO ("Tunnel protect update success for index : %d)",
		  sw_if_index);
}

static inline void
lcp_xfrm_configure_route_mode (struct xfrmnl_sa *sa, u8 is_ipv6,
			       ip_address_t *saddr, ip_address_t *daddr,
			       u32 sa_id, u8 dir, u32 phy_sw_if_idx)
{
  int ret, sw_if_index = -1;
  uword *p = NULL;

  if (nm->interface_type == NL_INTERFACE_TYPE_IPIP)
    ret = lcp_xfrm_create_ipip_tunnel (sa, &sw_if_index, is_ipv6, dir, saddr,
				       daddr, phy_sw_if_idx);
  else
    ret = lcp_xfrm_create_ipsec_tunnel (sa, &sw_if_index, phy_sw_if_idx);

  if (ret < 0)
    return;

  p = hash_get (lifetime_by_sa_id, sa_id);
  if (!p)
    return;
  ((sa_life_limits_t *) p[0])->tun_sw_if_idx = sw_if_index;

  lcp_xfrm_protect_tunnel (sw_if_index, is_ipv6, sa_id, dir, saddr, daddr);
}

static inline void
nl_xfrm_sa_add (struct xfrmnl_sa *sa)
{
  struct xfrmnl_ltime_cfg *lifetimes = xfrmnl_sa_get_lifetime_cfg (sa);
  ipsec_crypto_alg_t crypto_alg = IPSEC_CRYPTO_ALG_NONE;
  ipsec_integ_alg_t integ_alg = IPSEC_INTEG_ALG_NONE;
  ipsec_sa_flags_t flags = IPSEC_SA_FLAG_NONE;
  char key[IPSEC_KEY_MAX_LEN], auth_key[IPSEC_KEY_MAX_LEN];
  char alg_name[ALGO_NAME], auth_alg_name[ALGO_NAME];
  struct nl_addr *dst = xfrmnl_sa_get_daddr (sa);
  struct nl_addr *src = xfrmnl_sa_get_saddr (sa);
  unsigned int udp_src, udp_dst, encap_type;
  sa_life_limits_t *life = NULL, lifetime;
  unsigned int key_len, auth_key_len;
  ipsec_key_t ck = { 0 }, ik = { 0 };
  u32 spi = xfrmnl_sa_get_spi (sa);
  struct nl_addr *encap_oa = NULL;
  u8 ip_family, mode, is_ipv6, dir;
  u32 salt = 0, icv = 0, sai = 0, id = 0;
  ipsec_protocol_t proto = 0;
  ip_address_t saddr, daddr;
  int if_idx, sw_if_index;
  tunnel_t tun = {};
  u32 spd_id;
  int rv;

  lcp_xfrm_mk_ipaddr (dst, &daddr);
  lcp_xfrm_mk_ipaddr (src, &saddr);

  id = lcp_xfrm_ipsec_sa_id_table (spi, &daddr);

  /*
   * Ideal case, this scenaio will never be hit. But when reading SA
   * notification from sk_xfrm socket fails and we initate a sync,then there is
   * a possibility that we get notification for the one already present in VPP.
   * Hence the check
   */
  if (get_sa_by_sa_id (id))
    goto error;

  if (xfrmnl_sa_get_flags (sa) & XFRM_STATE_ESN)
    {
      flags |= IPSEC_SA_FLAG_USE_ESN;
    }
  /*
   * Kernel SA XFRM doesnt have a flag for AR config. So a non-zero
   * replay window size indicates AR is enabled.Also replay window
   * size is fixed to 64 in VPP (IPSEC_SA_ANTI_REPLAY_WINDOW_SIZE).
   * So its not configurable
   */

  if (xfrmnl_sa_get_replay_window (sa))
    {
      flags |= IPSEC_SA_FLAG_USE_ANTI_REPLAY;
    }

  xfrmnl_sa_get_encap_tmpl (sa, &encap_type, &udp_src, &udp_dst, &encap_oa);
  if (encap_type == UDP_ENCAP_ESPINUDP)
    {
      flags |= IPSEC_SA_FLAG_UDP_ENCAP;
    }
  else
    udp_src = udp_dst = IPSEC_UDP_PORT_NONE;

  lifetime.soft_byte_limit = xfrmnl_ltime_cfg_get_soft_bytelimit (lifetimes);
  lifetime.hard_byte_limit = xfrmnl_ltime_cfg_get_hard_bytelimit (lifetimes);
  lifetime.soft_packet_limit =
    xfrmnl_ltime_cfg_get_soft_packetlimit (lifetimes);
  lifetime.hard_packet_limit =
    xfrmnl_ltime_cfg_get_hard_packetlimit (lifetimes);
  lifetime.sa_id = id;
  lifetime.sa_in_tunnel = 0;
  lifetime.tun_sw_if_idx = ~0;

  proto =
    (50 == xfrmnl_sa_get_proto (sa)) ? IPSEC_PROTOCOL_ESP : IPSEC_PROTOCOL_AH;
  ip_family = xfrmnl_sa_get_family (sa);

  if (-1 != xfrmnl_sa_get_aead_params (sa, alg_name, &key_len, &icv, key))
    flags |= IPSEC_SA_FLAG_IS_AEAD;
  else
    {
      if (-1 == xfrmnl_sa_get_crypto_params (sa, alg_name, &key_len, key))
	{
	  NL_XFRM_ERR ("crypto param extraction failed");
	  goto error;
	}
      if (-1 == xfrmnl_sa_get_auth_params (sa, auth_alg_name, &auth_key_len,
					   NULL, auth_key))
	{
	  NL_XFRM_ERR ("auth param extraction failed");
	  goto error;
	}

      get_auth_algo (auth_alg_name, auth_key_len, &integ_alg);
      if (integ_alg == IPSEC_INTEG_N_ALG)
	{
	  NL_XFRM_ERR ("Invalid/Unsupported integ algo: %s keylen: %u",
		       auth_alg_name, auth_key_len);
	  goto error;
	}
      ik.len = auth_key_len / 8;
      clib_memcpy_fast (ik.data, (u8 *) auth_key, (auth_key_len / 8));
    }

  get_crypto_algo (alg_name, key_len, &crypto_alg);
  if (crypto_alg == IPSEC_CRYPTO_N_ALG)
    {
      NL_XFRM_ERR ("Invalid/Unsupported crypto algo: %s keylen: %u", alg_name,
		   key_len);
      goto error;
    }

  /*
   * Key_len/key here includes salt size/value. As per rfc5282
   * GCM salt size will be 4B which will be after cipher key
   */
  if (IPSEC_CRYPTO_ALG_IS_GCM (crypto_alg))
    {
      key_len -= GCM_SALT_SIZE * 8;
      clib_memcpy_fast (&salt, ((u8 *) key) + (key_len / 8), GCM_SALT_SIZE);
    }
  /*
   * Else for CCM if supported, salt size would be 3B and needs
   * to be handled here accordingly
   */
  ck.len = key_len / 8;
  clib_memcpy_fast (ck.data, (u8 *) key, (key_len / 8));

  is_ipv6 = (ip_family == AF_INET) ? 0 : 1;

  dir =
    lcp_xfrm_get_sa_direction (&saddr.ip, &daddr.ip, &sw_if_index, is_ipv6);

  if (!dir)
    flags |= IPSEC_SA_FLAG_IS_INBOUND;

  if (nm->interface_type == NL_INTERFACE_TYPE_IPIP)
    {
      /*
       * Other tunnel flags of VPP defined under
       * foreach_tunnel_encap_decap_flag are not supported by Strongswan/XFRM
       * NLs.
       */
      if (!(xfrmnl_sa_get_flags (sa) & XFRM_SA_XFLAG_DONT_ENCAP_DSCP))
	{
	  tun.t_encap_decap_flags |= TUNNEL_ENCAP_DECAP_FLAG_ENCAP_COPY_DSCP;
	}
      if (xfrmnl_sa_get_flags (sa) & XFRM_STATE_NOPMTUDISC)
	{
	  tun.t_encap_decap_flags |= TUNNEL_ENCAP_DECAP_FLAG_ENCAP_COPY_DF;
	}
      if (xfrmnl_sa_get_flags (sa) & XFRM_STATE_NOECN)
	{
	  if (!dir)
	    tun.t_encap_decap_flags |= TUNNEL_ENCAP_DECAP_FLAG_DECAP_COPY_ECN;
	  else
	    tun.t_encap_decap_flags |= TUNNEL_ENCAP_DECAP_FLAG_ENCAP_COPY_ECN;
	}
    }
  else
    {
      mode = (XFRM_MODE_TRANSPORT == xfrmnl_sa_get_mode (sa)) ? 0 : 1;
      if (mode)
	{
	  flags |= IPSEC_SA_FLAG_IS_TUNNEL;
	  if (AF_INET6 == ip_family)
	    flags |= IPSEC_SA_FLAG_IS_TUNNEL_V6;
	}
      flags |= IPSEC_SA_FLAG_IS_PROTECT;
    }
  if (ip_family == AF_INET)
    {
      is_ipv6 = 0;
      tun.t_src.version = tun.t_dst.version = AF_IP4;
      clib_memcpy_fast (&tun.t_src.ip.ip4.as_u32, &saddr.ip.ip4.as_u32,
			sizeof (ip4_address_t));
      clib_memcpy_fast (&tun.t_dst.ip.ip4.as_u32, &daddr.ip.ip4.as_u32,
			sizeof (ip4_address_t));
    }
  else
    {
      is_ipv6 = 1;
      tun.t_src.version = tun.t_dst.version = AF_IP6;
      clib_memcpy_fast (tun.t_src.ip.ip6.as_u32, &saddr.ip.ip6.as_u32,
			sizeof (ip6_address_t));
      clib_memcpy_fast (tun.t_dst.ip.ip6.as_u32, &daddr.ip.ip6.as_u32,
			sizeof (ip6_address_t));
    }

  rv = ipsec_sa_add_and_lock (id, spi, proto, crypto_alg, &ck, integ_alg, &ik,
			      flags, salt, udp_src, udp_dst, 0, &tun, &sai);
  if (rv)
    {
      NL_XFRM_ERR ("ipsec sa add %x failure(err: %d) %U -> %U", id, rv,
		   format_ip_address, &saddr, format_ip_address, &daddr);
      goto error;
    }
  vec_add1 (life, lifetime);
  hash_set (lifetime_by_sa_id, id, life);

  NL_XFRM_INFO ("ipsec sa add %x success %U -> %U", id, format_ip_address,
		&saddr, format_ip_address, &daddr);

  if (IS_ROUTE_MODE_ENABLED)
    lcp_xfrm_configure_route_mode (sa, is_ipv6, &saddr, &daddr, id, dir,
				   sw_if_index);

  else if ((sw_if_index != ~0) && (dir == 0))
    {
      spd_id = lcp_xfrm_create_spd (&saddr, &daddr, spi, &if_idx, dir);
      lcp_xfrm_inb_policy_cfg (&saddr, &daddr, id, spd_id, 1);
    }

error:
  return;
}

static inline void
get_max_addresses_by_prefix (ip_address_t *orig, u8 prefix, ip_address_t *max,
			     u8 is_ip6)
{
  if (!is_ip6)
    {
      ip4_prefix_max_address_host_order (&orig->ip.ip4, prefix, &max->ip.ip4);
      cpu_to_be (max->ip.ip4.as_u32, 32);
    }
  else
    {
      ip6_preflen_to_mask (prefix, &max->ip.ip6);

      for (int i = 0; i < 4; i++)
	{
	  max->ip.ip6.as_u32[i] = ~(max->ip.ip6.as_u32[i]);
	  max->ip.ip6.as_u32[i] |= orig->ip.ip6.as_u32[i];
	}
    }
}

static inline void
lcp_xfrm_update_addr_ranges (ipsec_policy_t *p, ip_address_t *sel_saddr,
			     ip_address_t *sel_daddr, u8 sel_saddr_prefix,
			     u8 sel_daddr_prefix)
{
  ip_address_t sel_stop_saddr, sel_stop_daddr;

  get_max_addresses_by_prefix (sel_saddr, sel_saddr_prefix, &sel_stop_saddr,
			       p->is_ipv6);
  get_max_addresses_by_prefix (sel_daddr, sel_daddr_prefix, &sel_stop_daddr,
			       p->is_ipv6);

  if (!p->is_ipv6)
    {
      clib_memcpy_fast (&p->laddr.start.ip4.as_u32, &sel_saddr->ip.ip4.as_u32,
			sizeof (ip4_address_t));
      clib_memcpy_fast (&p->laddr.stop.ip4.as_u32,
			&sel_stop_saddr.ip.ip4.as_u32, sizeof (ip4_address_t));
      clib_memcpy_fast (&p->raddr.start.ip4.as_u32, &sel_daddr->ip.ip4.as_u32,
			sizeof (ip4_address_t));
      clib_memcpy_fast (&p->raddr.stop.ip4.as_u32,
			&sel_stop_daddr.ip.ip4.as_u32, sizeof (ip4_address_t));
    }
  else
    {
      clib_memcpy_fast (&p->laddr.start.ip6.as_u32, &sel_saddr->ip.ip6.as_u32,
			sizeof (ip6_address_t));
      clib_memcpy_fast (&p->laddr.stop.ip6.as_u32,
			&sel_stop_saddr.ip.ip6.as_u32, sizeof (ip6_address_t));
      clib_memcpy_fast (&p->raddr.start.ip6.as_u32, &sel_daddr->ip.ip6.as_u32,
			sizeof (ip6_address_t));
      clib_memcpy_fast (&p->raddr.stop.ip6.as_u32,
			&sel_stop_daddr.ip.ip6.as_u32, sizeof (ip6_address_t));
    }
}

static inline int
find_matching_sp (ipsec_policy_t *p, ip_address_t *saddr, ip_address_t *daddr,
		  u8 sprefix, u8 dprefix, ipsec_spd_policy_type_t type)
{
  ip_address_t saddr_stop, daddr_stop;
  u8 matched = 0;
  u8 is_ip6 = (saddr->version == AF_IP6) ? 1 : 0;

  get_max_addresses_by_prefix (saddr, sprefix, &saddr_stop, is_ip6);
  get_max_addresses_by_prefix (daddr, dprefix, &daddr_stop, is_ip6);

  if (!is_ip6 && !ip4_address_compare (&p->laddr.start.ip4, &saddr->ip.ip4) &&
      !ip4_address_compare (&p->laddr.stop.ip4, &saddr_stop.ip.ip4) &&
      !ip4_address_compare (&p->raddr.start.ip4, &daddr->ip.ip4) &&
      !ip4_address_compare (&p->raddr.stop.ip4, &daddr_stop.ip.ip4) &&
      (p->type == type))
    matched = 1;

  else if (!ip6_address_compare (&p->laddr.start.ip6, &saddr->ip.ip6) &&
	   !ip6_address_compare (&p->laddr.stop.ip6, &saddr_stop.ip.ip6) &&
	   !ip6_address_compare (&p->raddr.start.ip6, &daddr->ip.ip6) &&
	   !ip6_address_compare (&p->raddr.stop.ip6, &daddr_stop.ip.ip6) &&
	   (p->type == type))
    matched = 1;
  if (matched)
    {
      NL_XFRM_DBG ("Found Matchin policy. Delete it");
      return 1;
    }
  return 0;
}

static inline void
lcp_xfrm_del_old_sp (ip_address_t *s_saddr, ip_address_t *s_daddr,
		     u8 s_sprefix, u8 s_dprefix, ipsec_spd_policy_type_t type)
{
  ipsec_main_t *im = &ipsec_main;
  u32 spd_idx, *policies;
  ipsec_spd_t *spd;
  ipsec_policy_t *p0 = NULL;
  int r = 0;
  u32 p_idx;
  vlib_main_t *vm = vlib_get_main ();

  pool_foreach_index (spd_idx, im->spds)
    {
      spd = pool_elt_at_index (im->spds, spd_idx);
      if (!spd)
	return;
#define _(t, v)                                                               \
  vec_foreach (policies, spd->policies[IPSEC_SPD_POLICY_##t])                 \
    {                                                                         \
      p0 = pool_elt_at_index (im->policies, *policies);                       \
      if (!p0)                                                                \
	return;                                                               \
      if (p0->policy == IPSEC_POLICY_ACTION_BYPASS)                           \
	continue;                                                             \
      r =                                                                     \
	find_matching_sp (p0, s_saddr, s_daddr, s_sprefix, s_dprefix, type);  \
      if (r)                                                                  \
	goto found;                                                           \
    }
      foreach_ipsec_spd_policy_type
#undef _
    }

found:
  if (!r)
    return;
  NL_XFRM_DBG ("Deleting Pol wth spdid:%x and sa_id:%x", p0->id, p0->sa_id);
  r = ipsec_add_del_policy (vm, p0, 0, &p_idx);
  if (!r)
    NL_XFRM_INFO ("ipsec inb policy del success %U -> %U", format_ip_address,
		  s_saddr, format_ip_address, s_daddr);
  else
    NL_XFRM_ERR ("ipsec inb policy del fail(err: %d) %U -> %U", r,
		 format_ip_address, s_saddr, format_ip_address, s_daddr);
}

static inline void
fib_entry_cfg (ip_address_t *sel_daddr, u8 sel_daddr_prefix, u32 if_idx,
	       u8 ip6, u8 is_add)
{
  u8 fib_index = 0;
  fib_route_path_t *rpath = NULL, path;
  fib_prefix_t rpfx;
  fib_source_t fib_src = FIB_SOURCE_API;

  clib_memset (&path, 0, sizeof (path));
  path.frp_weight = 1;
  path.frp_sw_if_index = if_idx;
  vec_add1 (rpath, path);

  rpfx.fp_len = sel_daddr_prefix;
  if (!ip6)
    {
      rpfx.fp_proto = FIB_PROTOCOL_IP4;
      memcpy (&rpfx.fp_addr.ip4, &sel_daddr->ip.ip4, sizeof (ip4_address_t));
    }
  else
    {
      rpfx.fp_proto = FIB_PROTOCOL_IP6;
      memcpy (&rpfx.fp_addr.ip6, &sel_daddr->ip.ip6, sizeof (ip6_address_t));
    }

  if (!is_add)
    fib_table_entry_path_remove2 (fib_index, &rpfx, fib_src, rpath);
  else
    fib_table_entry_path_add2 (fib_index, &rpfx, fib_src, FIB_ENTRY_FLAG_NONE,
			       rpath);
  vec_free (rpath);
}

static inline void
lcp_xfrm_tun_cfg_destroy (ip_address_t *sel_daddr, u8 sel_daddr_prefix,
			  u8 is_ipv6)
{
  int sw_if_index;
  uword *p = NULL;
  int rv;

  if (!is_ipv6)
    p = hash_get (tun_idx_by_sel_daddr, sel_daddr->ip.ip4.as_u32);
  else
    p = hash_get (tun_idx_by_sel_daddr,
		  ip6_address_hash_to_u32 (&sel_daddr->ip.ip6));

  if (!p)
    return;
  sw_if_index = ((policy_db_t *) p[0])->tun_sw_if_idx;

  if (sw_if_index == ~0)
    return;
  fib_entry_cfg (sel_daddr, sel_daddr_prefix, sw_if_index, is_ipv6, 0);

  if (!is_ipv6)
    hash_unset (tun_idx_by_sel_daddr, sel_daddr->ip.ip4.as_u32);
  else
    hash_unset (tun_idx_by_sel_daddr, sel_daddr->ip.ip6.as_u32);

  rv = ipsec_tun_protect_del (sw_if_index, NULL);
  if (rv)
    {
      NL_XFRM_ERR ("Tunnel protect del failure (err: %d)", rv);
      return;
    }

  if (nm->interface_type == NL_INTERFACE_TYPE_IPIP)
    rv = ipip_del_tunnel (sw_if_index);
  else
    rv = ipsec_itf_delete (sw_if_index);
  if (rv)
    NL_XFRM_ERR ("Tunnel deletion failure (err: %d)", rv);
  return;
}

static inline void
nl_xfrm_sp_del (struct xfrmnl_sp *sp)
{
  struct xfrmnl_sel *sel = xfrmnl_sp_get_sel (sp);
  struct nl_addr *sel_src = xfrmnl_sel_get_saddr (sel);
  struct nl_addr *sel_dst = xfrmnl_sel_get_daddr (sel);
  u8 fam = xfrmnl_sel_get_family (sel);
  u8 sel_saddr_prefix = xfrmnl_sel_get_prefixlen_s (sel);
  u8 sel_daddr_prefix = xfrmnl_sel_get_prefixlen_d (sel);
  ip_address_t sel_saddr, sel_daddr;
  u8 dir = xfrmnl_sp_get_dir (sp);
  ipsec_spd_policy_type_t type;
  u8 is_ip6;

  if (dir != XFRM_POLICY_OUT)
    return;

  is_ip6 = (fam == AF_INET6) ? 1 : 0;

  lcp_xfrm_mk_ipaddr (sel_dst, &sel_daddr);
  lcp_xfrm_mk_ipaddr (sel_src, &sel_saddr);

  if (IS_ROUTE_MODE_ENABLED)
    {
      lcp_xfrm_tun_cfg_destroy (&sel_daddr, sel_daddr_prefix, is_ip6);
    }
  else
    {
      ipsec_policy_mk_type (1, is_ip6, IPSEC_POLICY_ACTION_PROTECT, &type);

      lcp_xfrm_del_old_sp (&sel_saddr, &sel_daddr, sel_saddr_prefix,
			   sel_daddr_prefix, type);
    }

  return;
}

static inline void
lcp_xfrm_tun_update_fib (u32 sa_id, ip_address_t *sel_daddr,
			 u8 sel_daddr_prefix, u8 is_ipv6)
{
  int sw_if_index = -1;
  uword *p = NULL;
  policy_db_t *pols = NULL, pol;

  p = hash_get (lifetime_by_sa_id, sa_id);
  if (!p)
    return;
  sw_if_index = ((sa_life_limits_t *) p[0])->tun_sw_if_idx;

  pol.tun_sw_if_idx = sw_if_index;
  vec_add1 (pols, pol);
  if (!is_ipv6)
    hash_set (tun_idx_by_sel_daddr, sel_daddr->ip.ip4.as_u32, pols);
  else
    hash_set (tun_idx_by_sel_daddr,
	      ip6_address_hash_to_u32 (&sel_daddr->ip.ip6), pols);

  if (sw_if_index != ~0)
    fib_entry_cfg (sel_daddr, sel_daddr_prefix, sw_if_index, is_ipv6, 1);
}

static inline void
nl_xfrm_sp_add (struct xfrmnl_sp *sp, u8 num)
{
  /* User template(tunnel) variables */
  struct xfrmnl_user_tmpl *u_tmpl = xfrmnl_sp_usertemplate_n (sp, (num - 1));
  struct nl_addr *src = xfrmnl_user_tmpl_get_saddr (u_tmpl);
  struct nl_addr *dst = xfrmnl_user_tmpl_get_daddr (u_tmpl);
  u8 fam = xfrmnl_user_tmpl_get_family (u_tmpl);
  u32 spi = xfrmnl_user_tmpl_get_spi (u_tmpl);
  ip_address_t saddr, daddr;
  u32 sa_id;

  /* Selector variables */
  struct xfrmnl_sel *sel = xfrmnl_sp_get_sel (sp);
  struct nl_addr *sel_src = xfrmnl_sel_get_saddr (sel);
  struct nl_addr *sel_dst = xfrmnl_sel_get_daddr (sel);
  u8 sel_saddr_prefix = xfrmnl_sel_get_prefixlen_s (sel);
  u8 sel_daddr_prefix = xfrmnl_sel_get_prefixlen_d (sel);
  u16 sel_sportmask = xfrmnl_sel_get_sportmask (sel);
  u16 sel_dportmask = xfrmnl_sel_get_dportmask (sel);
  u16 sel_dport = xfrmnl_sel_get_dport (sel);
  u16 sel_sport = xfrmnl_sel_get_sport (sel);
  u8 proto = xfrmnl_sel_get_proto (sel);
  ip_address_t sel_saddr, sel_daddr;

  u32 prio = xfrmnl_sp_get_priority (sp);
  u8 dir = xfrmnl_sp_get_dir (sp);
  u8 is_ipv6 = 0, is_outbound = 0;
  vlib_main_t *vm = vlib_get_main ();
  ipsec_spd_policy_type_t type;
  u32 p_idx, spd_id = 0;
  int rv, sw_if_index;
  ipsec_policy_t p;

  /*
   * Inbound policy additions are handled as part of SA addition.
   * Hence we ignore inbound policy notifications from kernel
   */
  if (dir != XFRM_POLICY_OUT)
    return;

  is_ipv6 = (fam == AF_INET6) ? 1 : 0;

  lcp_xfrm_mk_ipaddr (sel_dst, &sel_daddr);
  lcp_xfrm_mk_ipaddr (sel_src, &sel_saddr);
  lcp_xfrm_mk_ipaddr (dst, &daddr);
  lcp_xfrm_mk_ipaddr (src, &saddr);

  sa_id = lcp_xfrm_ipsec_sa_id_table (spi, &daddr);

  if (IS_ROUTE_MODE_ENABLED)
    {
      /*
       * Add a fib entry for dest tun selectors via ipipX interface.
       */
      lcp_xfrm_tun_update_fib (sa_id, &sel_daddr, sel_daddr_prefix, is_ipv6);
      return;
    }

  is_outbound = 1;
  spd_id =
    lcp_xfrm_create_spd (&saddr, &daddr, spi, &sw_if_index, is_outbound);

  if (sw_if_index == ~0)
    {
      NL_XFRM_ERR ("SP add Notfn is not for vpp interfaces");
      return;
    }

  ipsec_policy_mk_type (is_outbound, is_ipv6, IPSEC_POLICY_ACTION_PROTECT,
			&type);
  lcp_xfrm_del_old_sp (&sel_saddr, &sel_daddr, sel_saddr_prefix,
		       sel_daddr_prefix, type);

  p.id = spd_id;
  p.priority = prio;
  p.is_ipv6 = is_ipv6;

  lcp_xfrm_update_addr_ranges (&p, &sel_saddr, &sel_daddr, sel_saddr_prefix,
			       sel_daddr_prefix);
  p.protocol = proto;
  update_port_details (&p, sel_sport, sel_dport, sel_sportmask, sel_dportmask);
  p.sa_id = sa_id;
  p.policy = IPSEC_POLICY_ACTION_PROTECT;

  ipsec_policy_mk_type (is_outbound, p.is_ipv6, p.policy, &p.type);
  rv = ipsec_add_del_policy (vm, &p, 1, &p_idx);
  if (!rv)
    NL_XFRM_INFO ("ipsec %s policy add success %U -> %U sa_id: %x spd_id: %x",
		  (!is_outbound ? "inb" : "outb"), format_ip_address,
		  &sel_saddr, format_ip_address, &sel_daddr, sa_id, spd_id);
  else
    NL_XFRM_ERR (
      "ipsec %s policy add fail(err: %d) %U -> %U sa_id: %x spd_id: %x",
      (!is_outbound ? "inb" : "outb"), rv, format_ip_address, &sel_saddr,
      format_ip_address, &sel_daddr, sa_id, spd_id);

  return;
}

void
nl_xfrm_sa_cfg (struct xfrmnl_sa *sa)
{
  switch (nl_object_get_msgtype ((struct nl_object *) sa))
    {
    case XFRM_MSG_UPDSA:
    case XFRM_MSG_NEWSA:
      nl_xfrm_sa_add (sa);
      break;

    case XFRM_MSG_EXPIRE:
    case XFRM_MSG_DELSA:
      nl_xfrm_sa_del (sa);
      break;
    }
}

void
nl_xfrm_sp_cfg (struct xfrmnl_sp *sp)
{
  u8 num_user_tmpl = 0;

  switch (nl_object_get_msgtype ((struct nl_object *) sp))
    {
    case XFRM_MSG_UPDPOLICY:
    case XFRM_MSG_NEWPOLICY:
      num_user_tmpl = xfrmnl_sp_get_nusertemplates (sp);
      if (!num_user_tmpl)
	{
	  NL_XFRM_DBG (
	    "Don't support allow/drop policies notification from Kernel. \
                        Number of user template (%u) should be 1. If more than 1    \
                        template is found, we choose only the first one",
	    num_user_tmpl);
	  return;
	}
      nl_xfrm_sp_add (sp, num_user_tmpl);
      break;

    case XFRM_MSG_DELPOLICY:
      /* DEL notification will not have the user template */
      nl_xfrm_sp_del (sp);
      break;
    }
}

static inline u8
build_nl_expire_msg (ipsec_sa_t *sa, u8 is_hard)
{
  sa_expire_req_nl_t expire_req;

  memset (&expire_req, 0, sizeof (expire_req));

  /* Fill up the nl header */
  expire_req.nlmsg_hdr.nlmsg_len =
    NLMSG_LENGTH (sizeof (expire_req.xfrm_expire));
  expire_req.nlmsg_hdr.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
  expire_req.nlmsg_hdr.nlmsg_type = XFRM_MSG_EXPIRE;
  expire_req.nlmsg_hdr.nlmsg_seq = ++g_seq;
  expire_req.nlmsg_hdr.nlmsg_pid = nl_socket_get_local_port (nm->sk_xfrm);

  /* Fill up the xfrm_user_expire with the SA info that expired */
  expire_req.xfrm_expire.hard = is_hard;
  expire_req.xfrm_expire.state.flags = XFRM_STATE_AF_UNSPEC;
  expire_req.xfrm_expire.state.id.spi = clib_host_to_net_u32 (sa->spi);
  expire_req.xfrm_expire.state.mode = (sa->flags & IPSEC_SA_FLAG_IS_TUNNEL) ?
					      XFRM_MODE_TUNNEL :
					      XFRM_MODE_TRANSPORT;
  expire_req.xfrm_expire.state.id.proto =
    (sa->protocol == IPSEC_PROTOCOL_ESP) ? IPPROTO_ESP : IPPROTO_AH;

  expire_req.xfrm_expire.state.family =
    (sa->tunnel.t_dst.version == AF_IP4) ? AF_INET : AF_INET6;

  (sa->tunnel.t_dst.version == AF_IP4) ?
	  clib_memcpy_fast (&expire_req.xfrm_expire.state.id.daddr.a4,
		      &sa->tunnel.t_dst.ip.ip4.as_u32,
		      sizeof (ip4_address_t)) :
	  clib_memcpy_fast (&expire_req.xfrm_expire.state.id.daddr.a6,
		      &sa->tunnel.t_dst.ip.ip6.as_u32, sizeof (ip6_address_t));

  (sa->tunnel.t_src.version == AF_IP4) ?
	  clib_memcpy_fast (&expire_req.xfrm_expire.state.saddr.a4,
		      &sa->tunnel.t_src.ip.ip4.as_u32,
		      sizeof (ip4_address_t)) :
	  clib_memcpy_fast (&expire_req.xfrm_expire.state.saddr.a6,
		      &sa->tunnel.t_src.ip.ip6.as_u32, sizeof (ip6_address_t));

  return send_nl_msg (&expire_req.nlmsg_hdr, XFRMGRP_EXPIRE, XFRM_MSG_EXPIRE);
}

u8
check_for_expiry ()
{
  sa_life_limits_t *life = NULL;
  vlib_counter_t count;
  uword *p = NULL;
  ipsec_sa_t *sa = NULL;
  int rv = 0;

  pool_foreach (sa, ipsec_sa_pool)
    {
      p = hash_get (lifetime_by_sa_id, sa->id);
      if (!p)
	continue;
      life = (sa_life_limits_t *) p[0];
      vlib_get_combined_counter (&ipsec_sa_counters, sa->stat_index, &count);

      if ((count.packets >= life->hard_packet_limit) ||
	  (count.bytes >= life->hard_byte_limit))
	{
	  NL_XFRM_INFO (
	    "HARD EXPIRY said : %x CntPkt: %u SoftPkt: %u HardPkt: %u", sa->id,
	    count.packets, life->soft_packet_limit, life->hard_packet_limit);
	  rv = build_nl_expire_msg (sa, 1);
	}
      else if ((count.packets >= life->soft_packet_limit) ||
	       (count.bytes >= life->soft_byte_limit))
	{
	  NL_XFRM_INFO (
	    "SOFT EXPIRY said : %x CntPkt: %u SoftPkt: %u HardPkt: %u", sa->id,
	    count.packets, life->soft_packet_limit, life->hard_packet_limit);
	  rv = build_nl_expire_msg (sa, 0);
	}
      if (rv)
	vlib_zero_combined_counter (&ipsec_sa_counters, sa->stat_index);
    }
  return 0;
}

const nl_xfrm_vft_t lcp_xfrm_vft = {
  .nvl_rt_xfrm_sa_cfg = { .is_mp_safe = 0, .cb = nl_xfrm_sa_cfg },
  .nvl_rt_xfrm_sp_cfg = { .is_mp_safe = 0, .cb = nl_xfrm_sp_cfg },
};

static clib_error_t *
lcp_xfrm_init (vlib_main_t *vm)
{
  lcp_xfrm_logger = vlib_log_register_class ("linux-cp", "ipsec");

  nl_xfrm_register_vft (&lcp_xfrm_vft);

  lifetime_by_sa_id = hash_create (0, sizeof (uword));
  tun_idx_by_sel_daddr = hash_create (0, sizeof (uword));

  return (NULL);
}

VLIB_INIT_FUNCTION (lcp_xfrm_init) = {
  .runs_before = VLIB_INITS ("lcp_nl_xfrm_init"),
};

uword
ipsec_xfrm_expire_process (vlib_main_t *vm, vlib_node_runtime_t *node,
			   vlib_frame_t *frame)
{
  /* init will wake it up */
  vlib_process_wait_for_event (vm);

  while (1)
    {
      vlib_process_wait_for_event_or_clock (vm, 2);
      vlib_process_get_events (vm, NULL);
      check_for_expiry ();
    }
  return 0;
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
