/*
 * Copyright (c) 2015 Cisco and/or its affiliates.
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
/*
 * ip/ip_packet.h: packet format common between ip4 & ip6
 *
 * Copyright (c) 2008 Eliot Dresselhaus
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 *  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 *  EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 *  MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 *  NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
 *  LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
 *  OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
 *  WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

#ifndef included_ip_packet_h
#define included_ip_packet_h

#include <vppinfra/byte_order.h>
#include <vppinfra/error.h>
#include <vppinfra/format.h>

typedef enum ip_protocol
{
#define ip_protocol(n,s) IP_PROTOCOL_##s = n,
#include "protocols.def"
#undef ip_protocol
} __clib_packed ip_protocol_t;

/* TCP/UDP ports. */
typedef enum
{
#define ip_port(s,n) IP_PORT_##s = n,
#include "ports.def"
#undef ip_port
} ip_port_t;

/* Classifies protocols into UDP, ICMP or other. */
typedef enum
{
  IP_BUILTIN_PROTOCOL_UDP,
  IP_BUILTIN_PROTOCOL_ICMP,
  IP_BUILTIN_PROTOCOL_UNKNOWN,
} ip_builtin_protocol_t;

#define foreach_ip_builtin_multicast_group	\
  _ (1, all_hosts_on_subnet)			\
  _ (2, all_routers_on_subnet)			\
  _ (4, dvmrp)					\
  _ (5, ospf_all_routers)			\
  _ (6, ospf_designated_routers)		\
  _ (13, pim)					\
  _ (18, vrrp)					\
  _ (102, hsrp)					\
  _ (22, igmp_v3)

typedef enum
{
#define _(n,f) IP_MULTICAST_GROUP_##f = n,
  foreach_ip_builtin_multicast_group
#undef _
} ip_multicast_group_t;


/**
 * The set of RFC defined DSCP values.
 */
#define foreach_ip_dscp                       \
  _(-1, INVALID)                              \
  _(0, CS0)                                   \
  _(8, CS1)                                   \
  _(10, AF11)                                 \
  _(12, AF12)                                 \
  _(14, AF13)                                 \
  _(16, CS2)                                  \
  _(18, AF21)                                 \
  _(20, AF22)                                 \
  _(22, AF23)                                 \
  _(24, CS3)                                  \
  _(26, AF31)                                 \
  _(28, AF32)                                 \
  _(30, AF33)                                 \
  _(32, CS4)                                  \
  _(34, AF41)                                 \
  _(36, AF42)                                 \
  _(38, AF43)                                 \
  _(40, CS5)                                  \
  _(46, EF)                                   \
  _(48, CS6)                                  \
  _(50, CS7)

typedef enum ip_dscp_t_
{
#define _(n,f) IP_DSCP_##f = n,
  foreach_ip_dscp
#undef _
} __clib_packed ip_dscp_t;

extern u8 *format_ip_dscp (u8 * s, va_list * va);
unformat_function_t unformat_ip_dscp;

/**
 * IP DSCP bit shift
 *  The ECN occupies the 2 least significant bits of the TC field
 */
#define IP_PACKET_TC_FIELD_DSCP_BIT_SHIFT 2
#define IP_PACKET_TC_FIELD_ECN_MASK 0x03

/**
 * The set of RFC defined DSCP values.
 */
#define foreach_ip_ecn                        \
  _(0, NON_ECN)                               \
  _(1, ECT_0)                                 \
  _(2, ECT_1)                                 \
  _(3, CE)

typedef enum ip_ecn_t_
{
#define _(n,f) IP_ECN_##f = n,
  foreach_ip_ecn
#undef _
} __clib_packed ip_ecn_t;

STATIC_ASSERT_SIZEOF (ip_ecn_t, 1);

extern u8 *format_ip_ecn (u8 * s, va_list * va);

/* Incremental checksum update. */
typedef uword ip_csum_t;

always_inline ip_csum_t
ip_csum_with_carry (ip_csum_t sum, ip_csum_t x)
{
  ip_csum_t t = sum + x;
  return t + (t < x);
}

/* Update checksum changing field at even byte offset from x -> 0. */
always_inline ip_csum_t
ip_csum_add_even (ip_csum_t c, ip_csum_t x)
{
  ip_csum_t d;

  d = c - x;

  /* Fold in carry from high bit. */
  d -= d > c;

  ip_csum_t t = ip_csum_with_carry (d, x);
  ASSERT ((t - c == 0) || (t - c == ~0));

  return d;
}

/* Update checksum changing field at even byte offset from 0 -> x. */
always_inline ip_csum_t
ip_csum_sub_even (ip_csum_t c, ip_csum_t x)
{
  return ip_csum_with_carry (c, x);
}

always_inline ip_csum_t
ip_csum_update_inline (ip_csum_t sum, ip_csum_t old, ip_csum_t new,
		       u32 field_byte_offset, u32 field_n_bytes)
{
  /* For even 1-byte fields on big-endian and odd 1-byte fields on little endian
     we need to shift byte into place for checksum. */
  if ((field_n_bytes % 2)
      && (field_byte_offset % 2) == CLIB_ARCH_IS_LITTLE_ENDIAN)
    {
      old = old << 8;
      new = new << 8;
    }
  sum = ip_csum_sub_even (sum, old);
  sum = ip_csum_add_even (sum, new);
  return sum;
}

#define ip_csum_update(sum,old,new,type,field)			\
  ip_csum_update_inline ((sum), (old), (new),			\
			 STRUCT_OFFSET_OF (type, field),	\
			 STRUCT_SIZE_OF (type, field))

always_inline u16
ip_csum_fold (ip_csum_t c)
{
  /* Reduce to 16 bits. */
#if defined(__x86_64__) && defined(__BMI2__)
  u64 tmp;
  asm volatile(
    /* using ADC is much faster than mov, shift, add sequence
     * compiler produces */
    "mov	%k[sum], %k[tmp]		\n\t"
    "shr	$32, %[sum]			\n\t"
    "add	%k[tmp], %k[sum]		\n\t"
    "mov	$16, %k[tmp]			\n\t"
    "shrx	%k[tmp], %k[sum], %k[tmp]	\n\t"
    "adc	%w[tmp], %w[sum]		\n\t"
    "adc	$0, %w[sum]			\n\t"
    : [ sum ] "+&r"(c), [ tmp ] "=&r"(tmp));
#else
#if uword_bits == 64
  c = (c & (ip_csum_t) 0xffffffff) + (c >> (ip_csum_t) 32);
  c = (c & 0xffff) + (c >> 16);
#endif

  c = (c & 0xffff) + (c >> 16);
  c = (c & 0xffff) + (c >> 16);
#endif
  return c;
}

extern ip_csum_t (*vnet_incremental_checksum_fp) (ip_csum_t, void *, uword);

/* Checksum routine. */
always_inline ip_csum_t
ip_incremental_checksum (ip_csum_t sum, void *_data, uword n_bytes)
{
  return (*vnet_incremental_checksum_fp) (sum, _data, n_bytes);
}

always_inline u16
ip_csum_and_memcpy_fold (ip_csum_t sum, void *dst)
{
  return ip_csum_fold (sum);
}

#endif /* included_ip_packet_h */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
