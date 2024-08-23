/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2021 Cisco Systems, Inc.
 */

#ifndef included_vector_toeplitz_h
#define included_vector_toeplitz_h
#include <vppinfra/clib.h>

typedef struct
{
  u16 key_length;
  u16 gfni_offset;
  u8 data[];
} clib_toeplitz_hash_key_t;

clib_toeplitz_hash_key_t *clib_toeplitz_hash_key_init (u8 *key, u32 keylen);
void clib_toeplitz_hash_key_free (clib_toeplitz_hash_key_t *k);

#ifdef CLIB_HAVE_VEC256
static_always_inline u32x8
toeplitz_hash_one_x8 (u32x8 hash, u64x4 v4, u8 data, u8 off)
{
  u32x8 v8 = u32x8_shuffle2 (v4 << (off * 8), v4 << (off * 8 + 4),
			     /*uppper 32 bits of each u64 in reverse order */
			     15, 13, 11, 9, 7, 5, 3, 1);

#ifdef CLIB_HAVE_VEC256_MASK_BITWISE_OPS
  return u32x8_mask_xor (hash, v8, data);
#else
  static const u32x8 bits = { 1, 2, 4, 8, 16, 32, 64, 128 };
  return hash ^ (((u32x8_splat (data) & bits) != u32x8_zero ()) & v8);
#endif
}
#endif

#if defined(__GFNI__) && defined(__AVX512F__)
static const u8x64 __clib_toeplitz_hash_gfni_permute = {
  /* clang-format off */
  0x00, 0x01, 0x02, 0x03, 0x40, 0x41, 0x42, 0x43,
  0x01, 0x02, 0x03, 0x04, 0x41, 0x42, 0x43, 0x44,
  0x02, 0x03, 0x04, 0x05, 0x42, 0x43, 0x44, 0x45,
  0x03, 0x04, 0x05, 0x06, 0x43, 0x44, 0x45, 0x46,
  0x04, 0x05, 0x06, 0x07, 0x44, 0x45, 0x46, 0x47,
  0x05, 0x06, 0x07, 0x08, 0x45, 0x46, 0x47, 0x48,
  0x06, 0x07, 0x08, 0x09, 0x46, 0x47, 0x48, 0x49,
  0x07, 0x08, 0x09, 0x0a, 0x47, 0x48, 0x49, 0x4a
  /* clang-format on */
};
static_always_inline u64x8
clib_toeplitz_hash_gfni_one (u8x64 d0, u64x8 m, int i)
{

  d0 = i == 1 ? (u8x64) u64x8_align_right (d0, d0, 1) : d0;
  d0 = i == 2 ? (u8x64) u64x8_align_right (d0, d0, 2) : d0;
  d0 = i == 3 ? (u8x64) u64x8_align_right (d0, d0, 3) : d0;
  d0 = i == 4 ? (u8x64) u64x8_align_right (d0, d0, 4) : d0;
  d0 = i == 5 ? (u8x64) u64x8_align_right (d0, d0, 5) : d0;
  d0 = i == 6 ? (u8x64) u64x8_align_right (d0, d0, 6) : d0;

  d0 = u8x64_permute (__clib_toeplitz_hash_gfni_permute, d0);

  return (u64x8) _mm512_gf2p8affine_epi64_epi8 ((__m512i) d0, (__m512i) m, 0);
}

static_always_inline u64x8
clib_toeplitz_hash_gfni_two (u8x64 d0, u8x64 d1, u64x8 m, int i)
{

  d0 = i == 1 ? (u8x64) u64x8_align_right (d0, d0, 1) : d0;
  d1 = i == 1 ? (u8x64) u64x8_align_right (d1, d1, 1) : d1;
  d0 = i == 2 ? (u8x64) u64x8_align_right (d0, d0, 2) : d0;
  d1 = i == 2 ? (u8x64) u64x8_align_right (d1, d1, 2) : d1;
  d0 = i == 3 ? (u8x64) u64x8_align_right (d0, d0, 3) : d0;
  d1 = i == 3 ? (u8x64) u64x8_align_right (d1, d1, 3) : d1;
  d0 = i == 4 ? (u8x64) u64x8_align_right (d0, d0, 4) : d0;
  d1 = i == 4 ? (u8x64) u64x8_align_right (d1, d1, 4) : d1;
  d0 = i == 5 ? (u8x64) u64x8_align_right (d0, d0, 5) : d0;
  d1 = i == 5 ? (u8x64) u64x8_align_right (d1, d1, 5) : d1;
  d0 = i == 6 ? (u8x64) u64x8_align_right (d0, d0, 6) : d0;
  d1 = i == 6 ? (u8x64) u64x8_align_right (d1, d1, 6) : d1;

  d0 = u8x64_permute2 (__clib_toeplitz_hash_gfni_permute, d0, d1);

  return (u64x8) _mm512_gf2p8affine_epi64_epi8 ((__m512i) d0, (__m512i) m, 0);
}
#endif

static_always_inline u32
clib_toeplitz_hash (clib_toeplitz_hash_key_t *k, u8 *data, int n_bytes)
{
  u8 *key = k->data;
  /* key must be 4 bytes longer than data */
  ASSERT (k->key_length - n_bytes >= 4);

#if defined(__GFNI__) && defined(__AVX512F__)
  u8x64 d0;
  u64x8 h0 = {};
  u64x8u *m = (u64x8u *) ((u8 *) k + k->gfni_offset);

  /* move data ptr backwards for 3 byte so mask load "prepends" three zeros */
  data -= 3;
  n_bytes += 3;

  if (n_bytes < 64)
    {
      d0 = u8x64_mask_load_zero ((u8 *) data, pow2_mask (n_bytes - 3) << 3);
      goto last8;
    }

  d0 = u8x64_mask_load_zero ((u8 *) data, -1ULL << 3);
next56:
  h0 = u64x8_xor3 (h0, clib_toeplitz_hash_gfni_one (d0, m[0], 0),
		   clib_toeplitz_hash_gfni_one (d0, m[1], 1));
  h0 = u64x8_xor3 (h0, clib_toeplitz_hash_gfni_one (d0, m[2], 2),
		   clib_toeplitz_hash_gfni_one (d0, m[3], 3));
  h0 = u64x8_xor3 (h0, clib_toeplitz_hash_gfni_one (d0, m[4], 4),
		   clib_toeplitz_hash_gfni_one (d0, m[5], 5));
  h0 ^= clib_toeplitz_hash_gfni_one (d0, m[6], 6);
  n_bytes -= 56;
  data += 56;
  m += 7;

  if (n_bytes >= 64)
    {
      d0 = *(u8x64u *) data;
      goto next56;
    }

  if (n_bytes == 0)
    goto done;

  d0 = u8x64_mask_load_zero ((u8 *) data, pow2_mask (n_bytes));
last8:
  h0 ^= clib_toeplitz_hash_gfni_one (d0, m[0], 0);
  n_bytes -= 8;

  if (n_bytes > 0)
    {
      m += 1;
      d0 = (u8x64) u64x8_align_right (u64x8_zero (), d0, 1);
      goto last8;
    }

done:
  return u64x8_hxor (h0);
#elif defined(CLIB_HAVE_VEC256)
  u64x4 v4, shift = { 0, 1, 2, 3 };
  u32x8 h0 = {};

  while (n_bytes >= 4)
    {
      v4 = u64x4_splat (clib_net_to_host_u64 (*(u64u *) key)) << shift;

      h0 = toeplitz_hash_one_x8 (h0, v4, data[0], 0);
      h0 = toeplitz_hash_one_x8 (h0, v4, data[1], 1);
      h0 = toeplitz_hash_one_x8 (h0, v4, data[2], 2);
      h0 = toeplitz_hash_one_x8 (h0, v4, data[3], 3);

      data += 4;
      key += 4;
      n_bytes -= 4;
    }

  if (n_bytes)
    {
      u64 v = (u64) clib_net_to_host_u32 ((u64) (*(u32u *) key)) << 32;
      v |= (u64) key[4] << 24;

      if (n_bytes == 3)
	{
	  v |= (u64) key[5] << 16;
	  v |= (u64) key[6] << 8;
	  v4 = u64x4_splat (v) << shift;
	  h0 = toeplitz_hash_one_x8 (h0, v4, data[0], 0);
	  h0 = toeplitz_hash_one_x8 (h0, v4, data[1], 1);
	  h0 = toeplitz_hash_one_x8 (h0, v4, data[2], 2);
	}
      else if (n_bytes == 2)
	{
	  v |= (u64) key[5] << 16;
	  v4 = u64x4_splat (v) << shift;
	  h0 = toeplitz_hash_one_x8 (h0, v4, data[0], 0);
	  h0 = toeplitz_hash_one_x8 (h0, v4, data[1], 1);
	}
      else
	{
	  v4 = u64x4_splat (v) << shift;
	  h0 = toeplitz_hash_one_x8 (h0, v4, data[0], 0);
	}
    }

  return u32x8_hxor (h0);
#endif
  u64 v, hash = 0;

  while (n_bytes >= 4)
    {
      v = clib_net_to_host_u64 (*(u64u *) key);

      for (u8 bit = 1 << 7, byte = data[0]; bit; bit >>= 1, v <<= 1)
	hash ^= byte & bit ? v : 0;
      for (u8 bit = 1 << 7, byte = data[1]; bit; bit >>= 1, v <<= 1)
	hash ^= byte & bit ? v : 0;
      for (u8 bit = 1 << 7, byte = data[2]; bit; bit >>= 1, v <<= 1)
	hash ^= byte & bit ? v : 0;
      for (u8 bit = 1 << 7, byte = data[3]; bit; bit >>= 1, v <<= 1)
	hash ^= byte & bit ? v : 0;

      data += 4;
      key += 4;
      n_bytes -= 4;
    }

  if (n_bytes)
    {
      v = (u64) clib_net_to_host_u32 ((u64) (*(u32u *) key)) << 32;
      v |= (u64) key[4] << 24;
      for (u8 bit = 1 << 7, byte = data[0]; bit; bit >>= 1, v <<= 1)
	hash ^= byte & bit ? v : 0;
      if (n_bytes > 1)
	{
	  v |= (u64) key[5] << 24;
	  for (u8 bit = 1 << 7, byte = data[1]; bit; bit >>= 1, v <<= 1)
	    hash ^= byte & bit ? v : 0;
	}
      if (n_bytes > 2)
	{
	  v |= (u64) key[6] << 24;
	  for (u8 bit = 1 << 7, byte = data[2]; bit; bit >>= 1, v <<= 1)
	    hash ^= byte & bit ? v : 0;
	}
    }
  return hash >> 32;
}

static_always_inline void
clib_toeplitz_hash_x4 (clib_toeplitz_hash_key_t *k, u8 *data0, u8 *data1,
		       u8 *data2, u8 *data3, u32 *hash0, u32 *hash1,
		       u32 *hash2, u32 *hash3, int n_bytes)
{
  /* key must be 4 bytes longer than data */
  ASSERT (k->key_length - n_bytes >= 4);
#if defined(__GFNI__) && defined(__AVX512F__)
  u64x8u *m = (u64x8u *) ((u8 *) k + k->gfni_offset);
  u8x64 d0, d1, d2, d3;
  u64x8 h0 = {}, h2 = {};
  u64 h, mask;

  /* move data ptr backwards for 3 byte so mask load "prepends" three zeros */
  data0 -= 3;
  data1 -= 3;
  data2 -= 3;
  data3 -= 3;
  n_bytes += 3;

  if (n_bytes < 64)
    {
      mask = pow2_mask (n_bytes - 3) << 3;
      d0 = u8x64_mask_load_zero ((u8 *) data0, mask);
      d1 = u8x64_mask_load_zero ((u8 *) data1, mask);
      d2 = u8x64_mask_load_zero ((u8 *) data2, mask);
      d3 = u8x64_mask_load_zero ((u8 *) data3, mask);
      goto last8;
    }

  mask = -1ULL << 3;
  d0 = u8x64_mask_load_zero ((u8 *) data0, mask);
  d1 = u8x64_mask_load_zero ((u8 *) data1, mask);
  d2 = u8x64_mask_load_zero ((u8 *) data2, mask);
  d3 = u8x64_mask_load_zero ((u8 *) data3, mask);
next56:
  h0 = u64x8_xor3 (h0, clib_toeplitz_hash_gfni_two (d0, d1, m[0], 0),
		   clib_toeplitz_hash_gfni_two (d0, d1, m[1], 1));
  h2 = u64x8_xor3 (h2, clib_toeplitz_hash_gfni_two (d2, d3, m[0], 0),
		   clib_toeplitz_hash_gfni_two (d2, d3, m[1], 1));

  h0 = u64x8_xor3 (h0, clib_toeplitz_hash_gfni_two (d0, d1, m[2], 2),
		   clib_toeplitz_hash_gfni_two (d0, d1, m[3], 3));
  h2 = u64x8_xor3 (h2, clib_toeplitz_hash_gfni_two (d2, d3, m[2], 2),
		   clib_toeplitz_hash_gfni_two (d2, d3, m[3], 3));

  h0 = u64x8_xor3 (h0, clib_toeplitz_hash_gfni_two (d0, d1, m[4], 4),
		   clib_toeplitz_hash_gfni_two (d0, d1, m[5], 5));
  h2 = u64x8_xor3 (h2, clib_toeplitz_hash_gfni_two (d2, d3, m[4], 4),
		   clib_toeplitz_hash_gfni_two (d2, d3, m[5], 5));

  h0 ^= clib_toeplitz_hash_gfni_two (d0, d1, m[6], 6);
  h2 ^= clib_toeplitz_hash_gfni_two (d2, d3, m[6], 6);

  n_bytes -= 56;
  data0 += 56;
  data1 += 56;
  data2 += 56;
  data3 += 56;
  m += 7;

  if (n_bytes >= 64)
    {
      d0 = *(u8x64u *) data0;
      d1 = *(u8x64u *) data1;
      d2 = *(u8x64u *) data2;
      d3 = *(u8x64u *) data3;
      goto next56;
    }

  if (n_bytes == 0)
    goto done;

  mask = pow2_mask (n_bytes);
  d0 = u8x64_mask_load_zero ((u8 *) data0, mask);
  d1 = u8x64_mask_load_zero ((u8 *) data1, mask);
  d2 = u8x64_mask_load_zero ((u8 *) data2, mask);
  d3 = u8x64_mask_load_zero ((u8 *) data3, mask);
last8:
  h0 ^= clib_toeplitz_hash_gfni_two (d0, d1, m[0], 0);
  h2 ^= clib_toeplitz_hash_gfni_two (d2, d3, m[0], 0);
  n_bytes -= 8;

  if (n_bytes > 0)
    {
      u64x8 zero = {};
      m += 1;
      d0 = (u8x64) u64x8_align_right (zero, d0, 1);
      d1 = (u8x64) u64x8_align_right (zero, d1, 1);
      d2 = (u8x64) u64x8_align_right (zero, d2, 1);
      d3 = (u8x64) u64x8_align_right (zero, d3, 1);
      goto last8;
    }

done:
  h = u64x8_hxor (h0);
  *hash0 = h;
  *hash1 = h >> 32;
  h = u64x8_hxor (h2);
  *hash2 = h;
  *hash3 = h >> 32;
#elif defined(CLIB_HAVE_VEC256)
  u8 *key = k->data;
  u64x4 v4, shift = { 0, 1, 2, 3 };
  u32x8 h0 = {}, h1 = {}, h2 = {}, h3 = {};

  while (n_bytes >= 4)
    {
      v4 = u64x4_splat (clib_net_to_host_u64 (*(u64u *) key)) << shift;

      h0 = toeplitz_hash_one_x8 (h0, v4, data0[0], 0);
      h1 = toeplitz_hash_one_x8 (h1, v4, data1[0], 0);
      h2 = toeplitz_hash_one_x8 (h2, v4, data2[0], 0);
      h3 = toeplitz_hash_one_x8 (h3, v4, data3[0], 0);

      h0 = toeplitz_hash_one_x8 (h0, v4, data0[1], 1);
      h1 = toeplitz_hash_one_x8 (h1, v4, data1[1], 1);
      h2 = toeplitz_hash_one_x8 (h2, v4, data2[1], 1);
      h3 = toeplitz_hash_one_x8 (h3, v4, data3[1], 1);

      h0 = toeplitz_hash_one_x8 (h0, v4, data0[2], 2);
      h1 = toeplitz_hash_one_x8 (h1, v4, data1[2], 2);
      h2 = toeplitz_hash_one_x8 (h2, v4, data2[2], 2);
      h3 = toeplitz_hash_one_x8 (h3, v4, data3[2], 2);

      h0 = toeplitz_hash_one_x8 (h0, v4, data0[3], 3);
      h1 = toeplitz_hash_one_x8 (h1, v4, data1[3], 3);
      h2 = toeplitz_hash_one_x8 (h2, v4, data2[3], 3);
      h3 = toeplitz_hash_one_x8 (h3, v4, data3[3], 3);

      data0 += 4;
      data1 += 4;
      data2 += 4;
      data3 += 4;
      key += 4;
      n_bytes -= 4;
    }

  if (n_bytes)
    {
      u64 v = (u64) clib_net_to_host_u32 ((u64) (*(u32u *) key)) << 32;
      v |= (u64) key[4] << 24;

      if (n_bytes == 3)
	{
	  v |= (u64) key[5] << 16;
	  v |= (u64) key[6] << 8;
	  v4 = u64x4_splat (v) << shift;
	  h0 = toeplitz_hash_one_x8 (h0, v4, data0[0], 0);
	  h1 = toeplitz_hash_one_x8 (h1, v4, data1[0], 0);
	  h2 = toeplitz_hash_one_x8 (h2, v4, data2[0], 0);
	  h3 = toeplitz_hash_one_x8 (h3, v4, data3[0], 0);

	  h0 = toeplitz_hash_one_x8 (h0, v4, data0[1], 1);
	  h1 = toeplitz_hash_one_x8 (h1, v4, data1[1], 1);
	  h2 = toeplitz_hash_one_x8 (h2, v4, data2[1], 1);
	  h3 = toeplitz_hash_one_x8 (h3, v4, data3[1], 1);

	  h0 = toeplitz_hash_one_x8 (h0, v4, data0[2], 2);
	  h1 = toeplitz_hash_one_x8 (h1, v4, data1[2], 2);
	  h2 = toeplitz_hash_one_x8 (h2, v4, data2[2], 2);
	  h3 = toeplitz_hash_one_x8 (h3, v4, data3[2], 2);
	}
      else if (n_bytes == 2)
	{
	  v |= (u64) key[5] << 16;
	  v4 = u64x4_splat (v) << shift;
	  h0 = toeplitz_hash_one_x8 (h0, v4, data0[0], 0);
	  h1 = toeplitz_hash_one_x8 (h1, v4, data1[0], 0);
	  h2 = toeplitz_hash_one_x8 (h2, v4, data2[0], 0);
	  h3 = toeplitz_hash_one_x8 (h3, v4, data3[0], 0);

	  h0 = toeplitz_hash_one_x8 (h0, v4, data0[1], 1);
	  h1 = toeplitz_hash_one_x8 (h1, v4, data1[1], 1);
	  h2 = toeplitz_hash_one_x8 (h2, v4, data2[1], 1);
	  h3 = toeplitz_hash_one_x8 (h3, v4, data3[1], 1);
	}
      else
	{
	  v4 = u64x4_splat (v) << shift;
	  h0 = toeplitz_hash_one_x8 (h0, v4, data0[0], 0);
	  h1 = toeplitz_hash_one_x8 (h1, v4, data1[0], 0);
	  h2 = toeplitz_hash_one_x8 (h2, v4, data2[0], 0);
	  h3 = toeplitz_hash_one_x8 (h3, v4, data3[0], 0);
	}
    }

  *hash0 = u32x8_hxor (h0);
  *hash1 = u32x8_hxor (h1);
  *hash2 = u32x8_hxor (h2);
  *hash3 = u32x8_hxor (h3);
#else
  u8 *key = k->data;
  u64 v, h0 = 0, h1 = 0, h2 = 0, h3 = 0;

  while (n_bytes >= 4)
    {
      v = clib_net_to_host_u64 (*(u64u *) key);

      for (u8 bit = 1 << 7; bit; bit >>= 1, v <<= 1)
	{
	  h0 ^= data0[0] & bit ? v : 0;
	  h1 ^= data1[0] & bit ? v : 0;
	  h2 ^= data2[0] & bit ? v : 0;
	  h3 ^= data3[0] & bit ? v : 0;
	}
      for (u8 bit = 1 << 7; bit; bit >>= 1, v <<= 1)
	{
	  h0 ^= data0[1] & bit ? v : 0;
	  h1 ^= data1[1] & bit ? v : 0;
	  h2 ^= data2[1] & bit ? v : 0;
	  h3 ^= data3[1] & bit ? v : 0;
	}
      for (u8 bit = 1 << 7; bit; bit >>= 1, v <<= 1)
	{
	  h0 ^= data0[2] & bit ? v : 0;
	  h1 ^= data1[2] & bit ? v : 0;
	  h2 ^= data2[2] & bit ? v : 0;
	  h3 ^= data3[2] & bit ? v : 0;
	}
      for (u8 bit = 1 << 7; bit; bit >>= 1, v <<= 1)
	{
	  h0 ^= data0[3] & bit ? v : 0;
	  h1 ^= data1[3] & bit ? v : 0;
	  h2 ^= data2[3] & bit ? v : 0;
	  h3 ^= data3[3] & bit ? v : 0;
	}

      data0 += 4;
      data1 += 4;
      data2 += 4;
      data3 += 4;
      key += 4;
      n_bytes -= 4;
    }

  if (n_bytes)
    {
      v = (u64) clib_net_to_host_u32 ((u64) (*(u32u *) key)) << 32;
      v |= (u64) key[4] << 24;
      for (u8 bit = 1 << 7; bit; bit >>= 1, v <<= 1)
	{
	  h0 ^= data0[0] & bit ? v : 0;
	  h1 ^= data1[0] & bit ? v : 0;
	  h2 ^= data2[0] & bit ? v : 0;
	  h3 ^= data3[0] & bit ? v : 0;
	}
      if (n_bytes > 1)
	{
	  v |= (u64) key[5] << 24;
	  for (u8 bit = 1 << 7; bit; bit >>= 1, v <<= 1)
	    {
	      h0 ^= data0[1] & bit ? v : 0;
	      h1 ^= data1[1] & bit ? v : 0;
	      h2 ^= data2[1] & bit ? v : 0;
	      h3 ^= data3[1] & bit ? v : 0;
	    }
	}
      if (n_bytes > 2)
	{
	  v |= (u64) key[6] << 24;
	  for (u8 bit = 1 << 7; bit; bit >>= 1, v <<= 1)
	    {
	      h0 ^= data0[2] & bit ? v : 0;
	      h1 ^= data1[2] & bit ? v : 0;
	      h2 ^= data2[2] & bit ? v : 0;
	      h3 ^= data3[2] & bit ? v : 0;
	    }
	}
    }
  *hash0 = h0 >> 32;
  *hash1 = h1 >> 32;
  *hash2 = h2 >> 32;
  *hash3 = h3 >> 32;
#endif
}

#endif
