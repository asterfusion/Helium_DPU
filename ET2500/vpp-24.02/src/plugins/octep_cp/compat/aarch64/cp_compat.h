/*
 * Copyright (c) 2023 Marvell.
 * SPDX-License-Identifier: Apache-2.0
 * https://spdx.org/licenses/Apache-2.0.html
 */

#ifndef __CP_COMPAT_H__
#define __CP_COMPAT_H__

#include <stdlib.h>
#include <string.h>

#define CP_ETHER_ADDR_LEN	  6    /**< Length of Ethernet address. */
#define CP_ETHER_GROUP_ADDR	  0x01 /**< Mcast or bcast Eth. addr. */
#define CP_ETHER_LOCAL_ADMIN_ADDR 0x02 /**< Locally assigned Eth. addr. */

#define __cp_always_inline inline __attribute__ ((always_inline))

#define cp_rmb()    asm volatile("dmb oshld" : : : "memory")
#define cp_io_rmb() cp_rmb ()
#define cp_wmb()    asm volatile("dmb oshst" : : : "memory")
#define cp_io_wmb() cp_wmb ()

static __cp_always_inline uint32_t
cp_read32_relaxed (const volatile void *addr)
{
  uint32_t val;

  asm volatile("ldr %w[val], [%x[addr]]" : [val] "=r"(val) : [addr] "r"(addr));
  return val;
}

static __cp_always_inline uint32_t
cp_read32 (const volatile void *addr)
{
  uint32_t val;
  val = cp_read32_relaxed (addr);
  cp_io_rmb ();
  return val;
}

static __cp_always_inline uint64_t
cp_read64_relaxed (const volatile void *addr)
{
  uint64_t val;

  asm volatile("ldr %x[val], [%x[addr]]" : [val] "=r"(val) : [addr] "r"(addr));
  return val;
}

static __cp_always_inline uint64_t
cp_read64 (const volatile void *addr)
{
  uint64_t val;
  val = cp_read64_relaxed (addr);
  cp_io_rmb ();
  return val;
}

static __cp_always_inline void
cp_write32_relaxed (uint32_t val, volatile void *addr)
{
  asm volatile("str %w[val], [%x[addr]]" : : [val] "r"(val), [addr] "r"(addr));
}

static __cp_always_inline void
cp_write32 (uint32_t value, volatile void *addr)
{
  cp_io_wmb ();
  cp_write32_relaxed (value, addr);
}

static __cp_always_inline void
cp_write64_relaxed (uint64_t val, volatile void *addr)
{
  asm volatile("str %x[val], [%x[addr]]" : : [val] "r"(val), [addr] "r"(addr));
}

static __cp_always_inline void
cp_write64 (uint64_t value, volatile void *addr)
{
  cp_io_wmb ();
  cp_write64_relaxed (value, addr);
}

static inline void
cp_eth_random_addr (uint8_t *addr)
{
  uint64_t r = rand ();
  uint8_t *p = (uint8_t *) &r;

  memcpy (addr, p, CP_ETHER_ADDR_LEN);
  addr[0] &= (uint8_t) ~CP_ETHER_GROUP_ADDR; /* clear multicast bit */
  addr[0] |= CP_ETHER_LOCAL_ADMIN_ADDR;	     /* set local assignment bit */
}

#endif /* __CP_COMPAT_H__ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
