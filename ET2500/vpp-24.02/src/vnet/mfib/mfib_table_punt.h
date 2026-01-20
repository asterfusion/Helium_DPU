#ifndef MFIB_TABLE_PUNT_H
#define MFIB_TABLE_PUNT_H

#include <stdbool.h>
#include <stdint.h>
#include <vnet/mfib/mfib_itf.h>
#include <vnet/mfib/mfib_entry.h>
#include <vnet/dpo/replicate_dpo.h>
#include <vnet/mfib/ip4_mfib.h>
#include <vnet/mfib/ip6_mfib.h>
#include <vnet/mfib/mfib_signal.h>
#include <vnet/fib/ip4_fib.h>
#include <vnet/fib/ip6_fib.h>
#include <vnet/ip/ip4.h>
#include <vnet/vnet.h>

extern int table_punt_array_init(void);

extern int table_punt_array_set(u32 table_id, bool punt_enabled);

extern bool table_punt_array_get(u32 table_id);

#endif