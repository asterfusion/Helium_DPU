/**
 * @file
 * @brief NAT46 DB
 */
#ifndef __included_nat46_db_h__
#define __included_nat46_db_h__

#include <vppinfra/bihash_24_8.h>
#include <vppinfra/bihash_48_8.h>
#include <nat/nat.h>
#include <vppinfra/tw_timer_1t_3w_64sl.h>


typedef struct
{
  union
  {
    struct
    {
      ip46_address_t addr;
      u32 fib_index;
      u16 port;
      u8 proto;
      u8 rsvd;
    };
    u64 as_u64[3];
  };
} nat46_db_bib_entry_key_t;

/* *INDENT-OFF* */
typedef CLIB_PACKED(struct
{
  ip4_address_t in_addr;
  ip6_address_t out_addr;
  u16 in_port;
  u16 out_port;
  u32 fib_index;
  u32 ses_num;
  u8 proto;
  u8 is_static;
}) nat46_db_bib_entry_t;
/* *INDENT-ON* */

typedef struct
{
  /* BIBs */
/* *INDENT-OFF* */
#define _(N, i, n, s) \
  nat46_db_bib_entry_t *_##n##_bib;
  foreach_snat_protocol
#undef _
/* *INDENT-ON* */
  nat46_db_bib_entry_t *_unk_proto_bib;

  /* BIB lookup */
  clib_bihash_24_8_t in2out;
  clib_bihash_24_8_t out2in;

  u32 limit;
  u32 bib_entries_num;
} nat46_db_bib_t;

typedef struct
{
  union
  {
    struct
    {
      ip46_address_t l_addr;
      ip46_address_t r_addr;
      u32 fib_index;
      u16 l_port;
      u16 r_port;
      u8 proto;
      u8 rsvd[7];
    };
    u64 as_u64[6];
  };
} nat46_db_st_entry_key_t;

/* *INDENT-OFF* */
typedef CLIB_PACKED(struct
{
  ip4_address_t in_r_addr;
  ip6_address_t out_r_addr;
  u16 r_port;
  u32 bibe_index;
  u32 expire;
  u8 proto;
  u8 tcp_state;
  u8 is_no_pat;
  u32 worker_index;
  /* handle needed to call timer */
  u32 session_timer_handle;
}) nat46_db_st_entry_t;
/* *INDENT-ON* */

typedef struct
{
  /* session tables */
/* *INDENT-OFF* */
#define _(N, i, n, s) \
  nat46_db_st_entry_t *_##n##_st;
  foreach_snat_protocol
#undef _
/* *INDENT-ON* */
  nat46_db_st_entry_t *_unk_proto_st;

  /* session lookup */
  clib_bihash_48_8_t in2out;
  clib_bihash_48_8_t out2in;

  u32 limit;
  u32 st_entries_num;
} nat46_db_st_t;

typedef nat46_db_bib_entry_key_t nat46_db_dynamic_no_pat_key_t;
typedef struct
{
  /* Main lookup tables no pat*/
  clib_bihash_24_8_t dynamic_mapping_by_no_pat;
  /* dynamic no pat mapping pool*/
  u32 dynamic_no_pat_mappings_cnt;
} nat46_db_dynamic_no_pat_t;

typedef struct
{
  union
  {
    struct
    {
      ip46_address_t addr;
      u32 fib_index;
      u8 proto;
      u8 rsvd8;
      u16 rsvd16;
    };
    u64 as_u64[3];
  };
} nat46_remote_mapping_key_t;

/* *INDENT-OFF* */
typedef CLIB_PACKED(struct
{
  ip4_address_t l_addr;
  ip6_address_t r_addr;
  u32 fib_index;
  u8 proto;
}) nat46_remote_mapping_entry_t;
/* *INDENT-ON* */

typedef struct
{
  /* dynamic no pat mapping pool*/
  nat46_remote_mapping_entry_t *mapping_entrys;
  /* lookup tables ip4toip6*/
  clib_bihash_24_8_t remote_ip4toip6;
  /* lookup tables ip6toip4*/
  clib_bihash_24_8_t remote_ip6toip4;
} nat46_db_remote_mapping_t;

struct nat46_db_s;

/**
 * @brief Call back function to free NAT46 pool address and port when BIB
 * entry is deleted.
 */
typedef void (*nat46_db_free_addr_port_function_t) (struct nat46_db_s * db,
						    ip6_address_t * addr,
						    u16 port, u8 proto);

typedef struct nat46_db_s
{
  nat46_db_bib_t bib;
  nat46_db_st_t st;

  /* Session Timer */
  TWT (tw_timer_wheel) *timers_per_worker;

  nat46_db_free_addr_port_function_t free_addr_port_cb;
  u8 addr_free;
} nat46_db_t;

/**
 * @brief Initialize NAT46 DB.
 *
 * @param max_st_per_worker nat46 st max limit.
 * @param db NAT46 DB.
 * @param bib_buckets Number of BIB hash buckets.
 * @param bib_memory_size Memory size of BIB hash.
 * @param st_buckets Number of session table hash buckets.
 * @param st_memory_size Memory size of session table hash.
 * @param free_addr_port_cb Call back function to free address and port.
 *
 * @returns 0 on success, non-zero value otherwise.
 */
int nat46_db_init (u32 max_st_per_worker, nat46_db_t * db, u32 bib_buckets, u32 bib_memory_size,
		   u32 st_buckets, u32 st_memory_size,
		   nat46_db_free_addr_port_function_t free_addr_port_cb);

/**
 * @brief submit or update NAT46 ste timer.
 *
 * @param db NAT46 DB.
 * @param st BIB entry.
 */
void nat46_submit_or_update_session_timer(nat46_db_t * db, nat46_db_st_entry_t *ste);


/**
 * @brief delete NAT46 ste timer.
 *
 * @param db NAT46 DB.
 * @param st BIB entry.
 */
void nat46_delete_session_timer(nat46_db_t * db, nat46_db_st_entry_t *ste);

/**
 * @brief Create new NAT46 BIB entry.
 *
 * @param thread_index thread index.
 * @param db NAT46 DB.
 * @param in_addr Inside IPv4 address.
 * @param out_addr Outside IPv6 address.
 * @param in_port Inside port number.
 * @param out_port Outside port number.
 * @param fib_index FIB index.
 * @param proto L4 protocol.
 * @param is_static 1 if static, 0 if dynamic.
 *
 * @returns BIB entry on success, 0 otherwise.
 */
nat46_db_bib_entry_t *nat46_db_bib_entry_create (u32 thread_index,
						 nat46_db_t * db,
						 ip4_address_t * in_addr,
						 ip6_address_t * out_addr,
						 u16 in_port, u16 out_port,
						 u32 fib_index, u8 proto,
						 u8 is_static);

/**
 * @brief Free NAT46 BIB entry.
 *
 * @param thread_index thread index.
 * @param db NAT46 DB.
 * @param bibe BIB entry.
 */
void nat46_db_bib_entry_free (u32 thread_index, nat46_db_t * db,
			      nat46_db_bib_entry_t * bibe);

/**
 * @brief Call back function when walking NAT46 BIB, non-zero
 * return value stop walk.
 */
typedef int (*nat46_db_bib_walk_fn_t) (nat46_db_bib_entry_t * bibe, void *ctx);

/**
 * @brief Walk NAT46 BIB.
 *
 * @param db NAT46 DB.
 * @param proto BIB L4 protocol:
 *  - 255 all BIBs
 *  - 6 TCP BIB
 *  - 17 UDP BIB
 *  - 1/58 ICMP BIB
 *
 * u - otherwise "unknown" protocol BIB
 * @param fn The function to invoke on each entry visited.
 * @param ctx A context passed in the visit function.
 */
void nat46_db_bib_walk (nat46_db_t * db, u8 proto,
			nat46_db_bib_walk_fn_t fn, void *ctx);

/**
 * @brief Find NAT46 BIB entry.
 *
 * @param db NAT46 DB.
 * @param addr IP address.
 * @param port Port number.
 * @param proto L4 protocol.
 * @param fib_index FIB index.
 * @param is_ip6 1 if find by IPv6 (inside) address, 0 by IPv4 (outside).
 *
 * @return BIB entry if found.
 */
nat46_db_bib_entry_t *nat46_db_bib_entry_find (nat46_db_t * db,
					       ip46_address_t * addr,
					       u16 port,
					       u8 proto,
					       u32 fib_index, u8 is_ip6);

/**
 * @brief Get BIB entry by index and protocol.
 *
 * @param db NAT46 DB.
 * @param proto L4 protocol.
 * @param bibe_index BIB entry index.
 *
 * @return BIB entry if found.
 */
nat46_db_bib_entry_t *nat46_db_bib_entry_by_index (nat46_db_t * db,
						   u8 proto, u32 bibe_index);
/**
 * @brief Create new NAT46 session table entry.
 *
 * @param thread_index thread index.
 * @param db NAT46 DB.
 * @param bibe Corresponding BIB entry.
 * @param in_r_addr Inside IPv6 address of the remote host.
 * @param out_r_addr Outside IPv4 address of the remote host.
 * @param r_port Remote host port number.
 *
 * @returns BIB entry on success, 0 otherwise.
 */
nat46_db_st_entry_t *nat46_db_st_entry_create (u32 thread_index,
					       nat46_db_t * db,
					       nat46_db_bib_entry_t * bibe,
					       ip4_address_t * in_r_addr,
					       ip6_address_t * out_r_addr,
					       u16 r_port);

/**
 * @brief Free NAT46 session table entry.
 *
 * @param thread_index thread index.
 * @param db NAT46 DB.
 * @param ste Session table entry.
 */
void nat46_db_st_entry_free (u32 thread_index, nat46_db_t * db,
			     nat46_db_st_entry_t * ste);

/**
 * @brief Find NAT46 session table entry.
 *
 * @param db NAT46 DB.
 * @param l_addr Local host address.
 * @param r_addr Remote host address.
 * @param l_port Local host port number.
 * @param r_port Remote host port number.
 * @param proto L4 protocol.
 * @param fib_index FIB index.
 * @param is_ip6 1 if find by IPv6 (inside) address, 0 by IPv4 (outside).
 *
 * @return BIB entry if found.
 */
nat46_db_st_entry_t *nat46_db_st_entry_find (nat46_db_t * db,
					     ip46_address_t * l_addr,
					     ip46_address_t * r_addr,
					     u16 l_port, u16 r_port,
					     u8 proto,
					     u32 fib_index, u8 is_ip6);

/**
 * @brief Call back function when walking NAT46 session table, non-zero
 * return value stop walk.
 */
typedef int (*nat46_db_st_walk_fn_t) (nat46_db_st_entry_t * ste, void *ctx);

/**
 * @brief Walk NAT46 session table.
 *
 * @param db NAT46 DB.
 * @param proto L4 protocol:
 *  - 255 all session tables
 *  - 6 TCP session table
 *  - 17 UDP session table
 *  - 1/58 ICMP session table
 *  - otherwise "unknown" protocol session table
 * @param fn The function to invoke on each entry visited.
 * @param ctx A context passed in the visit function.
 */
void nat46_db_st_walk (nat46_db_t * db, u8 proto,
		       nat46_db_st_walk_fn_t fn, void *ctx);

/**
 * @brief Walk Free expired session entries in session tables.
 *
 * @param thread_index thread index.
 * @param db NAT46 DB.
 * @param now Current time.
 *
 * @return free expired num
 */
u32 nat46_db_st_free_walk_expired (u32 thread_index, nat46_db_t * db, u32 now);

/**
 * @brief Timer Free expired session entries in session tables.
 *
 * @param thread_index thread index.
 * @param db NAT46 DB.
 * @param now Current time.
 *
 * @return free expired num
 */
u32 nat46_db_st_free_timer_expired (u32 thread_index, nat46_db_t * db, u32 now);

/**
 * @brief Free sessions using specific outside address.
 *
 * @param thread_index thread index.
 * @param db NAT46 DB.
 * @param out_addr Outside address to match.
 * @param plen     prefix len.
 */
void nat46_db_free_out_addr (u32 thread_index, nat46_db_t * db,
			     ip6_address_t * out_addr, u32 plen);

/*
 * @brief Get ST entry index.
 *
 * @param db NAT46 DB.
 * @param ste ST entry.
 *
 * @return ST entry index on success, ~0 otherwise.
 */
u32 nat46_db_st_entry_get_index (nat46_db_t * db, nat46_db_st_entry_t * ste);

/**
 * @brief Get ST entry by index and protocol.
 *
 * @param db NAT46 DB.
 * @param proto L4 protocol.
 * @param bibe_index ST entry index.
 *
 * @return BIB entry if found.
 */
nat46_db_st_entry_t *nat46_db_st_entry_by_index (nat46_db_t * db,
						 u8 proto, u32 ste_index);

/**
 * @brief create dynamic_no_pat.
 *
 * @param fib_index FIB index.
 * @param ste.
 * @param addr_6 nat out ipv6 address.
 * @param port   nat out port number.
 * @param proto L4 protocol.
 *
 */
void nat46_db_dynamic_no_pat_create(u32 fib_index, nat46_db_st_entry_t *ste,
        ip6_address_t * addr_6, u16 port, u8 proto);

/**
 * @brief Free NAT46 no pat .
 *
 * @param bibe BIB entry.
 *
 */
void nat46_db_dynamic_no_pat_free (nat46_db_bib_entry_t * bibe);


int nat46_db_remote_mapping_find_and_map46(u32 fib_index, 
        ip4_address_t *in_ip4, ip6_address_t *out_ip6, u8 proto);

int nat46_db_remote_mapping_find_and_map64(u32 fib_index, 
        ip6_address_t *in_ip6, ip4_address_t *out_ip4,  u8 proto);

typedef int (*nat46_db_remote_mapping_walk_fn_t) (nat46_remote_mapping_entry_t *mapping, void *ctx);

void nat46_db_remote_mapping_walk (nat46_db_remote_mapping_t *mappings,
        nat46_db_remote_mapping_walk_fn_t fn, void *ctx);

#endif /* __included_nat46_db_h__ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
