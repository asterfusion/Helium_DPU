#ifndef __included_softforward_h__
#define __included_softforward_h__

#include <vnet/vnet.h>
#include <vnet/ip/ip.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/api_errno.h>
#include <vppinfra/elog.h>
#include <vppinfra/bihash_8_8.h>
#include <vppinfra/dlist.h>
#include <vppinfra/error.h>
#include <vppinfra/pool.h>
#include <vlibapi/api.h>
#include <vlib/log.h>

#define MAX_SOFTFORWARD_MAPPING_CNT  64
#define MAX_SOFTFORWARD_MAPPING_NAME_LENGHT 20

#define MAX_SOFTFORWARD_MAPPING_BUCKET  (1024 * 16)
#define MAX_SOFTFORWARD_MAPPING_MEMORY_SIZE  (1024 * 16 * 4 * 64 + 1024 * 64)

/* session key (4-tuple) */
typedef struct
{
    union
    {
        struct
        {
            ip4_address_t daddr;
            u32 reserved;
        };
        u64 as_u64;
    };
} softforward_mapping_key_t;

typedef struct
{
    ip4_address_t daddr;
    ip4_address_t map_daddr;
    ip4_address_t map_saddr;

    u32 forward_port;
    u32 match_cnt;

} softforward_map_entry_t;

typedef struct
{
    u8 name[MAX_SOFTFORWARD_MAPPING_NAME_LENGHT];
    /* lookup tables*/
    clib_bihash_8_8_t map_softforward_table;
    /* mapping entry pool */
    softforward_map_entry_t *mapping_entrys;
    /* mapping self index in mapping pool*/
    u32 pool_index;

} softforward_mapping_t;

typedef struct softforward_main_s
{
  /* mapping pool */
  softforward_mapping_t *mapping_pool;

  /* mapping bind */
  u32 *mapping_interfaces; //sw_if_index -> mapping_pool_idx

  /* plugin node index */
  u32 softforward_node_index;

  /* hash config*/
  u32 mapping_hash_bucket;
  u32 mapping_hash_memory;

  /* API message ID base */
  u16 msg_id_base;

  /* convenience */
  vlib_main_t *vlib_main;
  vnet_main_t *vnet_main;
  api_main_t *api_main;

} softforward_main_t;

extern softforward_main_t sf_main;


softforward_map_entry_t *softforward_mapping_match (softforward_main_t *sfm,
               u32 sw_if_index,
			   softforward_mapping_key_t *match, 
               u32 thread_index);

softforward_mapping_t *
softforward_get_mapping_by_name(softforward_main_t * sfm, u8 *mapping_name);


int softforward_add_del_mapping (softforward_main_t * sfm, 
               u8 *mapping_name, 
               int is_add);

int softforward_add_del_mapping_entrys(softforward_main_t * sfm, u8 *mapping_name, 
        ip4_address_t *dst_addr, ip4_address_t *dst_map_addr, 
        u32 forward_pannel_port, ip4_address_t *modify_src_addr, int is_add);

int softforward_interface_bind_unbind(softforward_main_t * sfm,
            u32 sw_if_index, softforward_mapping_t *mapping, u8 is_unbind);


#endif /* __included_softforward_h__ */
