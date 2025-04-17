#include <vnet/vnet.h>
#include <vnet/ip/ip.h>
#include <vnet/ip/ip4.h>
#include <vnet/fib/fib_table.h>
#include <vnet/fib/ip4_fib.h>
#include <vnet/plugin/plugin.h>
#include <softforward/softforward.h>
#include <vpp/app/version.h>

softforward_main_t sf_main;

/* *INDENT-OFF* */
/* Hook up input features */
VNET_FEATURE_INIT (softforward_node, static) = {
  .arc_name = "ip4-unicast",
  .node_name = "softforward",
  .runs_after = VNET_FEATURES ("acl-plugin-in-ip4-fa"),
};

void
softforward_add_del_addr_to_fib (ip4_address_t * addr, u8 p_len, u32 sw_if_index,
			  int is_add)
{
    fib_prefix_t prefix = {
        .fp_len = p_len,
        .fp_proto = FIB_PROTOCOL_IP4,
        .fp_addr = {
            .ip4.as_u32 = addr->as_u32,
        },
    };
    u32 fib_index = ip4_fib_table_get_index_for_sw_if_index (sw_if_index);

    if (is_add)
        fib_table_entry_update_one_path (fib_index,
                &prefix,
                FIB_SOURCE_PLUGIN_LOW,
                (FIB_ENTRY_FLAG_CONNECTED |
                 FIB_ENTRY_FLAG_LOCAL |
                 FIB_ENTRY_FLAG_EXCLUSIVE),
                DPO_PROTO_IP4,
                NULL,
                sw_if_index,
                ~0, 1, NULL, FIB_ROUTE_PATH_FLAG_NONE);
    else
        fib_table_entry_delete (fib_index, &prefix, FIB_SOURCE_PLUGIN_LOW);
}

softforward_map_entry_t *
softforward_mapping_match (softforward_main_t *sfm,
               u32 sw_if_index,
			   softforward_mapping_key_t *match, 
               u32 thread_index)
{
    u32 mapping_idx;
    clib_bihash_kv_8_8_t kv, value;
    softforward_mapping_t *mapping;
    softforward_map_entry_t *e;

    mapping_idx = sfm->mapping_interfaces[sw_if_index];
    if (mapping_idx == 0)
        return NULL;

    mapping =  pool_elt_at_index(sfm->mapping_pool, mapping_idx - 1);

    kv.key = match->as_u64;
    if (clib_bihash_search_8_8 (&mapping->map_softforward_table, &kv, &value))
        return NULL;

    e = pool_elt_at_index (mapping->mapping_entrys, value.value);

    clib_atomic_add_fetch(&e->match_cnt, 1);

    return e;
}

softforward_mapping_t *
softforward_get_mapping_by_name(softforward_main_t * sfm, u8 *mapping_name)
{
    softforward_mapping_t *check_mapping = NULL;
    pool_foreach (check_mapping, sfm->mapping_pool,
    ({
       if (clib_memcmp(check_mapping->name,  mapping_name, vec_len (mapping_name)) == 0)
           return check_mapping;
    }));
    return NULL;
}

int
softforward_add_del_mapping (softforward_main_t * sfm, u8 *mapping_name, int is_add)
{
    softforward_mapping_t *mapping = NULL;
    char mapping_table_name[MAX_SOFTFORWARD_MAPPING_NAME_LENGHT + 64];

    memset(mapping_table_name, 0 , sizeof(mapping_table_name));

    if (is_add)
    {
        /* check old mapping  */
        if (softforward_get_mapping_by_name(sfm, mapping_name))
            return VNET_API_ERROR_VALUE_EXIST;

        if(pool_elts(sfm->mapping_pool) > MAX_SOFTFORWARD_MAPPING_CNT)
            return VNET_API_ERROR_INVALID_VALUE;

        pool_get (sfm->mapping_pool, mapping);
        clib_memset(mapping, 0 , sizeof(softforward_mapping_t));
        clib_memcpy (mapping->name, mapping_name, vec_len (mapping_name));
        mapping->pool_index = mapping - sfm->mapping_pool;

        sprintf(mapping_table_name, "sfm-mapping-%s", mapping_name);

        /* init mapping hash table*/
        clib_bihash_init_8_8 (&mapping->map_softforward_table, mapping_table_name, 
                    sfm->mapping_hash_bucket, sfm->mapping_hash_memory);
    }
    else
    {
        //check
        mapping = softforward_get_mapping_by_name(sfm, mapping_name);
        if (mapping)
        {
            u32 *pool_index;
            /* check sw_iface used */
            vec_foreach(pool_index, sfm->mapping_interfaces)
            {
                if( mapping->pool_index + 1 == pool_index[0] )
                    return VNET_API_ERROR_RSRC_IN_USE;
            }

            /* free hash and mapping entry pool */
            clib_bihash_free_8_8(&mapping->map_softforward_table);
            pool_free(mapping->mapping_entrys);

            /* Recycle mapping node */
            pool_put (sfm->mapping_pool, mapping);
        }
        else
            return VNET_API_ERROR_NO_SUCH_ENTRY;
    }
    return 0;
}

int 
softforward_add_del_mapping_entrys(softforward_main_t * sfm, u8 *mapping_name, 
        ip4_address_t *dst_addr, ip4_address_t *dst_map_addr, 
        u32 forward_pannel_port, ip4_address_t *modify_src_addr, int is_add)
{
    softforward_mapping_t *mapping = NULL;
    softforward_map_entry_t *mapping_entry = NULL;
    softforward_mapping_key_t key;
    clib_bihash_kv_8_8_t kv, value;
    u32 sw_if_index;

    mapping = softforward_get_mapping_by_name(sfm, mapping_name);

    if (mapping == NULL)
        return VNET_API_ERROR_NO_SUCH_NODE;

    /* check entry exist*/
    key.daddr = *dst_addr;
    key.reserved = 0;

    kv.key = key.as_u64;

    if (!clib_bihash_search_8_8 (&mapping->map_softforward_table, &kv, &value))
        mapping_entry = pool_elt_at_index (mapping->mapping_entrys, value.value);

    if (is_add)
    {
        if (mapping_entry)
            return VNET_API_ERROR_VALUE_EXIST;

        pool_get(mapping->mapping_entrys, mapping_entry);
        memset(mapping_entry, 0 , sizeof(softforward_map_entry_t));

        mapping_entry->daddr = *dst_addr;
        mapping_entry->map_daddr = *dst_map_addr;
        mapping_entry->forward_port = forward_pannel_port;
        if (modify_src_addr)
            mapping_entry->map_saddr = *modify_src_addr;

        kv.value = mapping_entry - mapping->mapping_entrys;
        clib_bihash_add_del_8_8 (&mapping->map_softforward_table, &kv, 1);
        
        for(sw_if_index = 0; sw_if_index < vec_len(sfm->mapping_interfaces); sw_if_index++)
        {
#if 0
            if( mapping->pool_index == 
               (sfm->mapping_interfaces[sw_if_index] - 1))
                softforward_add_del_addr_to_fib(dst_map_addr, 32, sw_if_index, is_add);
#endif
        }
    }
    else
    {
        if (mapping_entry)
        {
            clib_bihash_add_del_8_8 (&mapping->map_softforward_table, &kv, 0);
            pool_put(mapping->mapping_entrys, mapping_entry);

#if 0
            for(sw_if_index = 0; sw_if_index < vec_len(sfm->mapping_interfaces); sw_if_index++)
            {
                if( mapping->pool_index == 
                        (sfm->mapping_interfaces[sw_if_index] - 1))
                    softforward_add_del_addr_to_fib(dst_map_addr, 32, sw_if_index, is_add);
            }
#endif
        }
        else
            return VNET_API_ERROR_NO_SUCH_ENTRY;
    }

    return 0;
}

int
softforward_interface_bind_unbind(softforward_main_t * sfm,
            u32 sw_if_index, softforward_mapping_t *mapping,
            u8 is_unbind)
{
    /* check */
    vec_validate(sfm->mapping_interfaces, sw_if_index);

    if (is_unbind)
    {
        sfm->mapping_interfaces[sw_if_index] = 0;
        return vnet_feature_enable_disable ("ip4-unicast", "softforward", sw_if_index, 0, 0, 0);
    }

    sfm->mapping_interfaces[sw_if_index] = (mapping - sfm->mapping_pool) + 1;
    return vnet_feature_enable_disable ("ip4-unicast", "softforward", sw_if_index, 1, 0, 0);
}

static clib_error_t *
softforward_init (vlib_main_t * vm)
{
    clib_error_t *error = 0;
    softforward_main_t *sfm = &sf_main;
    vlib_node_t *node;

    sfm->vlib_main = vm;
    sfm->vnet_main = vnet_get_main ();

    node = vlib_get_node_by_name (vm, (u8 *) "softforward");
    sfm->softforward_node_index = node->index;

    return error;
}

VLIB_INIT_FUNCTION (softforward_init);


static clib_error_t *
softforward_config (vlib_main_t * vm, unformat_input_t * input)
{
    softforward_main_t *sfm = &sf_main;
    u32 mapping_hash_buckets = MAX_SOFTFORWARD_MAPPING_BUCKET;
    u32 mapping_hash_memory_size = MAX_SOFTFORWARD_MAPPING_MEMORY_SIZE;

    while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
        if (unformat(input, "mapping hash buckets %d", &mapping_hash_buckets))
            ;
        else if (unformat (input, "mapping hash memory %d", &mapping_hash_memory_size))
            ;
        else
            return clib_error_return (0, "unknown input '%U'", format_unformat_error, input);
    }

    sfm->mapping_hash_bucket = mapping_hash_buckets;
    sfm->mapping_hash_memory = mapping_hash_memory_size;
    return 0;
}

VLIB_CONFIG_FUNCTION (softforward_config, "softforward");
