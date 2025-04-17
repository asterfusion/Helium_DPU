/**
 * @file NAT plugin config declarations
 */
#ifndef __included_nat_config_h__
#define __included_nat_config_h__

/* if use walk all session to expire define it*/
//#define USER_WALK_EXPIRE_FLAG 

/* default session timeouts */
#define SNAT_UDP_TIMEOUT 300
#define SNAT_TCP_TRANSITORY_TIMEOUT 240
#define SNAT_TCP_ESTABLISHED_TIMEOUT 7440
#define SNAT_ICMP_TIMEOUT 60

/* number of worker handoff frame queue elements */
#define NAT_FQ_NELTS 64

/* NAT buffer flags */
#define SNAT_FLAG_HAIRPINNING (1 << 0)


#define NAT_PORT_PER_THREAD (0xffff - 1024)


/* Addresses Pool config */
#define MAX_ADDRESSES_POOL_CNT (~0) //no limit 
#define MAX_ADDRESSES_POOL_NAME_LEN (32)

#define NAT_HASH_MEMEORY_REDUNDANCE_SIZE (1024*1024) // 1MB

/* NAT44*/
#define NAT44_PER_WORKER_MAX_SESSION            (1024*1024)

#define NAT44_TRANSLATION_BUCKETS               (1024 * 256) //262144 --4--> 1048576
#define NAT44_TRANSLATION_MEMORY_SIZE           ((64 << 20) + NAT_HASH_MEMEORY_REDUNDANCE_SIZE)

#define NAT44_USER_BUCKETS                      (1024 * 256) //262144 --4--> 1048576
#define NAT44_USER_MEMORY_SIZE                  ((64 << 20) + NAT_HASH_MEMEORY_REDUNDANCE_SIZE)

#define NAT44_STATIC_MAPPING_BUCKETS            (4096)  //4096--4--> 16384 
#define NAT44_STATIC_MAPPING_MEMORY_SIZE        ((64 << 14) + NAT_HASH_MEMEORY_REDUNDANCE_SIZE)

#define NAT44_DYNAMIC_MAPPING_BY_NO_PAT_BUCKETS             (1024 * 1024 * 2) //2096912 --4--> 8387648
#define NAT44_DYNAMIC_MAPPING_BY_NO_PAT_MEMORY_SIZE         (1024 * 1024 * 10 * 64 + NAT_HASH_MEMEORY_REDUNDANCE_SIZE)

#define NAT44_EXPIRE_WALK_INTERVAL (10.0)

//limit
#define NAT44_MAX_TRANSLATIONS_PER_USER (2048)

/* NAT44 end */

/* NAT64 memory config*/
#define NAT64_PER_WORKER_MAX_ST                 (1024*1024)

#define NAT64_BIB_BUCKETS                       (1024 * 256) //262144 --4--> 1048576
#define NAT64_BIB_MEMORY_SIZE                   ((64 << 20) + NAT_HASH_MEMEORY_REDUNDANCE_SIZE)

#define NAT64_ST_BUCKETS                        (1024 * 256) //262144 --4--> 1048576
#define NAT64_ST_MEMORY_SIZE                    ((64 << 20) + NAT_HASH_MEMEORY_REDUNDANCE_SIZE)

#define NAT64_DYNAMIC_MAPPING_BY_NO_PAT_BUCKETS             (1024 * 1024 * 2)
#define NAT64_DYNAMIC_MAPPING_BY_NO_PAT_MEMORY_SIZE         (1024 * 1024 * 10 * 64 + NAT_HASH_MEMEORY_REDUNDANCE_SIZE)

#define NAT64_EXPIRE_WALK_INTERVAL (10.0)

/* NAT64 end */


/* NAT46*/
#define NAT46_PER_WORKER_MAX_ST                 (1024*1024)

#define NAT46_BIB_BUCKETS                       (1024 * 256)
#define NAT46_BIB_MEMORY_SIZE                   ((64 << 20) + NAT_HASH_MEMEORY_REDUNDANCE_SIZE)

#define NAT46_ST_BUCKETS                        (1024 * 256)
#define NAT46_ST_MEMORY_SIZE                    ((64 << 20) + NAT_HASH_MEMEORY_REDUNDANCE_SIZE)

#define NAT46_REMOTE_MAPPING_BUCKETS            (4096)
#define NAT46_REMOTE_MAPPING_MEMORY_SIZE        ((16 << 16) + NAT_HASH_MEMEORY_REDUNDANCE_SIZE)

#define NAT46_DYNAMIC_MAPPING_BY_NO_PAT_BUCKETS         (1024 * 1024 * 2)
#define NAT46_DYNAMIC_MAPPING_BY_NO_PAT_MEMORY_SIZE     (1024 * 1024 * 10 * 64 + NAT_HASH_MEMEORY_REDUNDANCE_SIZE)

//limit
#define NAT46_MAX_ADDR_POOL_SHIFT (1) //256

#define NAT46_EXPIRE_WALK_INTERVAL (10.0)

/* NAT46 end */



#endif /* __included_nat_config_h__ */
