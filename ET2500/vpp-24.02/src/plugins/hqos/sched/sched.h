/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2024-2027 Asterfusion Network
 */

#ifndef included_hqos_sched_h
#define included_hqos_sched_h

/**
 * @file
 * Hierarchical Scheduler
 *
 * The hierarchical scheduler prioritizes the transmission of packets
 * from different users and traffic classes according to the Service
 * Level Agreements (SLAs) defined for the current network node.
 *
 * The scheduler supports thousands of packet queues grouped under a
 * 5-level hierarchy:
 *     1. Port:
 *           - Typical usage: output Ethernet port;
 *           - Multiple ports are scheduled in round robin order with
 *      equal priority;
 *     2. Subport:
 *           - Typical usage: group of users;
 *           - Traffic shaping using the token bucket algorithm
 *      (one bucket per subport);
 *           - Upper limit enforced per traffic class at subport level;
 *           - Lower priority traffic classes able to reuse subport
 *      bandwidth currently unused by higher priority traffic
 *      classes of the same subport;
 *           - When any subport traffic class is oversubscribed
 *      (configuration time event), the usage of subport member
 *      pipes with high demand for that traffic class pipes is
 *      truncated to a dynamically adjusted value with no
 *             impact to low demand pipes;
 *     3. Pipe:
 *           - Typical usage: individual user/subscriber;
 *           - Traffic shaping using the token bucket algorithm
 *      (one bucket per pipe);
 *     4. Traffic class:
 *           - Traffic classes of the same pipe handled in strict
 *      priority order;
 *           - Upper limit enforced per traffic class at the pipe level;
 *           - Lower priority traffic classes able to reuse pipe
 *      bandwidth currently unused by higher priority traffic
 *      classes of the same pipe;
 *     5. Queue:
 *           - Typical usage: queue hosting packets from one or
 *      multiple connections of same traffic class belonging to
 *      the same user;
 *           - Weighted Round Robin (WRR) is used to service the
 *      queues within same pipe lowest priority traffic class (best-effort).
 */

#ifdef __cplusplus
extern "C" {
#endif

#include <stdbool.h>
#include <vlib/vlib.h>

#include "hqos/sched/sched_common.h"
#include "hqos/sched/pie.h"
#include "hqos/sched/red.h"
#include "hqos/sched/approx.h"
#include "hqos/sched/reciprocal.h"
#include "hqos/sched/bitmap.h"

//#define HQOS_SCHED_DEBUG 1

/** Maximum number of queues per pipe.
 * Note that the multiple queues (power of 2) can only be assigned to
 * lowest priority (best-effort) traffic class. Other higher priority traffic
 * classes can only have one queue.
 * Can not change.
 *
 * @see struct hqos_sched_port_params
 */
#define HQOS_SCHED_QUEUES_PER_PIPE    16
#define HQOS_SCHED_QUEUES_PER_PIPE_LOG2    4

/** Number of WRR queues for best-effort traffic class per pipe.
 *
 * @see struct hqos_sched_pipe_params
 */
#define HQOS_SCHED_BE_QUEUES_PER_PIPE    8


STATIC_ASSERT (HQOS_SCHED_QUEUES_PER_PIPE == (HQOS_SCHED_BE_QUEUES_PER_PIPE << 1), 
                "HQOS number of queues in BE must be consistent with the number of queues in SP");

/** Number of traffic classes per pipe (as well as subport).
 * @see struct hqos_sched_subport_params
 * @see struct hqos_sched_pipe_params
 */
#define HQOS_SCHED_TRAFFIC_CLASSES_PER_PIPE  (HQOS_SCHED_QUEUES_PER_PIPE - HQOS_SCHED_BE_QUEUES_PER_PIPE + 1)
                                                                                                 
/** Best-effort traffic class ID
 * Can not change.
 */
#define HQOS_SCHED_TRAFFIC_CLASS_BE    (HQOS_SCHED_TRAFFIC_CLASSES_PER_PIPE - 1)

/*
 * Ethernet framing overhead. Overhead fields per Ethernet frame:
 * 1. Preamble:                             7 bytes;
 * 2. Start of Frame Delimiter (SFD):       1 byte;
 * 3. Frame Check Sequence (FCS):           4 bytes;
 * 4. Inter Frame Gap (IFG):               12 bytes.
 *
 * The FCS is considered overhead only if not included in the packet
 * length (field pkt_len of vlib_buffer).
 *
 * @see struct hqos_sched_port_params
 */
#ifndef HQOS_SCHED_FRAME_OVERHEAD_DEFAULT
#define HQOSSCHED_FRAME_OVERHEAD_DEFAULT      24
#endif                                                                                           

/**
 * Congestion Management (CMAN) mode
 *
 * This is used for controlling the admission of packets into a packet queue or
 * group of packet queues on congestion.
 *
 * The *Random Early Detection (RED)* algorithm works by proactively dropping
 * more and more input packets as the queue occupancy builds up. When the queue
 * is full or almost full, RED effectively works as *tail drop*. The *Weighted
 * RED* algorithm uses a separate set of RED thresholds for each packet color.
 *
 * Similar to RED, Proportional Integral Controller Enhanced (PIE) randomly
 * drops a packet at the onset of the congestion and tries to control the
 * latency around the target value. The congestion detection, however, is based
 * on the queueing latency instead of the queue length like RED. For more
 * information, refer RFC8033.
 */
typedef enum _hqos_sched_cman_mode {
    HQOS_SCHED_CMAN_RED, /**< Random Early Detection (RED) */
    HQOS_SCHED_CMAN_PIE, /**< Proportional Integral Controller Enhanced (PIE) */
} hqos_sched_cman_mode;

/**
 * Color
 */
typedef enum _hqos_color {
    HQOS_COLOR_GREEN = 0, /**< Green */
    HQOS_COLOR_YELLOW,    /**< Yellow */
    HQOS_COLOR_RED,       /**< Red */
    HQOS_COLORS           /**< Number of colors */
} hqos_color;

/*
 * Pipe configuration parameters. The period and credits_per_period
 * parameters are measured in bytes, with one byte meaning the time
 * duration associated with the transmission of one byte on the
 * physical medium of the output port, with pipe or pipe traffic class
 * rate (measured as percentage of output port rate) determined as
 * credits_per_period divided by period. One credit represents one
 * byte.
 */
typedef struct _hqos_sched_pipe_params {
    /** Token bucket rate (measured in bytes per second) */
    u64 tb_rate;

    /** Token bucket size (measured in credits) */
    u64 tb_size;

    /** Traffic class rates (measured in bytes per second) */
    u64 tc_rate[HQOS_SCHED_TRAFFIC_CLASSES_PER_PIPE];

    /** Enforcement period (measured in milliseconds) */
    u64 tc_period;

    /** Best-effort traffic class oversubscription weight */
    u8 tc_ov_weight;

    /** WRR weights of best-effort traffic class queues */
    u8 wrr_weights[HQOS_SCHED_BE_QUEUES_PER_PIPE];
} hqos_sched_pipe_params;

/*
 * Congestion Management configuration parameters.
 */
typedef struct _hqos_sched_cman_params {
    /** Congestion Management mode */
    hqos_sched_cman_mode cman_mode;

    union {
        /** RED parameters */
        hqos_red_params red_params[HQOS_SCHED_TRAFFIC_CLASSES_PER_PIPE][HQOS_COLORS];

        /** PIE parameters */
        hqos_pie_params pie_params[HQOS_SCHED_TRAFFIC_CLASSES_PER_PIPE];
    };
} hqos_sched_cman_params;

/*
 * Subport configuration parameters. The period and credits_per_period
 * parameters are measured in bytes, with one byte meaning the time
 * duration associated with the transmission of one byte on the
 * physical medium of the output port, with pipe or pipe traffic class
 * rate (measured as percentage of output port rate) determined as
 * credits_per_period divided by period. One credit represents one
 * byte.
 */
typedef struct _hqos_sched_subport_params {
    /** Number of subport pipes.
     * The subport can enable/allocate fewer pipes than the maximum
     * number set through struct port_params::n_max_pipes_per_subport,
     * as needed, to avoid memory allocation for the queues of the
     * pipes that are not really needed.
     */
    u32 n_pipes_per_subport_enabled;

    /** Packet queue size for each traffic class.
     * All the pipes within the same subport share the similar
     * configuration for the queues.
     */
    u16 qsize[HQOS_SCHED_TRAFFIC_CLASSES_PER_PIPE];

    /** Pipe profile table.
     * Every pipe is configured using one of the profiles from this table.
     */
    hqos_sched_pipe_params *pipe_profiles;

    /** Profiles in the pipe profile table */
    u32 n_pipe_profiles;

    /** Max allowed profiles in the pipe profile table */
    u32 n_max_pipe_profiles;

    /** Congestion Management parameters
     * If NULL the congestion management is disabled for the subport,
     * otherwise proper parameters need to be provided.
     */
    hqos_sched_cman_params *cman_params;
} hqos_sched_subport_params;

typedef struct _hqos_sched_subport_profile_params {
    /** Token bucket rate (measured in bytes per second) */
    u64 tb_rate;

    /** Token bucket size (measured in credits) */
    u64 tb_size;

    /** Traffic class rates (measured in bytes per second) */
    u64 tc_rate[HQOS_SCHED_TRAFFIC_CLASSES_PER_PIPE];

    /** Enforcement period for rates (measured in milliseconds) */
    u64 tc_period;
} hqos_sched_subport_profile_params;

/** Port configuration parameters. */
typedef struct _hqos_sched_port_params {

    /** Output port rate (measured in bytes per second) */
    u64 rate;

    /** Maximum Ethernet frame size (measured in bytes).
     * Should not include the framing overhead.
     */
    u32 mtu;

    /** Framing overhead per packet (measured in bytes) */
    u32 frame_overhead;

    /** Number of subports */
    u32 n_subports_per_port;

    /** subport profile table.
     * Every pipe is configured using one of the profiles from this table.
     */
    hqos_sched_subport_profile_params *subport_profiles;

    /** Profiles in the pipe profile table */
    u32 n_subport_profiles;

    /** Max allowed profiles in the pipe profile table */
    u32 n_max_subport_profiles;

    /** Maximum number of subport pipes.
     * This parameter is used to reserve a fixed number of bits
     * in vlib_buffer::sched.queue_id for the pipe_id for all
     * the subports of the same port.
     */
    u32 n_pipes_per_subport;

    /** Default tc queue size. */
    u32 n_queue_size;
} hqos_sched_port_params;


/** Subport statistics */
typedef struct _hqos_sched_subport_stats {
    /** Number of packets successfully written */
    u64 n_pkts_tc[HQOS_SCHED_TRAFFIC_CLASSES_PER_PIPE];

    /** Number of packets dropped */
    u64 n_pkts_tc_dropped[HQOS_SCHED_TRAFFIC_CLASSES_PER_PIPE];

    /** Number of bytes successfully written for each traffic class */
    u64 n_bytes_tc[HQOS_SCHED_TRAFFIC_CLASSES_PER_PIPE];

    /** Number of bytes dropped for each traffic class */
    u64 n_bytes_tc_dropped[HQOS_SCHED_TRAFFIC_CLASSES_PER_PIPE];

    /** Number of packets dropped by congestion management scheme */
    u64 n_pkts_cman_dropped[HQOS_SCHED_TRAFFIC_CLASSES_PER_PIPE];
} hqos_sched_subport_stats;

/** Queue statistics */
typedef struct _hqos_sched_queue_stats {
    /** Packets successfully written */
    u64 n_pkts;

    /** Packets dropped */
    u64 n_pkts_dropped;

    /** Packets dropped by congestion management scheme */
    u64 n_pkts_cman_dropped;

    /** Bytes successfully written */
    u64 n_bytes;

    /** Bytes dropped */
    u64 n_bytes_dropped;
} hqos_sched_queue_stats;

/*********************************************
 * Runtime struct
 ********************************************/
#ifndef HQOS_SCHED_PORT_N_GRINDERS
#define HQOS_SCHED_PORT_N_GRINDERS 8
#endif

#define HQOS_SCHED_TB_RATE_CONFIG_ERR          (1e-7)
#define HQOS_SCHED_WRR_SHIFT                   (3)
#define HQOS_SCHED_MAX_QUEUES_PER_TC           HQOS_SCHED_BE_QUEUES_PER_PIPE
#define HQOS_SCHED_GRINDER_PCACHE_SIZE         (64 / HQOS_SCHED_QUEUES_PER_PIPE)
#define HQOS_SCHED_PIPE_INVALID                (UINT32_MAX)
#define HQOS_SCHED_BMP_POS_INVALID             (UINT32_MAX)


/* Scaling for cycles_per_byte calculation
 * Chosen so that minimum rate is 480 bit/sec
 */
#define HQOS_SCHED_TIME_SHIFT                  (8)

typedef enum _hqos_grinder_state {
    e_GRINDER_PREFETCH_PIPE = 0,
    e_GRINDER_PREFETCH_TC_QUEUE_ARRAYS,
    e_GRINDER_PREFETCH_VLIB_BUF,
    e_GRINDER_READ_VLIB_BUF
} hqos_grinder_state;

typedef enum _hqos_sched_subport_array {
    e_HQOS_SCHED_SUBPORT_ARRAY_PIPE = 0,
    e_HQOS_SCHED_SUBPORT_ARRAY_QUEUE,
    e_HQOS_SCHED_SUBPORT_ARRAY_QUEUE_EXTRA,
    e_HQOS_SCHED_SUBPORT_ARRAY_PIPE_PROFILES,
    e_HQOS_SCHED_SUBPORT_ARRAY_BMP_ARRAY,
    e_HQOS_SCHED_SUBPORT_ARRAY_QUEUE_ARRAY,
    e_HQOS_SCHED_SUBPORT_ARRAY_TOTAL,
} hqos_sched_subport_array;

typedef struct _hqos_sched_queue {
    u16 qw;
    u16 qr;
} hqos_sched_queue;

typedef struct _hqos_sched_queue_extra {
    hqos_sched_queue_stats stats;
    union {
        hqos_red red;
        hqos_pie pie;
    };
} hqos_sched_queue_extra;

typedef struct _hqos_sched_pipe_profile {
    /* Token bucket (TB) */
    u64 tb_period;
    u64 tb_credits_per_period;
    u64 tb_size;
    u64 orig_tb_rate;

    /* Pipe traffic classes */
    u64 tc_period;
    u64 tc_credits_per_period[HQOS_SCHED_TRAFFIC_CLASSES_PER_PIPE];
    u64 orig_tc_period;
    u8 tc_ov_weight;

    /* Pipe best-effort traffic class queues */
    u8  wrr_cost[HQOS_SCHED_BE_QUEUES_PER_PIPE];
    /* WRR weights of best-effort traffic class queues */
    u8 wrr_weights[HQOS_SCHED_BE_QUEUES_PER_PIPE];
} hqos_sched_pipe_profile;

typedef struct _hqos_sched_pipe {
    /* Token bucket (TB) */
    u64 tb_time; /* time of last update */
    u64 tb_credits;

    /* Pipe profile and flags */
    u32 profile;

    /* Traffic classes (TCs) */
    u64 tc_time; /* time of next update */
    u64 tc_credits[HQOS_SCHED_TRAFFIC_CLASSES_PER_PIPE];

    /* Weighted Round Robin (WRR) */
    u8 wrr_tokens[HQOS_SCHED_BE_QUEUES_PER_PIPE];

    /* TC oversubscription */
    u64 tc_ov_credits;
    u8 tc_ov_period_id;
} __attribute__((__aligned__ (CLIB_CACHE_LINE_BYTES))) hqos_sched_pipe;

typedef struct _hqos_sched_subport_profile {
    /* Token bucket (TB) */
    u64 tb_period;
    u64 tb_credits_per_period;
    u64 tb_size;
    u64 orig_tb_rate;

    u64 tc_credits_per_period[HQOS_SCHED_TRAFFIC_CLASSES_PER_PIPE];
    u64 tc_period;
    u64 orig_tc_period;
} hqos_sched_subport_profile;

typedef struct _hqos_sched_grinder {
    /* Pipe cache */
    u16 pcache_qmask[HQOS_SCHED_GRINDER_PCACHE_SIZE];
    u32 pcache_qindex[HQOS_SCHED_GRINDER_PCACHE_SIZE];
    u32 pcache_w;
    u32 pcache_r;

    /* Current pipe */
    hqos_grinder_state state;
    u32 productive;
    u32 pindex;
    struct _hqos_sched_subport *subport;
    hqos_sched_subport_profile *subport_params;
    hqos_sched_pipe *pipe;
    hqos_sched_pipe_profile *pipe_params;

    /* TC cache */
    u8 tccache_qmask[HQOS_SCHED_TRAFFIC_CLASSES_PER_PIPE];
    u32 tccache_qindex[HQOS_SCHED_TRAFFIC_CLASSES_PER_PIPE];
    u32 tccache_w;
    u32 tccache_r;

    /* Current TC */
    u32 tc_index;
    hqos_sched_queue *queue[HQOS_SCHED_MAX_QUEUES_PER_TC];
    vlib_buffer_t **qbase[HQOS_SCHED_MAX_QUEUES_PER_TC];
    u32 qindex[HQOS_SCHED_MAX_QUEUES_PER_TC];
    u16 qsize;
    u32 qmask;
    u32 qpos;
    vlib_buffer_t *pkt;

    /* WRR */
    u16 wrr_tokens[HQOS_SCHED_BE_QUEUES_PER_PIPE];
    u16 wrr_mask[HQOS_SCHED_BE_QUEUES_PER_PIPE];
    u8 wrr_cost[HQOS_SCHED_BE_QUEUES_PER_PIPE];
} hqos_sched_grinder;

typedef struct _hqos_sched_subport {
    /* Token bucket (TB) */
    u64 tb_time; /* time of last update */
    u64 tb_credits;

    /* Traffic classes (TCs) */
    u64 tc_time; /* time of next update */
    u64 tc_credits[HQOS_SCHED_TRAFFIC_CLASSES_PER_PIPE];

    /* TC oversubscription */
    u64 tc_ov_wm;
    u64 tc_ov_wm_min;
    u64 tc_ov_wm_max;
    f64 tc_ov_rate;
    u8 tc_ov_period_id;
    u8 tc_ov;
    u32 tc_ov_n;

    /* Statistics */
    CLIB_CACHE_LINE_ALIGN_MARK(cacheline0);
    hqos_sched_subport_stats stats;

    CLIB_CACHE_LINE_ALIGN_MARK(cacheline1);
    /* subport profile */
    u32 profile;
    /* Subport pipes */
    u32 n_pipes_per_subport_enabled;
    u32 n_pipe_profiles;
    u32 n_max_pipe_profiles;

    /* Pipe best-effort TC rate */
    u64 pipe_tc_be_rate_max;

    /* Pipe queues size */
    u16 qsize[HQOS_SCHED_TRAFFIC_CLASSES_PER_PIPE];

    bool cman_enabled;
    hqos_sched_cman_mode cman;

    union {
        hqos_red_config red_config[HQOS_SCHED_TRAFFIC_CLASSES_PER_PIPE][HQOS_COLORS];
        hqos_pie_config pie_config[HQOS_SCHED_TRAFFIC_CLASSES_PER_PIPE];
    };

    /* Scheduling loop detection */
    u32 pipe_loop;
    u32 pipe_exhaustion;

    /* Bitmap */
    hqos_bitmap *bmp;
    alignas(16) uint32_t grinder_base_bmp_pos[HQOS_SCHED_PORT_N_GRINDERS];

    /* Grinders */
    struct _hqos_sched_grinder grinder[HQOS_SCHED_PORT_N_GRINDERS];
    u32 busy_grinders;

    /* Queue base calculation */
    u32 qsize_add[HQOS_SCHED_QUEUES_PER_PIPE];
    u32 qsize_sum;

    /* TC oversubscription activation */
    int tc_ov_enabled;

    hqos_sched_pipe *pipe;
    hqos_sched_queue *queue;
    hqos_sched_queue_extra *queue_extra;
    hqos_sched_pipe_profile *pipe_profiles;
    u8 *bmp_array;

    vlib_buffer_t **queue_array;

    CLIB_CACHE_LINE_ALIGN_MARK(memory);

} __attribute__((__aligned__ (CLIB_CACHE_LINE_BYTES)))hqos_sched_subport;


typedef struct _hqos_sched_port {
    /* User parameters */
    u32 n_subports_per_port;
    u32 n_pipes_per_subport;
    u32 n_pipes_per_subport_log2;
    u32 n_queue_size;
    u16 pipe_queue[HQOS_SCHED_TRAFFIC_CLASSES_PER_PIPE];
    u8 pipe_tc[HQOS_SCHED_QUEUES_PER_PIPE];
    u8 tc_queue[HQOS_SCHED_QUEUES_PER_PIPE];
    u32 n_subport_profiles;
    u32 n_max_subport_profiles;
    u64 rate;
    u32 mtu;
    u32 frame_overhead;

    /* Timing */
    u64 time_cpu_cycles;     /* Current CPU time measured in CPU cycles */
    u64 time_cpu_bytes;      /* Current CPU time measured in bytes */
    u64 time;                /* Current NIC TX time measured in bytes */
    hqos_reciprocal inv_cycles_per_byte; /* CPU cycles per byte */ 
    u64 cycles_per_byte;

    /* Grinders */
    vlib_buffer_t **pkts_out;
    u32 n_pkts_out;
    u32 subport_id;
    u32 n_active_subports;

    /* Large data structures */
    hqos_sched_subport_profile *subport_profiles;
    CLIB_CACHE_LINE_ALIGN_MARK(cacheline0);
    hqos_sched_subport *subports[0];
} __attribute__((__aligned__ (CLIB_CACHE_LINE_BYTES))) hqos_sched_port;

/*************************** 
 * Configuration Function 
 ***************************/

/**
 * Hierarchical scheduler memory footprint size per port
 *
 * @param port_params
 *   Port scheduler configuration parameter structure
 * @param subport_params
 *   Array of subport parameter structures
 * @return
 *   Memory footprint size in bytes upon success, 0 otherwise
 */
uint32_t
hqos_sched_port_get_memory_footprint(hqos_sched_port_params *port_params,
                                     hqos_sched_subport_params **subport_params);


/**
 * Hierarchical scheduler port configuration
 *
 * @param params
 *   Port scheduler configuration parameter structure
 * @return
 *   Handle to port scheduler instance upon success or NULL otherwise.
 */
hqos_sched_port *
hqos_sched_port_config(hqos_sched_port_params *params);

/**
 * Hierarchical scheduler port free
 *
 * @param port
 *   Handle to port scheduler instance.
 *   If port is NULL, no operation is performed.
 */
void
hqos_sched_port_free(hqos_sched_port *port);

/**
 * Hierarchical scheduler subport bandwidth profile add
 * Note that this function is safe to use in runtime for adding new
 * subport bandwidth profile as it doesn't have any impact on hierarchical
 * structure of the scheduler.
 * @param port
 *   Handle to port scheduler instance
 * @param profile
 *   Subport bandwidth profile
 * @param subport_profile_id
 *   Subport profile id
 * @return
 *   0 upon success, error code otherwise
 */
int
hqos_sched_port_subport_profile_add(hqos_sched_port *port,
                                    hqos_sched_subport_profile_params *profile,
                                    u32 *subport_profile_id);

/**
 * Hierarchical scheduler subport bandwidth profile update
 *
 * @param port
 *   Handle to port scheduler instance
 * @param profile
 *   Subport bandwidth profile
 * @param subport_profile_id
 *   Subport profile id
 * @return
 *   0 upon success, error code otherwise
 */
int
hqos_sched_port_subport_profile_update(hqos_sched_port *port,
                                    hqos_sched_subport_profile_params *profile,
                                    u32 subport_profile_id);

/**
 * Hierarchical scheduler pipe profile add
 *
 * @param port
 *   Handle to port scheduler instance
 * @param subport_id
 *   Subport ID
 * @param params
 *   Pipe profile parameters
 * @param pipe_profile_id
 *   Set to valid profile id when profile is added successfully.
 * @return
 *   0 upon success, error code otherwise
 */
int
hqos_sched_subport_pipe_profile_add(hqos_sched_port *port,
                                    u32 subport_id,
                                    hqos_sched_pipe_params *params,
                                    u32 *pipe_profile_id);

/**
 * Hierarchical scheduler pipe profile update
 *
 * when update, all references to this profile need to be reconfigured
 *
 * @param port
 *   Handle to port scheduler instance
 * @param subport_id
 *   Subport ID
 * @param params
 *   Pipe profile parameters
 * @param pipe_profile_id
 *   Valid profile id .
 * @return
 *   0 upon success, error code otherwise
 */
int
hqos_sched_subport_pipe_profile_update(hqos_sched_port *port,
                                    u32 subport_id,
                                    hqos_sched_pipe_params *params,
                                    u32 pipe_profile_id);

/**
 * Hierarchical scheduler subport traffic class
 * oversubscription enable/disable.
 * This function should be called at the time of subport initialization.
 *
 * @param port
 *   Handle to port scheduler instance
 * @param subport_id
 *   Subport ID
 * @param tc_ov_enable
 *  Boolean flag to enable/disable TC OV
 * @return
 *   0 upon success, error code otherwise
 */
int
hqos_sched_subport_tc_ov_config(hqos_sched_port *port, u32 subport_id, bool tc_ov_enable);

/**
 * Hierarchical scheduler subport configuration
 * Note that this function is safe to use at runtime
 * to configure subport bandwidth profile.
 * @param port
 *   Handle to port scheduler instance
 * @param subport_id
 *   Subport ID
 * @param params
 *   Subport configuration parameters. Must be non-NULL
 *   for first invocation (i.e initialization) for a given
 *   subport. Ignored (recommended value is NULL) for all
 *   subsequent invocation on the same subport.
 * @param subport_profile_id
 *   ID of subport bandwidth profile
 * @return
 *   0 upon success, error code otherwise
 */
int
hqos_sched_subport_config(hqos_sched_port *port,
                          u32 subport_id,
                          hqos_sched_subport_params *params,
                          u32 subport_profile_id);

/**
 * Hierarchical scheduler pipe configuration
 *
 * @param port
 *   Handle to port scheduler instance
 * @param subport_id
 *   Subport ID
 * @param pipe_id
 *   Pipe ID within subport
 * @param pipe_profile
 *   ID of subport-level pre-configured pipe profile
 * @return
 *   0 upon success, error code otherwise
 */
int
hqos_sched_pipe_config(hqos_sched_port *port,
                       u32 subport_id,
                       u32 pipe_id,
                       int pipe_profile);

/**
 * Hierarchical scheduler port enqueue. Writes up to n_pkts to port
 * scheduler and returns the number of packets actually written. For
 * each packet, the port scheduler queue to write the packet to is
 * identified by reading the hierarchy path from the packet
 * descriptor; if the queue is full or congested and the packet is not
 * written to the queue, then the packet is automatically dropped
 * without any action required from the caller.
 *
 * @param port
 *   Handle to port scheduler instance
 * @param pkts
 *   Array storing the packet descriptor handles
 * @param n_pkts
 *   Number of packets to enqueue from the pkts array into the port scheduler
 * @return
 *   Number of packets successfully enqueued
 */
int
hqos_sched_port_enqueue(hqos_sched_port *port, vlib_buffer_t **pkts, u32 n_pkts);

/**
 * Hierarchical scheduler port dequeue. Reads up to n_pkts from the
 * port scheduler and stores them in the pkts array and returns the
 * number of packets actually read.  The pkts array needs to be
 * pre-allocated by the caller with at least n_pkts entries.
 *
 * @param port
 *   Handle to port scheduler instance
 * @param pkts
 *   Pre-allocated packet descriptor array where the packets dequeued
 *   from the port
 *   scheduler should be stored
 * @param n_pkts
 *   Number of packets to dequeue from the port scheduler
 * @return
 *   Number of packets successfully dequeued and placed in the pkts array
 */
int
hqos_sched_port_dequeue(hqos_sched_port *port, vlib_buffer_t **pkts, u32 n_pkts);


/*************************** 
 * Statistics Function 
 ***************************/

/**
 * Hierarchical scheduler subport statistics read
 *
 * @param port
 *   Handle to port scheduler instance
 * @param subport_id
 *   Subport ID
 * @param stats
 *   Pointer to pre-allocated subport statistics structure where the statistics
 *   counters should be stored
 * @param tc_ov
 *   Pointer to pre-allocated HQOS_SCHED_TRAFFIC_CLASSES_PER_PIPE-entry array
 *   where the oversubscription status for each of the subport traffic classes
 *   should be stored.
 * @return
 *   0 upon success, error code otherwise
 */
int
hqos_sched_subport_read_stats(hqos_sched_port *port,
                              u32 subport_id,
                              hqos_sched_subport_stats *stats,
                              u32 *tc_ov);

/**
 * Hierarchical scheduler queue statistics read
 *
 * @param port
 *   Handle to port scheduler instance
 * @param queue_id
 *   Queue ID within port scheduler
 * @param stats
 *   Pointer to pre-allocated subport statistics structure where the statistics
 *   counters should be stored
 * @param qlen
 *   Pointer to pre-allocated variable where the current queue length
 *   should be stored.
 * @return
 *   0 upon success, error code otherwise
 */
int
hqos_sched_queue_read_stats(hqos_sched_port *port,
                            u32 queue_id,
                            hqos_sched_queue_stats *stats,
                            u16 *qlen);


static_always_inline u64
hqos_sched_time_ms_to_rate(u64 time_ms, u64 bytes)
{
    u64 rate = time_ms;

    rate = 1000 * bytes / rate  ;

    return rate;
}

#ifdef __cplusplus
}
#endif

#endif //included_hqos_sched_h
