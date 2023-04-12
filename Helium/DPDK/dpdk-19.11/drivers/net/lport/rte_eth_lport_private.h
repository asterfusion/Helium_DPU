/*
 * Copyright (C) 2018 Marvell International Ltd.
 *
 * This program is provided "as is" without any warranty of any kind, and is
 * distributed under the applicable Marvell proprietary limited use license
 * agreement.
 */

#ifndef RTE_ETH_LPORT_PRIVATE_H
#define RTE_ETH_LPORT_PRIVATE_H

#include <rte_atomic.h>
#include <rte_ethdev_driver.h>
#include <rte_kvargs.h>
#include <rte_ring.h>
#include <rte_spinlock.h>

#include <stdbool.h>

#define LPORT_CFG_KVARG		"cfg"
#define LPORT_IFACE_KVARG	"iface"

#define LPORT_CFG_SECTION	"l-domain"
#define LPORT_CFG_MAX_ENT	16

#define RTE_LPORT_LOG(lvl, msg, ...)		\
	RTE_LOG(lvl, PMD, "%s(%d) - " msg "\n", \
		__func__, __LINE__, ##__VA_ARGS__)

#define LPORT_MAX_DOMAIN	2
#define LPORT_MAX_PORT		16
#define LPORT_PNAME_MAX_LEN	8

struct lport;
struct ldomain;

typedef enum {
	DSA_PORT_TAG,
	DSA_VID_TAG,
	VLAN_TAG,
	INVALID_TAG = -1,
} lport_tag_type_t;

typedef union {
	uintptr_t value;
	void      *ptr; /* this is a possible extension point for the case where
			 * tag is something more complicated than some "int"
			 */
} lport_tag_t;

struct lport_mapping {
	lport_tag_t  tag;
	struct lport *port;
};

typedef
int (*lport_retag_cb_t)(const struct lport *lport,
			struct rte_mbuf **tx_pkts, int nb_pkts);
typedef
void (*lport_dispatch_cb_t)(const struct ldomain *ldomain,
			    struct rte_mbuf **rx_pkts, uint16_t nb_pkts);
typedef
struct lport* (*lport_match_cb_t)(const struct ldomain *ldomain, uint8_t *data);

struct lport_qids {
	uint16_t rx_id;
	uint16_t tx_id;
};

struct lport_lcstats { /* "local" per core stats */
	uint64_t tx_pkts;
	uint64_t rx_pkts;
	uint64_t tx_bytes;
	uint64_t rx_bytes;

	uint64_t tx_dropped;
	uint64_t rx_dropped;
};

struct ldata_per_core {
	struct lport_qids q_ids[LPORT_MAX_DOMAIN];
	struct lport_lcstats stats[LPORT_MAX_PORT];
	struct lport_lcstats bstats[LPORT_MAX_PORT];
	uint64_t next_tsc; /* timestamp - see rx_burst for its usage */
} __rte_cache_aligned;

struct lport {
	struct ldomain   *ldomain;
	struct rte_ring  *rx_ring;
	lport_retag_cb_t retag_cb;
	lport_tag_t      tag;
	uint16_t         id;
	/* l-port flags ... */
	uint8_t active;
	uint8_t rxq_configured;
	uint8_t txq_configured;
	uint8_t promisc_mode;
	uint8_t allmulticast_on;
	uint8_t mtu_configured;
	uint16_t mtu;
	struct rte_ether_addr mac;
	/* ... and less often used data */
	struct rte_eth_dev *eth_dev;
	char name[LPORT_PNAME_MAX_LEN];
};

struct ldomain {
	rte_spinlock_t rx_lock; /* This lock is used to synchronize rx_bursts on
				 * physical port from different cores.
				 */
	/* If there is not enough TX queues to have dedicated one for each lport
	 * then last queue is configured as a shared one with corresponding TX
	 * ring and lock.  See lport_ethdev_configure() and related tx callback
	 * lport_tx_burst_locked().
	 */
	rte_spinlock_t   tx_lock;
	struct rte_ring *tx_ring;
	lport_dispatch_cb_t dispatch_cb;

	struct lport_mapping *tag_map;

	uint16_t id;
	uint16_t eth_id;	 /* p-port rte_ethdev id */

	/* now less often used data */
	uint16_t lports_cnt;     /* number of lports configured */
	uint16_t active_lports;  /* number of active lports */
	uint16_t rxq_configured; /* number of l-ports w/ rx queue configured */
	uint16_t txq_configured; /* number of l-ports w/ tx queue configured */

	uint16_t max_tx_queues;  /* maximal # of tx queues that can be used */

	uint8_t active;		/* p-port has been started */
	uint8_t configured;	/* p-port has been configured */
	uint8_t initialized;	/* internal data initialized */

	lport_tag_type_t tag_type;
	lport_match_cb_t match_cb;
	int socket_id;		 /* memory socket id */

	char *port_arg;
};

#endif /* RTE_ETH_LPORT_PRIVATE_H */
