/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2022 Marvell.
 */

#include <inttypes.h>
#include <signal.h>
#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>

#include <rte_atomic.h>
#include <rte_bitmap.h>
#include <rte_byteorder.h>
#include <rte_cycles.h>
#include <rte_ethdev.h>
#include <rte_hexdump.h>
#include <rte_ipsec.h>
#include <rte_malloc.h>
#include <rte_pmd_cnxk.h>
#include <rte_security.h>
#include <rte_eventdev.h>
#include <rte_event_eth_rx_adapter.h>
#include <rte_event_eth_tx_adapter.h>
#include <rte_event_crypto_adapter.h>

#include "ipsec_msns.h"

#define NB_ETHPORTS_USED	 1
#define MEMPOOL_CACHE_SIZE	 32
#define MEMPOOL_PRV_AREA_SIZE	 128
#define RTE_TEST_RX_DESC_DEFAULT 1024
#define RTE_TEST_TX_DESC_DEFAULT 1024
#define RTE_PORT_ALL		 (~(uint16_t)0x0)
#define CDEV_MP_CACHE_SZ 64
#define CDEV_MP_CACHE_MULTIPLIER 1.5 /* from rte_mempool.c */

#define RX_PTHRESH 8  /**< Default values of RX prefetch threshold reg. */
#define RX_HTHRESH 8  /**< Default values of RX host threshold reg. */
#define RX_WTHRESH 0  /**< Default values of RX write-back threshold reg. */

#define TX_PTHRESH 32 /**< Default values of TX prefetch threshold reg. */
#define TX_HTHRESH 0  /**< Default values of TX host threshold reg. */
#define TX_WTHRESH 0  /**< Default values of TX write-back threshold reg. */

#define NB_MBUF 10240U
#define MAX_PKT_BURST 32

int create_default_flow(uint16_t port_id, enum rte_pmd_cnxk_sec_action_alg alg, uint32_t spi,
			       uint16_t sa_lo, uint16_t sa_hi, uint32_t sa_index);
enum test_mode {
	IPSEC_MSNS,
	EVENT_IPSEC_INB_MSNS_PERF,
	EVENT_IPSEC_INB_PERF,
	EVENT_IPSEC_INB_OUTB_PERF,
	EVENT_IPSEC_INB_LAOUTB_PERF,
	POLL_IPSEC_INB_OUTB_PERF,
	/* Verify the RTE PMD APIs */
	IPSEC_RTE_PMD_CNXK_API_TEST,
	POLL_IPSEC_INB_PERF,
	POLL_IPSEC_OUTB_PERF,
	EVENT_IPSEC_OUTB_PERF,
};

static struct rte_mempool *mbufpool[RTE_MAX_ETHPORTS];
static struct rte_mempool *vector_pool[RTE_MAX_ETHPORTS];
static struct rte_mempool *sess_pool;
static struct rte_mempool *cryptodev_session_pool;
/* ethernet addresses of ports */
static struct rte_ether_addr ports_eth_addr[RTE_MAX_ETHPORTS];
static uint16_t stats_tmo = 5;
static bool is_plat_cn20k;

#define VECTOR_SIZE_DEFAULT   64
#define VECTOR_TMO_NS_DEFAULT 1E6
static uint16_t vector_en;
static uint16_t vector_sz = VECTOR_SIZE_DEFAULT;

static struct rte_eth_conf port_conf = {
	.rxmode = {
			.mq_mode = RTE_ETH_MQ_RX_NONE,
			.offloads = RTE_ETH_RX_OFFLOAD_CHECKSUM | RTE_ETH_RX_OFFLOAD_SECURITY,
		},
	.txmode = {
			.mq_mode = RTE_ETH_MQ_TX_NONE,
			.offloads = RTE_ETH_TX_OFFLOAD_SECURITY | RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE,
		},
	.lpbk_mode = 0,
};

static struct rte_eth_rxconf rx_conf = {
	.rx_thresh = {
			.pthresh = RX_PTHRESH,
			.hthresh = RX_HTHRESH,
			.wthresh = RX_WTHRESH,
		},
	.rx_free_thresh = 32,
};

static struct rte_eth_txconf tx_conf = {
	.tx_thresh = {
			.pthresh = TX_PTHRESH,
			.hthresh = TX_HTHRESH,
			.wthresh = TX_WTHRESH,
		},
	.tx_free_thresh = 32, /* Use PMD default values */
	.tx_rs_thresh = 32,   /* Use PMD default values */
};

struct lcore_cfg {
	uint8_t socketid;
	uint16_t nb_ports;
	uint16_t portid;
	int eventdev_id;
	int event_port_id;
	int eventq_id;
	uint16_t queueid;

	/* Stats */
	uint64_t rx_pkts;
	uint64_t rx_ipsec_pkts;
	uint64_t tx_pkts;
	uint64_t ipsec_failed;
	uint64_t num_inb_sas;
	uint64_t num_outb_sas;
};

static struct lcore_cfg lcore_cfg[RTE_MAX_LCORE];

static struct rte_flow *default_flow[RTE_MAX_ETHPORTS][RTE_PMD_CNXK_SEC_ACTION_ALG4 + 1];
static struct rte_flow *default_flow_no_msns[RTE_MAX_ETHPORTS];

struct sa_index_map {
	struct rte_bitmap *map;
	uint32_t size;
};

struct ipsec_sa_info {
	struct rte_security_session *sa;
	struct ipsec_session_data *sa_data;
};

struct outb_sa_exp_info {
	RTE_TAILQ_ENTRY(outb_sa_exp_info) next;
	struct ipsec_session_data *sa_data;
	uint16_t port_id;
};

struct ipsec_mbuf_metadata {
	struct rte_crypto_op cop;
	struct rte_crypto_sym_op sym_cop;
	uint8_t buf[32];
} __rte_cache_aligned;

struct ethaddr_info {
	struct rte_ether_addr src, dst;
};

struct ethaddr_info ethaddr_tbl[RTE_MAX_ETHPORTS] = {
	{ {{0}}, {{0x00, 0x16, 0x3e, 0x7e, 0x94, 0x9a}} },
	{ {{0}}, {{0x00, 0x16, 0x3e, 0x22, 0xa1, 0xd9}} },
	{ {{0}}, {{0x00, 0x16, 0x3e, 0x08, 0x69, 0x26}} },
	{ {{0}}, {{0x00, 0x16, 0x3e, 0x49, 0x9e, 0xdd}} }
};

/* Example usage, max entries 4K */
#define MAX_SA_SIZE (4 * 1024)
#define DEFAULT_SEC_ACTION_ALG 0xFF /* Default is no action alg */

struct ipsec_sa_info inb_sas[MAX_SA_SIZE + 1];
struct ipsec_sa_info outb_sas[MAX_SA_SIZE + 1];
static struct sa_index_map bmap[RTE_MAX_ETHPORTS][2];
static rte_spinlock_t exp_ses_dest_lock = RTE_SPINLOCK_INITIALIZER;

static uint32_t ethdev_port_mask = RTE_PORT_ALL;
static volatile bool force_quit;
static uint32_t nb_bufs = 0;
static enum test_mode testmode;
static bool event_en;
static bool poll_mode;
static bool pfc;
static int eventdev_id;
static int rx_adapter_id;
static int tx_adapter_id;
static int nb_event_queues;
static int nb_event_ports;
static uint32_t num_sas = 1;
static bool softexp;
static bool inl_inb_oop;
static bool ipsec_stats;
static uint8_t action_alg = DEFAULT_SEC_ACTION_ALG;
static uint32_t soft_limit = 8 * 1024 * 1024;
static uint32_t esn_ar;
static bool esn_en;
static bool verbose;
static struct ipsec_session_data *sess_conf = &conf_aes_128_gcm;

TAILQ_HEAD(outb_sa_expiry_q, outb_sa_exp_info);
struct outb_sa_expiry_q sa_exp_q;
pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t cond = PTHREAD_COND_INITIALIZER;

static void
signal_handler(int signum)
{
	if (signum == SIGINT || signum == SIGTERM) {
		printf("\n\nSignal %d received, preparing to exit...\n",
				signum);
		force_quit = true;
	}
}

static const char *
ipsec_test_mode_to_string(enum test_mode testmode)
{
	switch (testmode) {
	case IPSEC_MSNS:
		return "IPSEC_MSNS";
	case EVENT_IPSEC_INB_MSNS_PERF:
		return "EVENT_IPSEC_INB_MSNS_PERF";
	case EVENT_IPSEC_INB_PERF:
		return "EVENT_IPSEC_INB_PERF";
	case EVENT_IPSEC_INB_OUTB_PERF:
		return "EVENT_IPSEC_INB_OUTB_PERF";
	case EVENT_IPSEC_INB_LAOUTB_PERF:
		return "EVENT_IPSEC_INB_LAOUTB_PERF";
	case POLL_IPSEC_INB_OUTB_PERF:
		return "POLL_IPSEC_INB_OUTB_PERF";
	case IPSEC_RTE_PMD_CNXK_API_TEST:
		return "IPSEC_RTE_PMD_CNXK_API_TEST";
	case POLL_IPSEC_INB_PERF:
		return "POLL_IPSEC_INB_PERF";
	case POLL_IPSEC_OUTB_PERF:
		return "POLL_IPSEC_OUTB_PERF";
	case EVENT_IPSEC_OUTB_PERF:
		return "EVENT_IPSEC_OUTB_PERF";

	}
	return NULL;
}

static inline void
crypto_op_reset(struct rte_security_session *ses, struct rte_mbuf *mb[],
		struct rte_crypto_op *cop[], uint16_t num)
{
	struct rte_crypto_sym_op *sop;
	uint32_t i;

	const struct rte_crypto_op unproc_cop = {
		.type = RTE_CRYPTO_OP_TYPE_SYMMETRIC,
		.status = RTE_CRYPTO_OP_STATUS_NOT_PROCESSED,
		.sess_type = RTE_CRYPTO_OP_SECURITY_SESSION,
	};

	for (i = 0; i != num; i++) {
		cop[i]->raw = unproc_cop.raw;
		sop = cop[i]->sym;
		sop->m_src = mb[i];
		sop->m_dst = NULL;
		__rte_security_attach_session(sop, ses);
	}
}

static inline int
event_crypto_enqueue(struct rte_mbuf *pkt, struct lcore_cfg *info, uint16_t sa_index)
{
	struct ipsec_mbuf_metadata *priv;
	struct rte_crypto_op *cop;
	struct rte_event cev;
	int ret;

	/* Get pkt private data */
	priv = rte_mbuf_to_priv(pkt);
	cop = &priv->cop;

	/* Reset crypto operation data */
	crypto_op_reset(outb_sas[sa_index].sa, &pkt, &cop, 1);

	/* Update event_ptr with rte_crypto_op */
	cev.event = 0;
	cev.event_ptr = cop;

	/* Enqueue event to crypto adapter */
	ret = rte_event_crypto_adapter_enqueue(info->eventdev_id, info->event_port_id, &cev, 1);
	if (unlikely(ret <= 0)) {
		rte_pktmbuf_free(pkt);
		printf("Cannot enqueue event: %i (errno: %i)\n", ret, rte_errno);
		return rte_errno;
	}

	return 0;
}

static inline int
ipsec_ev_cryptodev_process_one_pkt(const struct rte_crypto_op *cop, struct rte_mbuf *pkt)
{
	struct rte_ether_hdr *ethhdr;
	uint16_t port_id = 0;
	struct ip *ip;

	/* If operation was not successful, free the packet */
	if (unlikely(cop->status != RTE_CRYPTO_OP_STATUS_SUCCESS)) {
		printf("Crypto operation failed\n");
		rte_pktmbuf_free(pkt);
		return -1;
	}
	ip = rte_pktmbuf_mtod(pkt, struct ip *);

	/* Prepend Ether layer */
	ethhdr = (struct rte_ether_hdr *)rte_pktmbuf_prepend(pkt, RTE_ETHER_HDR_LEN);
	if (unlikely(ethhdr == NULL)) {
		rte_pktmbuf_free(pkt);
		return -1;
	}

	/* Route pkt and update required fields */
	if (ip->ip_v == IPVERSION) {
		pkt->ol_flags |= RTE_MBUF_F_TX_IPV4;
		pkt->l3_len = sizeof(struct ip);
		pkt->l2_len = RTE_ETHER_HDR_LEN;

		ethhdr->ether_type = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4);
	} else {
		pkt->ol_flags |= RTE_MBUF_F_TX_IPV6;
		pkt->l3_len = sizeof(struct ip6_hdr);
		pkt->l2_len = RTE_ETHER_HDR_LEN;

		ethhdr->ether_type = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV6);
	}

	/* Update Ether with port's MAC addresses */
	memcpy(&ethhdr->src_addr, &ethaddr_tbl[port_id].src, sizeof(struct rte_ether_addr));
	memcpy(&ethhdr->dst_addr, &ethaddr_tbl[port_id].dst, sizeof(struct rte_ether_addr));

	/* Save eth queue for Tx */
	pkt->port = 0;
	rte_event_eth_tx_adapter_txq_set(pkt, 0);

	return 0;
}

static inline int
ipsec_ev_cryptodev_process(struct rte_event *ev)
{
	struct rte_crypto_op *cop;
	struct rte_mbuf *pkt;

	/* Get pkt data */
	cop = ev->event_ptr;
	pkt = cop->sym->m_src;

	if (ipsec_ev_cryptodev_process_one_pkt(cop, pkt))
		return 0;

	/* Update event */
	ev->mbuf = pkt;

	return 1;
}

static inline enum pkt_type
process_ipsec_get_pkt_type(struct rte_mbuf *pkt, uint8_t **nlp)
{
	struct rte_ether_hdr *eth;
	uint32_t ptype = pkt->packet_type;

	eth = rte_pktmbuf_mtod(pkt, struct rte_ether_hdr *);
	rte_prefetch0(eth);

	if (RTE_ETH_IS_IPV4_HDR(ptype)) {
		*nlp = RTE_PTR_ADD(eth, RTE_ETHER_HDR_LEN +
				offsetof(struct ip, ip_p));
		if ((ptype & RTE_PTYPE_TUNNEL_MASK) == RTE_PTYPE_TUNNEL_ESP)
			return PKT_TYPE_IPSEC_IPV4;
		else
			return PKT_TYPE_PLAIN_IPV4;
	} else if (RTE_ETH_IS_IPV6_HDR(ptype)) {
		*nlp = RTE_PTR_ADD(eth, RTE_ETHER_HDR_LEN +
				offsetof(struct ip6_hdr, ip6_nxt));
		if ((ptype & RTE_PTYPE_TUNNEL_MASK) == RTE_PTYPE_TUNNEL_ESP)
			return PKT_TYPE_IPSEC_IPV6;
		else
			return PKT_TYPE_PLAIN_IPV6;
	}

	/* Unknown/Unsupported type */
	return PKT_TYPE_INVALID;
}

static int
cryptodev_session_pool_init(void)
{
	char mp_name[RTE_MEMPOOL_NAMESIZE];
	struct rte_mempool *sess_mp;
	uint32_t nb_sess;
	size_t sess_sz;
	void *sec_ctx;

	sec_ctx = rte_cryptodev_get_sec_ctx(0);
	if (sec_ctx == NULL)
		return -ENOENT;

	sess_sz = rte_security_session_get_size(sec_ctx);

	snprintf(mp_name, RTE_MEMPOOL_NAMESIZE, "crypto_sess_mp");
	nb_sess = (num_sas + CDEV_MP_CACHE_SZ * rte_lcore_count());
	nb_sess = RTE_MAX(nb_sess, CDEV_MP_CACHE_SZ *
			CDEV_MP_CACHE_MULTIPLIER);
	sess_mp = rte_cryptodev_sym_session_pool_create(
			mp_name, nb_sess, sess_sz, CDEV_MP_CACHE_SZ,
			0, 0);
	cryptodev_session_pool = sess_mp;

	if (sess_mp == NULL)
		rte_exit(EXIT_FAILURE, "Cannot init cryptodev session pool\n");

	return 0;
}

static int
cryptodevs_init(void)
{
	struct rte_cryptodev_config dev_conf;
	struct rte_cryptodev_qp_conf qp_conf;
	struct rte_cryptodev_info cdev_info;
	uint32_t dev_max_sess;
	uint16_t cdev_id = 0;
	uint16_t qp;
	int ret;

	ret = cryptodev_session_pool_init();
	if (ret)
		return ret;

	rte_cryptodev_info_get(cdev_id, &cdev_info);

	dev_conf.socket_id = rte_cryptodev_socket_id(cdev_id);
	/* Use the first socket if SOCKET_ID_ANY is returned. */
	if (dev_conf.socket_id == SOCKET_ID_ANY)
		dev_conf.socket_id = 0;
	dev_conf.nb_queue_pairs = 1;
	dev_conf.ff_disable = RTE_CRYPTODEV_FF_ASYMMETRIC_CRYPTO;
	dev_max_sess = cdev_info.sym.max_nb_sessions;

	if (dev_max_sess != 0 && dev_max_sess < num_sas)
		rte_exit(EXIT_FAILURE, "Device does not support at least %u sessions",
			 num_sas);

	if (rte_cryptodev_configure(cdev_id, &dev_conf))
		rte_panic("Failed to initialize cryptodev %u\n", cdev_id);

	qp_conf.nb_descriptors = 2048;
	qp_conf.mp_session = cryptodev_session_pool;
	for (qp = 0; qp < dev_conf.nb_queue_pairs; qp++)
		if (rte_cryptodev_queue_pair_setup(cdev_id, qp, &qp_conf, dev_conf.socket_id))
			rte_panic("Failed to setup queue for cdev_id %u\n", cdev_id);

	if (rte_cryptodev_start(cdev_id))
		rte_panic("Failed to start cryptodev %u\n", cdev_id);

	printf("\n");

	return 0;
}

static int
cnxk_sa_index_init(int port_id, enum rte_security_ipsec_sa_direction dir, uint32_t size)
{
	uint32_t bmap_sz;
	uint32_t i;
	void *mem;

	if (bmap[port_id][dir].map == NULL) {
		bmap_sz = rte_bitmap_get_memory_footprint(size);
		mem = rte_zmalloc("ut_sa_index_bmap", bmap_sz, RTE_CACHE_LINE_SIZE);
		if (mem == NULL)
			return -1;
		bmap[port_id][dir].map = rte_bitmap_init(size, mem, bmap_sz);
		if (bmap[port_id][dir].map == NULL)
			return -1;
		for (i = 0; i < size; i++)
			rte_bitmap_set(bmap[port_id][dir].map, i);
		bmap[port_id][dir].size = size;
	}
	return 0;
}

static void
cnxk_sa_index_fini(int port_id, enum rte_security_ipsec_sa_direction dir)
{
	rte_free(bmap[port_id][dir].map);
	bmap[port_id][dir].map = NULL;
}

static int
cnxk_sa_index_alloc(int port_id, enum rte_security_ipsec_sa_direction dir, uint32_t size)
{
	bool update_idx;
	int index, bit;
	uint32_t count;
	uint32_t i, j;

	if (bmap[port_id][dir].map == NULL)
		return -1;

	if (size > bmap[port_id][dir].size)
		return -1;

	__rte_bitmap_scan_init(bmap[port_id][dir].map);
	i = 0;
retry:
	update_idx = 1;
	count = 0;
	index = -1;
	for (; i < bmap[port_id][dir].size; i++) {
		bit = rte_bitmap_get(bmap[port_id][dir].map, i);
		if (bit) {
			if (update_idx) {
				if ((i + size) > bmap[port_id][dir].size)
					return -1;
				index = i;
				update_idx = 0;
			}
			count++;
			if (count >= size) {
				for (j = index; j < (index + size); j++)
					rte_bitmap_clear(bmap[port_id][dir].map, j);
				return index;
			}
		} else {
			i++;
			goto retry;
		}
	}
	return -1;
}

static int
cnxk_sa_index_free(int port_id, enum rte_security_ipsec_sa_direction dir, uint32_t sa_index,
		   uint32_t size)
{
	uint32_t i;
	int bit;

	if (bmap[port_id][dir].map == NULL)
		return -1;

	if ((sa_index + size) > bmap[port_id][dir].size)
		return -1;

	for (i = sa_index; i < sa_index + size; i++) {
		bit = rte_bitmap_get(bmap[port_id][dir].map, i);
		if (!bit)
			rte_bitmap_set(bmap[port_id][dir].map, i);
	}
	return 0;
}

static int
compare_pkt_data(struct rte_mbuf *m, uint8_t *ref, unsigned int tot_len)
{
	unsigned int nb_segs = m->nb_segs;
	struct rte_mbuf *save = m;
	unsigned int matched = 0;
	unsigned int len;

	while (m && nb_segs != 0) {
		len = tot_len;
		if (len > m->data_len)
			len = m->data_len;
		if (len != 0) {
			if (memcmp(rte_pktmbuf_mtod(m, char *), ref + matched, len)) {
				printf("\n====Test case failed: Data Mismatch");
				rte_hexdump(stdout, "Data", rte_pktmbuf_mtod(m, char *), len);
				rte_hexdump(stdout, "Reference", ref + matched, len);
				return -1;
			}
		}
		tot_len -= len;
		matched += len;
		m = m->next;
		nb_segs--;
	}

	if (tot_len) {
		printf("\n====Test casecase failed: Data Missing %u", tot_len);
		printf("\n====nb_segs %u, tot_len %u", nb_segs, tot_len);
		rte_pktmbuf_dump(stderr, save, -1);
		return -1;
	}
	return 0;
}

static void
dump_alg_data(struct ipsec_session_data *sess_conf)
{
	int i;

	if (sess_conf->aead && sess_conf->xform.aead.aead.algo == RTE_CRYPTO_AEAD_AES_GCM) {
		printf("Crypto Alg: AES-GCM-%u\n", sess_conf->xform.aead.aead.key.length * 8);
		printf("Crypto Key: ");
		for (i = 0; i < sess_conf->xform.aead.aead.key.length - 1; i++)
			printf("%02X", sess_conf->key.data[i]);
		printf("%02X\n", sess_conf->key.data[i]);

		printf("Crypto Salt: %02X%02X%02X%02X\n",
		       ((uint8_t *)(&sess_conf->ipsec_xform.salt))[0],
		       ((uint8_t *)(&sess_conf->ipsec_xform.salt))[1],
		       ((uint8_t *)(&sess_conf->ipsec_xform.salt))[2],
		       ((uint8_t *)(&sess_conf->ipsec_xform.salt))[3]);
	}
}

/* Create Inline IPsec session */
static int
create_inline_ipsec_session(struct ipsec_session_data *sa, uint16_t portid,
			    struct rte_security_session **ses,
			    enum rte_security_ipsec_sa_direction dir,
			    enum rte_security_ipsec_tunnel_type tun_type)
{
	uint32_t src_v4 = rte_cpu_to_be_32(RTE_IPV4(192, 168, 1, 2));
	uint32_t dst_v4 = rte_cpu_to_be_32(RTE_IPV4(192, 168, 1, 1));
	uint16_t src_v6[8] = {0x2607, 0xf8b0, 0x400c, 0x0c03, 0x0000, 0x0000, 0x0000, 0x001a};
	uint16_t dst_v6[8] = {0x2001, 0x0470, 0xe5bf, 0xdead, 0x4957, 0x2174, 0xe82c, 0x4887};
	struct rte_security_session_conf sess_conf = {
		.action_type = RTE_SECURITY_ACTION_TYPE_INLINE_PROTOCOL,
		.protocol = RTE_SECURITY_PROTOCOL_IPSEC,
		.ipsec = sa->ipsec_xform,
		.crypto_xform = &sa->xform.aead,
		.userdata = NULL,
	};
	const struct rte_security_capability *sec_cap;
	struct rte_security_ctx *sec_ctx;

	sess_conf.ipsec.direction = dir;
	sec_ctx = (struct rte_security_ctx *)rte_eth_dev_get_sec_ctx(portid);

	if (sec_ctx == NULL) {
		printf("Ethernet device doesn't support security features.\n");
		return -1;
	}

	sec_cap = rte_security_capabilities_get(sec_ctx);
	if (sec_cap == NULL) {
		printf("No capabilities registered\n");
		return -1;
	}

	/* iterate until ESP tunnel*/
	while (sec_cap->action != RTE_SECURITY_ACTION_TYPE_NONE) {
		if (sec_cap->action == sess_conf.action_type &&
		    sec_cap->protocol == RTE_SECURITY_PROTOCOL_IPSEC &&
		    sec_cap->ipsec.mode == sess_conf.ipsec.mode && sec_cap->ipsec.direction == dir)
			break;
		sec_cap++;
	}

	if (sec_cap->action == RTE_SECURITY_ACTION_TYPE_NONE) {
		printf("No suitable security capability found\n");
		return -1;
	}

	sess_conf.crypto_xform->aead.key.data = sa->key.data;

	/* Save SA as userdata for the security session. When
	 * the packet is received, this userdata will be
	 * retrieved using the metadata from the packet.
	 *
	 * The PMD is expected to set similar metadata for other
	 * operations, like rte_eth_event, which are tied to
	 * security session. In such cases, the userdata could
	 * be obtained to uniquely identify the security
	 * parameters denoted.
	 */

	sess_conf.userdata = (void *)sa;
	sess_conf.ipsec.tunnel.type = tun_type;
	if (tun_type == RTE_SECURITY_IPSEC_TUNNEL_IPV4) {
		memcpy(&sess_conf.ipsec.tunnel.ipv4.src_ip, &src_v4, sizeof(src_v4));
		memcpy(&sess_conf.ipsec.tunnel.ipv4.dst_ip, &dst_v4, sizeof(dst_v4));
	} else {
		memcpy(&sess_conf.ipsec.tunnel.ipv6.src_addr, &src_v6, sizeof(src_v6));
		memcpy(&sess_conf.ipsec.tunnel.ipv6.dst_addr, &dst_v6, sizeof(dst_v6));
	}

	*ses = rte_security_session_create(sec_ctx, &sess_conf, sess_pool);
	if (*ses == NULL) {
		printf("SEC Session init failed\n");
		return -1;
	}

	return 0;
}

static int
create_ipsec_laoutb_perf_session(struct ipsec_session_data *sa, uint16_t cdev_id,
				 struct rte_security_session **ses)
{
	uint32_t src_v4 = rte_cpu_to_be_32(RTE_IPV4(192, 168, 1, 2));
	uint32_t dst_v4 = rte_cpu_to_be_32(RTE_IPV4(192, 168, 1, 1));
	uint16_t src_v6[8] = {0x2607, 0xf8b0, 0x400c, 0x0c03, 0x0000, 0x0000, 0x0000, 0x001a};
	uint16_t dst_v6[8] = {0x2001, 0x0470, 0xe5bf, 0xdead, 0x4957, 0x2174, 0xe82c, 0x4887};
	struct rte_security_session_conf sess_conf = {
		.action_type = RTE_SECURITY_ACTION_TYPE_LOOKASIDE_PROTOCOL,
		.protocol = RTE_SECURITY_PROTOCOL_IPSEC,
		.ipsec = sa->ipsec_xform,
		.crypto_xform = &sa->xform.aead,
		.userdata = NULL,
	};
	union rte_event_crypto_metadata m_data;
	void *ctx = rte_cryptodev_get_sec_ctx(cdev_id);

	sa->spi = sa->ipsec_xform.spi;
	sess_conf.crypto_xform->aead.key.data = sa->key.data;
	sess_conf.userdata = (void *)sa;

	if (sess_conf.ipsec.tunnel.type == RTE_SECURITY_IPSEC_TUNNEL_IPV4) {
		memcpy(&sess_conf.ipsec.tunnel.ipv4.src_ip, &src_v4, sizeof(src_v4));
		memcpy(&sess_conf.ipsec.tunnel.ipv4.dst_ip, &dst_v4, sizeof(dst_v4));
	} else {
		memcpy(&sess_conf.ipsec.tunnel.ipv6.src_addr, &src_v6, sizeof(src_v6));
		memcpy(&sess_conf.ipsec.tunnel.ipv6.dst_addr, &dst_v6, sizeof(dst_v6));
	}

	*ses = rte_security_session_create(ctx, &sess_conf, cryptodev_session_pool);
	if (*ses == NULL) {
		printf("Cryptodev SEC Session init failed\n");
		return -1;
	}
	memset(&m_data, 0, sizeof(m_data));

	/* Fill in response information */
	m_data.response_info.sched_type = RTE_SCHED_TYPE_PARALLEL;
	m_data.response_info.op = RTE_EVENT_OP_NEW;
	m_data.response_info.queue_id = rte_eth_dev_count_avail() + 1;

	/* Fill in request information */
	m_data.request_info.cdev_id = cdev_id;
	m_data.request_info.queue_pair_id = 0;

	/* Attach meta info to session */
	rte_cryptodev_session_event_mdata_set(cdev_id, *ses, RTE_CRYPTO_OP_TYPE_SYMMETRIC,
			RTE_CRYPTO_OP_SECURITY_SESSION, &m_data, sizeof(m_data));

	return 0;
}

static int
create_ipsec_perf_session(struct ipsec_session_data *sa, uint16_t portid,
			  struct rte_security_session **ses)
{
	uint32_t src_v4 = rte_cpu_to_be_32(RTE_IPV4(192, 168, 1, 2));
	uint32_t dst_v4 = rte_cpu_to_be_32(RTE_IPV4(192, 168, 1, 1));
	uint16_t src_v6[8] = {0x2607, 0xf8b0, 0x400c, 0x0c03, 0x0000, 0x0000, 0x0000, 0x001a};
	uint16_t dst_v6[8] = {0x2001, 0x0470, 0xe5bf, 0xdead, 0x4957, 0x2174, 0xe82c, 0x4887};
	struct rte_security_session_conf sess_conf = {
		.action_type = RTE_SECURITY_ACTION_TYPE_INLINE_PROTOCOL,
		.protocol = RTE_SECURITY_PROTOCOL_IPSEC,
		.ipsec = sa->ipsec_xform,
		.crypto_xform = &sa->xform.aead,
		.userdata = NULL,
	};
	struct rte_security_ctx *sec_ctx;
	uint32_t sa_index = sa->ipsec_xform.spi;
	uint16_t sa_hi = 0, sa_lo = 0;
	uint32_t spi = 0;
	bool inbound;
	int ret;

	switch (action_alg) {
	case RTE_PMD_CNXK_SEC_ACTION_ALG0:
		spi = (0x2 << 28 | sa_index);
		sa_hi = (spi >> 16) & 0xffff;
		sa_lo = 0x0;
		break;
	case RTE_PMD_CNXK_SEC_ACTION_ALG1:
		/* Only SPI[31:28] are considered as SA[3:0] hence use.
		 * rest from SPI[15:4].
		 */
		spi = ((sa_index & 0xF) << 28) | ((sa_index >> 4) << 4);
		sa_hi = (spi >> 16) & 0xffff;
		sa_lo = 0x0000;
		break;
	case RTE_PMD_CNXK_SEC_ACTION_ALG2:
		/* Only SPI[27:25] are considered as SA[2:0] hence use.
		 * rest from SPI[15:3].
		 */
		spi = ((sa_index & 0x7) << 25) | ((sa_index >> 3) << 3);
		sa_hi = (spi >> 16) & 0xffff;
		sa_lo = 0x0000;
		break;
	case RTE_PMD_CNXK_SEC_ACTION_ALG3:
		/* Only SPI[28:25] are considered as SA[3:0] hence use.
		 * rest from SPI[15:4].
		 */
		spi = ((sa_index & 0xF) << 25) | ((sa_index >> 4) << 4);
		sa_hi = (spi >> 16) & 0xffff;
		sa_lo = 0x0000;
		break;
	default:
		spi = sa_index;
		break;
	}

	sa->spi = sa->ipsec_xform.spi;
	sec_ctx = rte_eth_dev_get_sec_ctx(portid);
	sess_conf.crypto_xform->aead.key.data = sa->key.data;

	/* Save SA as userdata for the security session. When
	 * the packet is received, this userdata will be
	 * retrieved using the metadata from the packet.
	 *
	 * The PMD is expected to set similar metadata for other
	 * operations, like rte_eth_event, which are tied to
	 * security session. In such cases, the userdata could
	 * be obtained to uniquely identify the security
	 * parameters denoted.
	 */

	sess_conf.userdata = (void *)sa;
	if (sess_conf.ipsec.tunnel.type == RTE_SECURITY_IPSEC_TUNNEL_IPV4) {
		memcpy(&sess_conf.ipsec.tunnel.ipv4.src_ip, &src_v4, sizeof(src_v4));
		memcpy(&sess_conf.ipsec.tunnel.ipv4.dst_ip, &dst_v4, sizeof(dst_v4));
	} else {
		memcpy(&sess_conf.ipsec.tunnel.ipv6.src_addr, &src_v6, sizeof(src_v6));
		memcpy(&sess_conf.ipsec.tunnel.ipv6.dst_addr, &dst_v6, sizeof(dst_v6));
	}
	sess_conf.ipsec.options.esn = esn_en;
	sess_conf.ipsec.options.stats = ipsec_stats;
	sess_conf.ipsec.replay_win_sz = esn_ar;

	*ses = rte_security_session_create(sec_ctx, &sess_conf, sess_pool);
	if (*ses == NULL) {
		printf("SEC Session init failed\n");
		return -1;
	}

	inbound = sa->ipsec_xform.direction;
	printf("Port %d: Created %s session with SPI = 0x%x\n", portid,
	       inbound ? "inbound" : "outbound", sa->spi);

	sess_conf.ipsec.spi = spi;
	ret = rte_security_session_update(sec_ctx, *ses, &sess_conf);
	if (ret) {
		printf("Port %d: %s session update failed for SA Index=%d SPI: %d\n", portid,
		       sa->ipsec_xform.direction ? "inbound" : "outbound", sa_index, spi);
		rte_security_session_destroy(sec_ctx, *ses);
		return -1;
	}

	printf("Port %d: Updated %s session with SPI = 0x%x\n", portid,
	       inbound ? "inbound" : "outbound", spi);

	if (inbound && (action_alg != DEFAULT_SEC_ACTION_ALG)) {
		/* Create all flow rules on port 0 and it would get applied on all ports due
		 * to channel mask.
		 */
		ret = create_default_flow(portid, action_alg, spi, sa_lo, sa_hi, sa_index);
		if (ret) {
			printf("Flow creation failed\n");
			return -1;
		}
	}

	return 0;
}

static __rte_always_inline void
handle_inb_oop(struct rte_mbuf *mbuf)
{
	struct rte_mbuf *orig = *(struct rte_mbuf **)rte_security_oop_dynfield(mbuf);

	if (orig == NULL)
		abort();
	/* Free original buffer */
	rte_pktmbuf_free(orig);
}

#if !defined(MSNS_CN9K)
static void
handle_inb_soft_exp(uint16_t port_id, struct rte_mbuf *mbuf, uint32_t lcore_id)
{
	struct lcore_cfg *info = &lcore_cfg[lcore_id];
	struct rte_security_session *in_ses;
	struct ipsec_session_data *sa_data;
	union rte_pmd_cnxk_cpt_res_s *res;
	struct rte_security_ctx *sec_ctx;
	int spi, ret;

	res = rte_pmd_cnxk_inl_ipsec_res(mbuf);
	if (!res)
		return;

	if (res->cn10k.uc_compcode != 0xf0)
		return;

	sec_ctx = rte_eth_dev_get_sec_ctx(port_id);
	sa_data = (struct ipsec_session_data *) *rte_security_dynfield(mbuf);
	spi = sa_data->spi;

	in_ses = inb_sas[spi].sa;
	if (unlikely(in_ses == NULL)) {
		printf("Invalid SA reported\n");
		return;
	}
	rte_spinlock_lock(&exp_ses_dest_lock);
	if (rte_security_session_destroy(sec_ctx, in_ses)) {
		printf("Session Destroy failed for SPI: %d\n", spi);
		return;
	}

	ret = create_ipsec_perf_session(sa_data, port_id, &inb_sas[spi].sa);
	if (!ret)
		info->num_inb_sas += 1;

	rte_spinlock_unlock(&exp_ses_dest_lock);
}
#endif

/* Check the link status of all ports in up to 3s, and print them finally */
static void
check_all_ports_link_status(uint32_t port_mask)
{
#define CHECK_INTERVAL 100 /* 100ms */
#define MAX_CHECK_TIME 30  /* 3s (30 * 100ms) in total */
	uint8_t count, all_ports_up, print_flag = 0;
	char link_status[RTE_ETH_LINK_MAX_STR_LEN];
	struct rte_eth_link link;
	uint16_t portid;
	int ret;

	printf("Checking link statuses...\n");
	fflush(stdout);
	for (count = 0; count <= MAX_CHECK_TIME; count++) {
		all_ports_up = 1;
		RTE_ETH_FOREACH_DEV(portid) {
			if ((port_mask & RTE_BIT64(portid)) == 0)
				continue;
			memset(&link, 0, sizeof(link));
			ret = rte_eth_link_get_nowait(portid, &link);
			if (ret < 0) {
				all_ports_up = 0;
				if (print_flag == 1)
					printf("Port %u link get failed: %s\n", portid,
					       rte_strerror(-ret));
				continue;
			}

			/* print link status if flag set */
			if (print_flag == 1) {
				rte_eth_link_to_str(link_status, sizeof(link_status), &link);
				printf("Port %d %s\n", portid, link_status);
				continue;
			}
			/* clear all_ports_up flag if any link down */
			if (link.link_status == RTE_ETH_LINK_DOWN) {
				all_ports_up = 0;
				break;
			}
		}
		/* after finally printing all link status, get out */
		if (print_flag == 1)
			break;

		if (all_ports_up == 0) {
			fflush(stdout);
			rte_delay_ms(CHECK_INTERVAL);
		}

		/* set the print_flag if all ports up or timeout */
		if (all_ports_up == 1 || count == (MAX_CHECK_TIME - 1))
			print_flag = 1;
	}
}

static void
print_ethaddr(const char *name, const struct rte_ether_addr *eth_addr)
{
	char buf[RTE_ETHER_ADDR_FMT_SIZE];

	rte_ether_format_addr(buf, RTE_ETHER_ADDR_FMT_SIZE, eth_addr);
	printf("%s%s", name, buf);
}

static void
copy_buf_to_pkt_segs(void *buf, unsigned int len, struct rte_mbuf *pkt, unsigned int offset)
{
	unsigned int copy_len;
	struct rte_mbuf *seg;
	void *seg_buf;

	seg = pkt;
	while (offset >= seg->data_len) {
		offset -= seg->data_len;
		seg = seg->next;
	}
	copy_len = seg->data_len - offset;
	seg_buf = rte_pktmbuf_mtod_offset(seg, char *, offset);
	while (len > copy_len) {
		rte_memcpy(seg_buf, buf, (size_t)copy_len);
		len -= copy_len;
		buf = ((char *)buf + copy_len);
		seg = seg->next;
		seg_buf = rte_pktmbuf_mtod(seg, void *);
	}
	rte_memcpy(seg_buf, buf, (size_t)len);
}

static inline void
copy_buf_to_pkt(void *buf, unsigned int len, struct rte_mbuf *pkt, unsigned int offset)
{
	if (offset + len <= pkt->data_len) {
		rte_memcpy(rte_pktmbuf_mtod_offset(pkt, char *, offset), buf, (size_t)len);
		return;
	}
	copy_buf_to_pkt_segs(buf, len, pkt, offset);
}

static inline int
init_traffic(struct rte_mempool *mp, struct rte_mbuf **pkts_burst,
	     struct ipsec_test_packet *vectors)
{
	struct rte_mbuf *pkt;

	pkt = rte_pktmbuf_alloc(mp);
	if (pkt == NULL)
		return -1;

	pkt->data_len = vectors->len;
	pkt->pkt_len = vectors->len;
	copy_buf_to_pkt(vectors->data, vectors->len, pkt, 0);
	pkts_burst[0] = pkt;
	return 0;
}

static void
init_lcore(void)
{
	uint16_t ev_port_id = 0;
	unsigned int lcore_id;

	for (lcore_id = 0; lcore_id < RTE_MAX_LCORE; lcore_id++) {
		lcore_cfg[lcore_id].socketid = rte_lcore_to_socket_id(lcore_id);
		if (rte_lcore_is_enabled(lcore_id) != 0) {
			if (event_en) {
				/* Assign event port id */
				lcore_cfg[lcore_id].eventdev_id = 0;
				lcore_cfg[lcore_id].event_port_id = -1;
				if (ev_port_id >= nb_event_ports)
					continue;
				lcore_cfg[lcore_id].event_port_id = ev_port_id++;
			} else {
				lcore_cfg[lcore_id].portid = 0;
			}
		}
	}
}

static int
init_sess_mempool(void)
{
	struct rte_security_ctx *sec_ctx;
	uint16_t nb_sess = RTE_MAX(num_sas * 2, 2048ul);
	uint32_t sess_sz;
	int socketid = 0;
	char s[64];

	sec_ctx = rte_eth_dev_get_sec_ctx(0);
	if (sec_ctx == NULL)
		return -ENOENT;

	sess_sz = rte_security_session_get_size(sec_ctx);
	if (sess_pool == NULL) {
		snprintf(s, sizeof(s), "sess_pool_%d", socketid);
		sess_pool = rte_mempool_create(s, nb_sess, sess_sz, MEMPOOL_CACHE_SIZE, 0,
					       NULL, NULL, NULL, NULL, socketid, 0);
		if (sess_pool == NULL) {
			printf("Cannot init sess pool on socket %d\n", socketid);
			return -1;
		}
		printf("Allocated sess pool on socket %d\n", socketid);
	}
	return 0;
}

static int
init_pktmbuf_pool(uint32_t portid, unsigned int nb_mbuf)
{
	int socketid = 0;
	char s[64];

	if (mbufpool[portid] == NULL) {
		snprintf(s, sizeof(s), "mbuf_pool_%d", portid);
		mbufpool[portid] = rte_pktmbuf_pool_create(s, nb_mbuf, MEMPOOL_CACHE_SIZE,
							   MEMPOOL_PRV_AREA_SIZE,
							   RTE_MBUF_DEFAULT_BUF_SIZE, socketid);
		if (mbufpool[portid] == NULL) {
			printf("Cannot init mbuf pool on socket %d\n", socketid);
			return -1;
		}
		printf("Allocated mbuf pool for port %d\n", portid);
	}
	return 0;
}

int
create_default_flow(uint16_t port_id, enum rte_pmd_cnxk_sec_action_alg alg, uint32_t spi,
		    uint16_t sa_lo, uint16_t sa_hi, uint32_t sa_index)
{
	struct rte_pmd_cnxk_sec_action sec = {0};
	struct rte_flow_action_mark mark = {0};
	struct rte_flow_item_esp mesp = {0};
	struct rte_flow_item_esp esp = {0};
	struct rte_flow_action action[3];
	struct rte_flow_item pattern[2];
	struct rte_flow_attr attr = {0};
	struct rte_flow_error err;
	struct rte_flow *flow;
	int act_count = 0;
	int ret;

	/* Add the default rte_flow to enable SECURITY for all ESP packets */
	pattern[0].type = RTE_FLOW_ITEM_TYPE_ESP;
	pattern[0].spec = &esp;
	pattern[0].mask = &mesp;
	pattern[0].last = NULL;
	pattern[1].type = RTE_FLOW_ITEM_TYPE_END;

	action[act_count].type = RTE_FLOW_ACTION_TYPE_SECURITY;
	action[act_count].conf = &sec;
	act_count++;

	esp.hdr.spi = RTE_BE32(spi);
	mesp.hdr.spi = RTE_BE32(0xffffffff);
	switch (alg) {
	case RTE_PMD_CNXK_SEC_ACTION_ALG0:
		/* SPI = 0x10000001, sa_index = 0 */
		sec.alg = RTE_PMD_CNXK_SEC_ACTION_ALG0;
		sec.sa_xor = 1;
		sec.sa_hi = sa_hi;
		sec.sa_lo = sa_lo;
		break;
	case RTE_PMD_CNXK_SEC_ACTION_ALG1:
		/* SPI = 0x10000001, sa_index = 1 */
		sec.alg = RTE_PMD_CNXK_SEC_ACTION_ALG1;
		sec.sa_xor = 1;
		sec.sa_hi = sa_hi;
		sec.sa_lo = sa_lo;
		break;
	case RTE_PMD_CNXK_SEC_ACTION_ALG2:
		/* SPI = 0x04000001, sa_index = 2 */
		sec.alg = RTE_PMD_CNXK_SEC_ACTION_ALG2;
		sec.sa_xor = 1;
		sec.sa_hi = sa_hi;
		sec.sa_lo = sa_lo;
		break;
	case RTE_PMD_CNXK_SEC_ACTION_ALG3:
		/* SPI = 0x04000001, sa_index = 2 */
		sec.alg = RTE_PMD_CNXK_SEC_ACTION_ALG3;
		sec.sa_xor = 1;
		sec.sa_hi = sa_hi;
		sec.sa_lo = sa_lo;
		break;
	case RTE_PMD_CNXK_SEC_ACTION_ALG4:
		/* SPI = 0x100, sa_index = 3 */
		sec.alg = RTE_PMD_CNXK_SEC_ACTION_ALG4;
		sec.sa_xor = 0;
		sec.sa_hi = sa_hi;
		sec.sa_lo = sa_lo;
		sec.sa_index = sa_index;
		esp.hdr.spi = RTE_BE32(0x100);
		mesp.hdr.spi = RTE_BE32(0xffffffff);
		mark.id = 0x200;
		action[act_count].type = RTE_FLOW_ACTION_TYPE_MARK;
		action[act_count].conf = &mark;
		act_count++;
		break;
	}

	action[act_count].type = RTE_FLOW_ACTION_TYPE_END;
	action[act_count].conf = NULL;
	attr.ingress = 1;

	ret = rte_flow_validate(port_id, &attr, pattern, action, &err);
	if (ret)
		return ret;

	flow = rte_flow_create(port_id, &attr, pattern, action, &err);
	if (flow == NULL) {
		printf("\nDefault flow rule create failed\n");
		return -1;
	}

	default_flow[port_id][alg] = flow;
	return 0;
}

static void
destroy_default_flow(uint16_t port_id)
{
	struct rte_flow_error err;
	uint8_t alg;
	int ret;

	for (alg = RTE_PMD_CNXK_SEC_ACTION_ALG0; alg <= RTE_PMD_CNXK_SEC_ACTION_ALG4; alg++) {
		if (!default_flow[port_id][alg])
			continue;
		ret = rte_flow_destroy(port_id, default_flow[port_id][alg], &err);
		if (ret) {
			printf("\nDefault flow rule destroy failed for port=%d alg=%d, rc=%d\n",
			       port_id, alg, ret);
			return;
		}
		default_flow[port_id][alg] = NULL;
	}
}

static int
ut_eventdev_stop(void)
{
	int rc = 0;

	rte_event_dev_stop(eventdev_id);
	rc = rte_event_eth_rx_adapter_stop(rx_adapter_id);
	rc |= rte_event_eth_tx_adapter_stop(tx_adapter_id);
	return rc;
}

static int
ut_eventdev_start(void)
{
	int rc = 0;

	rc |= rte_event_eth_rx_adapter_start(rx_adapter_id);
	rc |= rte_event_eth_tx_adapter_start(tx_adapter_id);
	rc = rte_event_dev_start(eventdev_id);
	return rc;
}

static int
ut_eventdev_setup(void)
{
	struct rte_event_crypto_adapter_queue_conf crypto_queue_conf;
	struct rte_event_eth_rx_adapter_queue_conf queue_conf;
	struct rte_event_dev_info evdev_default_conf = {0};
	struct rte_event_dev_config eventdev_conf = {0};
	struct rte_event_queue_conf eventq_conf = {0};
	struct rte_event_port_conf ev_port_conf = {0};
	const int all_queues = -1;
	uint8_t ev_queue_id = 0;
	int portid, ev_port_id, cdev_id = 0;
	uint32_t caps = 0;
	int ret;

	/* Setup eventdev */
	eventdev_id = 0;
	rx_adapter_id = 0;
	tx_adapter_id = 0;

	/* Get default conf of eventdev */
	ret = rte_event_dev_info_get(eventdev_id, &evdev_default_conf);
	if (ret < 0) {
		printf("Error in getting event device info[devID:%d]\n",
		       eventdev_id);
		return ret;
	}
	nb_event_ports = rte_lcore_count();
	nb_event_queues = evdev_default_conf.max_event_queues;

	/* Get Tx adapter capabilities */
	ret = rte_event_eth_tx_adapter_caps_get(eventdev_id, tx_adapter_id, &caps);
	if (ret < 0) {
		printf("Failed to get event device %d eth tx adapter"
		       " capabilities\n",
		       eventdev_id);
		return ret;
	}

	eventdev_conf.nb_events_limit =
		evdev_default_conf.max_num_events;
	eventdev_conf.nb_event_queue_flows =
		evdev_default_conf.max_event_queue_flows;
	eventdev_conf.nb_event_port_dequeue_depth =
		evdev_default_conf.max_event_port_dequeue_depth;
	eventdev_conf.nb_event_port_enqueue_depth =
		evdev_default_conf.max_event_port_enqueue_depth;

	eventdev_conf.nb_event_queues = nb_event_queues;
	eventdev_conf.nb_event_ports = nb_event_ports;

	/* Configure event device */

	ret = rte_event_dev_configure(eventdev_id, &eventdev_conf);
	if (ret < 0) {
		printf("Error in configuring event device\n");
		return ret;
	}

	/* Configure event queue */
	eventq_conf.schedule_type = RTE_SCHED_TYPE_PARALLEL;
	eventq_conf.nb_atomic_flows = 1024;
	eventq_conf.nb_atomic_order_sequences = 1024;

	/* Setup the queue */
	for (ev_queue_id = 0; ev_queue_id < nb_event_queues; ev_queue_id++) {
		ret = rte_event_queue_setup(eventdev_id, ev_queue_id, &eventq_conf);
		if (ret < 0) {
			printf("Failed to setup event queue %d, rc=%d\n", ev_queue_id, ret);
			return ret;
		}
	}

	/* Configure event port */
	for (ev_port_id = 0; ev_port_id < nb_event_ports; ev_port_id++) {
		ret = rte_event_port_setup(eventdev_id, ev_port_id, NULL);
		if (ret < 0) {
			printf("Failed to setup event port %d\n", ret);
			return ret;
		}

		/* Make event queue - event port link */
		ret = rte_event_port_link(eventdev_id, ev_port_id, NULL, NULL, 1);
		if (ret < 0) {
			printf("Failed to link event port %d\n", ret);
			return ret;
		}
	}

	/* Setup port conf */
	ev_port_conf.new_event_threshold = 1200;
	ev_port_conf.dequeue_depth =
		evdev_default_conf.max_event_port_dequeue_depth;
	ev_port_conf.enqueue_depth =
		evdev_default_conf.max_event_port_enqueue_depth;

	/* Create Rx adapter */
	ret = rte_event_eth_rx_adapter_create(rx_adapter_id, eventdev_id,
					      &ev_port_conf);
	if (ret < 0) {
		printf("Failed to create rx adapter %d\n", ret);
		return ret;
	}

	/* Create tx adapter */
	ret = rte_event_eth_tx_adapter_create(tx_adapter_id, eventdev_id,
					      &ev_port_conf);
	if (ret < 0) {
		printf("Failed to create tx adapter %d\n", ret);
		return ret;
	}

	RTE_ETH_FOREACH_DEV(portid) {
		if ((ethdev_port_mask & RTE_BIT64(portid)) == 0)
			continue;
		/* Setup queue conf */
		memset(&queue_conf, 0, sizeof(queue_conf));
		queue_conf.ev.queue_id = portid % nb_event_queues;
		queue_conf.ev.sched_type = RTE_SCHED_TYPE_PARALLEL;
		queue_conf.ev.event_type = RTE_EVENT_TYPE_ETHDEV;

		if (vector_en) {
			/* Event vector enable */
			queue_conf.vector_sz = vector_sz;
			queue_conf.vector_timeout_ns = VECTOR_TMO_NS_DEFAULT;
			queue_conf.vector_mp = vector_pool[portid];
			queue_conf.rx_queue_flags |= RTE_EVENT_ETH_RX_ADAPTER_QUEUE_EVENT_VECTOR;
		}

		/* Add queue to the adapter */
		ret = rte_event_eth_rx_adapter_queue_add(rx_adapter_id, portid,
							 all_queues, &queue_conf);
		if (ret < 0) {
			printf("Failed to add eth queue to rx adapter %d\n", ret);
			return ret;
		}

		/* Add queue to the adapter */
		ret = rte_event_eth_tx_adapter_queue_add(tx_adapter_id, portid,
							 all_queues);
		if (ret < 0) {
			printf("Failed to add eth queue to tx adapter %d\n", ret);
			return ret;
		}

	}
	/* Start rx adapter */
	ret = rte_event_eth_rx_adapter_start(rx_adapter_id);
	if (ret < 0) {
		printf("Failed to start rx adapter %d\n", ret);
		return ret;
	}

	/* Start tx adapter */
	ret = rte_event_eth_tx_adapter_start(tx_adapter_id);
	if (ret < 0) {
		printf("Failed to start tx adapter %d\n", ret);
		return ret;
	}

	if (testmode != EVENT_IPSEC_INB_LAOUTB_PERF)
		goto eventdev_start;

	/* Create event crypto adapter */
	ret = rte_event_crypto_adapter_caps_get(eventdev_id, cdev_id, &caps);
	if (ret < 0) {
		printf("Failed to get event device's crypto capabilities %d", ret);
		return ret;
	}

	if (!(caps & RTE_EVENT_CRYPTO_ADAPTER_CAP_INTERNAL_PORT_OP_FWD)) {
		printf("Event crypto adapter does not support forward mode!");
		return -EINVAL;
	}

	ev_port_conf.new_event_threshold = evdev_default_conf.max_num_events;
	ev_port_conf.dequeue_depth = evdev_default_conf.max_event_port_dequeue_depth;
	ev_port_conf.enqueue_depth = evdev_default_conf.max_event_port_enqueue_depth;

	/* Create adapter */
	ret = rte_event_crypto_adapter_create(cdev_id, eventdev_id, &ev_port_conf,
					      RTE_EVENT_CRYPTO_ADAPTER_OP_FORWARD);
	if (ret < 0) {
		printf("Failed to create event crypto adapter %d", ret);
		return ret;
	}

	memset(&crypto_queue_conf, 0, sizeof(crypto_queue_conf));

	/* Add crypto queue pairs to event crypto adapter */
	ret = rte_event_crypto_adapter_queue_pair_add(cdev_id, eventdev_id,
			-1, /* adds all the pre configured queue pairs to the instance */
			&crypto_queue_conf);
	if (ret < 0) {
		printf("Failed to add queue pairs to event crypto adapter %d", ret);
		return ret;
	}
	ret = rte_event_crypto_adapter_start(cdev_id);
	if (ret < 0) {
		printf("Failed to start event crypto device %d (%d)", cdev_id, ret);
		return ret;
	}

eventdev_start:
	/* Start eventdev */
	ret = rte_event_dev_start(eventdev_id);
	if (ret < 0) {
		printf("Failed to start event device %d\n", ret);
		return ret;
	}

	/* Stop event dev before traffic */
	ut_eventdev_stop();

	return 0;
}

static void
ut_eventdev_teardown(void)
{
	int ret;
	int portid;

	/* Stop rx adapter */
	ret = rte_event_eth_rx_adapter_stop(rx_adapter_id);
	if (ret < 0)
		printf("Failed to stop rx adapter %d\n", ret);

	/* Stop tx adapter */
	ret = rte_event_eth_tx_adapter_stop(tx_adapter_id);
	if (ret < 0)
		printf("Failed to stop tx adapter %d\n", ret);

	RTE_ETH_FOREACH_DEV(portid) {
		if ((ethdev_port_mask & RTE_BIT64(portid)) == 0)
			continue;
		ret = rte_event_eth_rx_adapter_queue_del(rx_adapter_id, portid, -1);
		if (ret < 0)
			printf("Failed to remove rx adapter queues %d\n", ret);
		ret = rte_event_eth_tx_adapter_queue_del(tx_adapter_id, portid, -1);
		if (ret < 0)
			printf("Failed to remove tx adapter queues %d\n", ret);
	}

	/* Release rx adapter */
	ret = rte_event_eth_rx_adapter_free(rx_adapter_id);
	if (ret < 0)
		printf("Failed to free rx adapter %d\n", ret);

	/* Release tx adapter */
	ret = rte_event_eth_tx_adapter_free(tx_adapter_id);
	if (ret < 0)
		printf("Failed to free tx adapter %d\n", ret);

	if (testmode == EVENT_IPSEC_INB_LAOUTB_PERF) {
		ret = rte_event_crypto_adapter_stop(0);
		if (ret < 0)
			printf("Failed to stop event crypto device %d", ret);
	}
	/* Stop and release event devices */
	rte_event_dev_stop(eventdev_id);
	ret = rte_event_dev_close(eventdev_id);
	if (ret < 0)
		printf("Failed to close event dev %d, %d\n", eventdev_id, ret);
}

static void
print_usage(const char *name)
{
	printf("Invalid arguments\n");
	printf("Usage: %s ", name);
	fprintf(stderr, "Usage: %s [arguments]\n"
		"\t[--testmode <N>]\n"
		"\t\t\t0: IPSEC_MSNS\n"
		"\t\t\t1: EVENT_IPSEC_INB_MSNS_PERF\n"
		"\t\t\t2: EVENT_IPSEC_INB_PERF\n"
		"\t\t\t3: EVENT_IPSEC_INB_OUTB_PERF\n"
		"\t\t\t4: EVENT_IPSEC_INB_LAOUTB_PERF\n"
		"\t\t\t5: POLL_IPSEC_INB_OUTB_PERF\n"
		"\t\t\t6: IPSEC_RTE_PMD_CNXK_API_TEST\n"
		"\t\t\t7: POLL_IPSEC_INB_PERF\n"
		"\t\t\t8: POLL_IPSEC_OUTB_PERF\n"
		"\t\t\t9: EVENT_IPSEC_OUTB_PERF\n"
		"\t[--timeout <sec>]     Timeout in seconds for stats print\n"
		"\t[--pfc]               Enable PFC with EVENT_IPSEC_INB_MSNS_PERF\n"
		"\t[--portmask]	          Port mask to enable\n"
		"\t[--nb-mbufs <count >]  MBUFs per packet pool\n"
		"\t[--num-sas <count>]    Number of SA's to create\n"
		"\t[--softexp-en]         Enable soft expiry on SA's\n"
		"\t[--softlimit <count>]  Soft expiry pkt limit\n"
		"\t[--inl-inb-oop]        Enable inline inbound OOP\n"
		"\t[--action-alg]         Use SA_XOR action algo for perf test\n"
		"\t[--ipsec-stats-en]     Enable IPSEC stats\n"
		"\t[--vector-en]          Enable vector mode with eventdev. Default is disabled\n"
		"\t[--vector-sz <size>]   Set vector size. Default is 32.\n"
		"\t[--esn-ar <winsz>]     Enable ESN with anti-replay window size\n"
		"\t[--esn]                Enable ESN on SAs\n"
		"\t[--verbose]            Enable verbose mode\n"
		"\t[--algo <aes_128_gcm|aes_256_gcm>] Cipher algorithm to use\n",
		name);
}

static int
parse_args(int argc, char **argv)
{
	char *name = argv[0];

	argc--;
	argv++;
	while (argc) {
		if (!strcmp(argv[0], "--testmode") && (argc > 1)) {
			testmode = strtoul(argv[1], NULL, 0);
			if (testmode == EVENT_IPSEC_INB_MSNS_PERF ||
			    testmode == EVENT_IPSEC_INB_OUTB_PERF ||
			    testmode == EVENT_IPSEC_INB_LAOUTB_PERF ||
			    testmode == EVENT_IPSEC_INB_PERF ||
			    testmode == EVENT_IPSEC_OUTB_PERF ||
			    testmode == IPSEC_RTE_PMD_CNXK_API_TEST)
				event_en = true;
			else
				poll_mode = true;

			argc -= 2;
			argv += 2;
			continue;
		}

		if (!strcmp(argv[0], "--pfc")) {
			pfc = true;
			argc--;
			argv++;
			continue;
		}

		if (!strcmp(argv[0], "--portmask") && (argc > 1)) {
			ethdev_port_mask = strtoul(argv[1], NULL, 0);
			argc -= 2;
			argv += 2;
			continue;
		}

		if (!strcmp(argv[0], "--nb-mbufs") && (argc > 1)) {
			nb_bufs = atoi(argv[1]);
			argc-=2;
			argv+=2;
			continue;
		}

		if (!strcmp(argv[0], "--num-sas") && (argc > 1)) {
			num_sas = atoi(argv[1]);
			if (num_sas > MAX_SA_SIZE) {
				printf("Number of SAs given is greater than MAX SAs\n");
				return -1;
			}
			argc -= 2;
			argv += 2;
			continue;
		}

		if (!strcmp(argv[0], "--verbose")) {
			verbose = true;
			argc--;
			argv++;
			continue;
		}

		if (!strcmp(argv[0], "--softexp-en")) {
			softexp = true;
			argc--;
			argv++;
			continue;
		}

		if (!strcmp(argv[0], "--inl-inb-oop")) {
			inl_inb_oop = true;
			argc--;
			argv++;
			continue;
		}

		if (!strcmp(argv[0], "--ipsec-stats-en")) {
			ipsec_stats = true;
			argc--;
			argv++;
			continue;
		}

		if (!strcmp(argv[0], "--action-alg") && (argc > 1)) {
			action_alg = strtoul(argv[1], NULL, 0);
			argc -= 2;
			argv += 2;
			if (action_alg > RTE_PMD_CNXK_SEC_ACTION_ALG4) {
				printf("Not supported security action alg %d\n", action_alg);
				printf("Default IPsec flow will be applied\n");
				action_alg = DEFAULT_SEC_ACTION_ALG; /* Default flow */
			}
			continue;
		}

		if (!strcmp(argv[0], "--softlimit") && (argc > 1)) {
			soft_limit = atoi(argv[1]);
			argc -= 2;
			argv += 2;
			continue;
		}

		if (!strcmp(argv[0], "--esn-ar") && (argc > 1)) {
			esn_ar = atoi(argv[1]);
			esn_en = true;
			argc -= 2;
			argv += 2;
			continue;
		}

		if (!strcmp(argv[0], "--esn")) {
			esn_en = true;
			argc -= 1;
			argv += 1;
			continue;
		}

		if (!strcmp(argv[0], "--algo")) {
			const char *alg = argv[1];

			argc -= 2;
			argv += 2;
			if (!strcmp(alg, "aes-128-gcm")) {
				sess_conf = &conf_aes_128_gcm;
				continue;
			} else if (!strcmp(alg, "aes-256-gcm")) {
				sess_conf = &conf_aes_256_gcm;
				continue;
			} else {
				printf("Invalid algo %s\n", alg);
			}
		}

		if (!strcmp(argv[0], "--vector-en")) {
			vector_en = true;
			argc--;
			argv++;
			continue;
		}
		if (!strcmp(argv[0], "--vector-sz") && (argc > 1)) {
			vector_sz = strtoul(argv[1], NULL, 0);
			argc -= 2;
			argv += 2;
			continue;
		}

		if (!strcmp(argv[0], "--timeout") && (argc > 1)) {
			stats_tmo = strtoul(argv[1], NULL, 0);
			argc -= 2;
			argv += 2;
			continue;
		}

		/* Unknown args */
		print_usage(name);
		return -1;
	}

	return 0;
}

static int
port_init(uint16_t portid, uint32_t nb_mbufs, uint16_t nb_rx_queue, uint16_t nb_tx_queue,
	  uint16_t nb_rxd, uint16_t nb_txd)
{
	uint16_t queueid, lcore_id;
	struct lcore_cfg *lconf;
	int socketid = 0, ret;

	ret = init_pktmbuf_pool(portid, nb_mbufs);
	if (ret) {
		printf("Failed to setup pktmbuf pool for port=%d, ret=%d", portid, ret);
		return ret;
	}

	if (vector_en && vector_pool[portid] == NULL) {
		unsigned int nb_vec;
		char s[64];

		nb_vec = (nb_mbufs + vector_sz - 1) / vector_sz;
		nb_vec = RTE_MAX(512U, nb_vec);
		nb_vec += rte_lcore_count() * 32;
		snprintf(s, sizeof(s), "vector_pool_%d", portid);
		vector_pool[portid] = rte_event_vector_pool_create(s, nb_vec, 32, vector_sz,
								   socketid);
		if (vector_pool[portid] == NULL) {
			printf("Failed to create vector pool for port %d\n", portid);
			return -ENOMEM;
		}
		printf("Allocated vector pool for port %d\n", portid);
	}

	/* Enable loopback mode for non perf test */
	port_conf.lpbk_mode = (testmode == IPSEC_MSNS || testmode == IPSEC_RTE_PMD_CNXK_API_TEST) ?
			       1 : 0;

	/* port configure */
	ret = rte_eth_dev_configure(portid, nb_rx_queue, nb_tx_queue, &port_conf);
	if (ret < 0) {
		printf("Cannot configure device: err=%d, port=%d\n", ret, portid);
		return ret;
	}
	ret = rte_eth_macaddr_get(portid, &ports_eth_addr[portid]);
	if (ret < 0) {
		printf("Cannot get mac address: err=%d, port=%d\n", ret, portid);
		return ret;
	}
	printf("Port %u ", portid);
	print_ethaddr("Address:", &ports_eth_addr[portid]);
	printf("\n");

	queueid = 0;
	for (lcore_id = 0; lcore_id < RTE_MAX_LCORE; lcore_id++) {

		if (rte_lcore_is_enabled(lcore_id) == 0)
			continue;

		if (lcore_id == rte_get_main_lcore())
			continue;

		if (queueid == nb_tx_queue)
			break;

		/* init TX queue */
		printf("Setup txq=%u,%d,%d\n", lcore_id, queueid, socketid);

		ret = rte_eth_tx_queue_setup(portid, queueid, nb_txd, socketid, &tx_conf);
		if (ret < 0) {
			printf("rte_eth_tx_queue_setup: err=%d, port=%d\n", ret, portid);
			return ret;
		}

		printf("Setup rxq=%u,%d,%d\n", lcore_id, queueid, socketid);
		ret = rte_eth_rx_queue_setup(portid, queueid, nb_rxd, socketid, &rx_conf,
					     mbufpool[portid]);
		if (ret < 0) {
			printf("rte_eth_rx_queue_setup: err=%d, port=%d\n", ret, portid);
			return ret;
		}

		lconf = &lcore_cfg[lcore_id];
		lconf->queueid = queueid;

		queueid++;
	}

	/* Init sa_index map with 4K size*/
	ret = cnxk_sa_index_init(portid, RTE_SECURITY_IPSEC_SA_DIR_EGRESS, MAX_SA_SIZE);
	if (ret) {
		printf("egress sa index init failed: err=%d, port=%d\n", ret, portid);
		return ret;
	}

	ret = cnxk_sa_index_init(portid, RTE_SECURITY_IPSEC_SA_DIR_INGRESS, MAX_SA_SIZE);
	if (ret) {
		printf("egress sa index init failed: err=%d, port=%d\n", ret, portid);
		return ret;
	}

	return 0;
}

static int
ut_setup(int argc, char **argv)
{
	uint32_t nb_lcores;
	uint32_t nb_mbufs;
	uint16_t nb_ports;
	uint16_t nb_rxd;
	uint16_t nb_txd;
	uint16_t portid;
	int ret;

	ret = rte_eal_init(argc, argv);
	if (ret < 0) {
		printf("Invalid EAL arguments\n");
		return -1;
	}
	argc -= ret;
	argv += ret;

	ret = parse_args(argc, argv);
	if (ret < 0)
		return ret;

	nb_ports = rte_eth_dev_count_avail();
	if (nb_ports < NB_ETHPORTS_USED || ethdev_port_mask == 0) {
		printf("At least %u port(s) used for test\n", NB_ETHPORTS_USED);
		return -1;
	}

	ret = init_sess_mempool();
	if (ret) {
		printf("Unable to initialize session mempool: ret = %d\n", ret);
		return -1;
	}

	nb_lcores = rte_lcore_count();

	nb_rxd = RTE_TEST_RX_DESC_DEFAULT;
	nb_txd = RTE_TEST_TX_DESC_DEFAULT;

	nb_mbufs = nb_bufs ? nb_bufs : RTE_MAX(nb_ports * (nb_rxd + nb_txd +
							   nb_lcores * MEMPOOL_CACHE_SIZE),
					       NB_MBUF);

	/* Setup all available ports */
	RTE_ETH_FOREACH_DEV(portid) {
		if ((ethdev_port_mask & RTE_BIT64(portid)) == 0)
			continue;

		if (testmode == POLL_IPSEC_INB_OUTB_PERF ||
		    testmode == POLL_IPSEC_INB_PERF ||
		    testmode == POLL_IPSEC_OUTB_PERF ||
		    testmode == EVENT_IPSEC_INB_PERF ||
		    testmode == EVENT_IPSEC_OUTB_PERF ||
		    testmode == EVENT_IPSEC_INB_OUTB_PERF)
			ret = port_init(portid, nb_mbufs, nb_lcores - 1, nb_lcores - 1,
					nb_rxd, nb_txd);
		else
			ret = port_init(portid, nb_mbufs, 1, 1, nb_rxd, nb_txd);
	}
	if (ret)
		return -1;

	if (testmode == EVENT_IPSEC_INB_LAOUTB_PERF)
		cryptodevs_init();

	if (event_en) {
		/* Setup event device */
		ret = ut_eventdev_setup();
		if (ret < 0) {
			printf("Failed to setup eventdev, err=%d\n", ret);
			return ret;
		}
	}

	init_lcore();

	RTE_ETH_FOREACH_DEV(portid) {
		if ((ethdev_port_mask & RTE_BIT64(portid)) == 0)
			continue;
		/* Enable PFC if requested */
		if (pfc) {
			struct rte_eth_pfc_queue_conf pfc_conf;
			struct rte_eth_fc_conf fc_conf;

			/* Disable flow control */
			memset(&fc_conf, 0, sizeof(fc_conf));
			fc_conf.mode = RTE_ETH_FC_NONE;
			ret = rte_eth_dev_flow_ctrl_set(portid, &fc_conf);
			if (ret) {
				printf("Failed to disable flow control on port=%u, ret=%d\n",
				       portid, ret);
				return ret;
			}

			/* Enable PFC */
			memset(&pfc_conf, 0, sizeof(pfc_conf));
			pfc_conf.mode = RTE_ETH_FC_FULL;
			pfc_conf.rx_pause.tx_qid = 0;
			pfc_conf.rx_pause.tc = (portid + 3) % 8;
			pfc_conf.tx_pause.rx_qid = 0;
			pfc_conf.tx_pause.tc = (portid + 3) % 8;
			ret = rte_eth_dev_priority_flow_ctrl_queue_configure(portid, &pfc_conf);
			if (ret) {
				printf("Failed to enable PFC %u on port=%u, ret=%d\n",
				       pfc_conf.rx_pause.tc, portid, ret);
				return ret;
			}

			printf("Enabled PFC class %u on port %d RX/TX\n", pfc_conf.rx_pause.tc,
			       portid);
		}

		/* Start device */
		ret = rte_eth_dev_start(portid);
		if (ret < 0) {
			printf("rte_eth_dev_start: err=%d, port=%d\n", ret, portid);
			return ret;
		}
		/* always enable promiscuous */
		ret = rte_eth_promiscuous_enable(portid);
		if (ret != 0) {
			printf("rte_eth_promiscuous_enable: err=%s, port=%d\n", rte_strerror(-ret),
			       portid);
			return ret;
		}
	}

	check_all_ports_link_status(ethdev_port_mask);
	return 0;
}

static void
ut_teardown(void)
{
	int ret, cdev_id;
	int portid;

	for (cdev_id = 0; cdev_id < rte_cryptodev_count(); cdev_id++) {
		rte_cryptodev_stop(cdev_id);
		rte_cryptodev_close(cdev_id);
	}

	RTE_ETH_FOREACH_DEV(portid) {
		if ((ethdev_port_mask & RTE_BIT64(portid)) == 0)
			continue;
		ret = rte_eth_dev_stop(portid);
		if (ret != 0)
			printf("rte_eth_dev_stop: err=%s, port=%u\n", rte_strerror(-ret), portid);
	}

	/* Event device cleanup */
	if (event_en)
		ut_eventdev_teardown();

	/* port tear down */
	RTE_ETH_FOREACH_DEV(portid) {
		if ((ethdev_port_mask & RTE_BIT64(portid)) == 0)
			continue;
		ret = rte_eth_dev_reset(portid);
		if (ret != 0)
			printf("rte_eth_dev_reset: err=%s, port=%u\n", rte_strerror(-ret), portid);

		cnxk_sa_index_fini(portid, RTE_SECURITY_IPSEC_SA_DIR_EGRESS);
		cnxk_sa_index_fini(portid, RTE_SECURITY_IPSEC_SA_DIR_INGRESS);
	}
}

static void
ipsec_inb_sa_init(struct rte_pmd_cnxk_ipsec_inb_sa *sa)
{
	size_t offset;

	memset(sa, 0, sizeof(struct rte_pmd_cnxk_ipsec_inb_sa));

	sa->w0.s.pkt_output = CPT_IE_OT_SA_PKT_OUTPUT_NO_FRAG;
	sa->w0.s.pkt_format = CPT_IE_OT_SA_PKT_FMT_META;
	sa->w0.s.pkind = CPT_IE_OT_CPT_PKIND;
	sa->w0.s.et_ovrwr = 1;
	sa->w2.s.l3hdr_on_err = 1;

	offset = offsetof(struct rte_pmd_cnxk_ipsec_inb_sa, ctx);
	sa->w0.s.hw_ctx_off = offset / 8;
	sa->w0.s.ctx_push_size = sa->w0.s.hw_ctx_off + 1;
	sa->w0.s.ctx_size = 2;
	sa->w0.s.ctx_hdr_size = 1;
	sa->w0.s.aop_valid = 1;
}

static void
create_default_ipsec_flow(uint16_t port_id)
{
	struct rte_flow_action action[2];
	struct rte_flow_item pattern[2];
	struct rte_flow_attr attr = {0};
	struct rte_flow_error err;
	struct rte_flow *flow;
	int ret;

	/* Add the default rte_flow to enable SECURITY for all ESP packets */

	pattern[0].type = RTE_FLOW_ITEM_TYPE_ESP;
	pattern[0].spec = NULL;
	pattern[0].mask = NULL;
	pattern[0].last = NULL;
	pattern[1].type = RTE_FLOW_ITEM_TYPE_END;

	action[0].type = RTE_FLOW_ACTION_TYPE_SECURITY;
	action[0].conf = NULL;
	action[1].type = RTE_FLOW_ACTION_TYPE_END;
	action[1].conf = NULL;

	attr.ingress = 1;

	ret = rte_flow_validate(port_id, &attr, pattern, action, &err);
	if (ret)
		return;

	flow = rte_flow_create(port_id, &attr, pattern, action, &err);
	if (flow == NULL)
		return;

	default_flow_no_msns[port_id] = flow;
	printf("Created default flow enabling SECURITY for all ESP traffic on port %d\n",
		port_id);
}

static void
destroy_default_ipsec_flow(uint16_t portid)
{
	struct rte_flow_error err;
	int ret;

	if (!default_flow_no_msns[portid])
		return;
	ret = rte_flow_destroy(portid, default_flow_no_msns[portid], &err);
	if (ret) {
		printf("\nDefault flow rule destroy failed\n");
		return;
	}
	default_flow_no_msns[portid] = NULL;
}

#define SA_COOKIE 0xAFAFAFAF
static void
pmd_cnxk_api_inb_session_fill(struct rte_pmd_cnxk_ipsec_inb_sa *sa)
{
	uint8_t *salt_key = sa->w8.s.salt;
	uint32_t *tmp_salt;
	uint64_t *tmp_key;
	int i;

	ipsec_inb_sa_init(sa);

	sa->w0.s.count_glb_octets = 1;
	sa->w0.s.count_glb_pkts = 1;
	sa->w2.s.dir = CPT_IE_SA_DIR_INBOUND;
	sa->w2.s.ipsec_protocol = CPT_IE_SA_PROTOCOL_ESP;
	sa->w2.s.ipsec_mode = CPT_IE_SA_MODE_TUNNEL;
	sa->w2.s.enc_type = CPT_IE_OT_SA_ENC_AES_GCM;
	sa->w2.s.auth_type = CPT_IE_OT_SA_AUTH_NULL;

	memcpy(salt_key, &sess_conf->ipsec_xform.salt, 4);
	tmp_salt = (uint32_t *)salt_key;
	*tmp_salt = rte_be_to_cpu_32(*tmp_salt);
	sa->w2.s.spi = 1;

	memcpy(sa->cipher_key, sess_conf->key.data, 16);
	tmp_key = (uint64_t *)sa->cipher_key;
	for (i = 0; i < (int)(CPT_CTX_MAX_CKEY_LEN / sizeof(uint64_t)); i++)
		tmp_key[i] = rte_be_to_cpu_64(tmp_key[i]);

	sa->w2.s.aes_key_len = CPT_IE_SA_AES_KEY_LEN_128;
	sa->w1.s.cookie = SA_COOKIE;
}

static int
pmd_cnxk_api_custom_inb_sa_verify(void)
{
	uint16_t lcore_id = rte_lcore_id();
	struct lcore_cfg *info = &lcore_cfg[lcore_id];
	unsigned int portid, nb_rx = 0, j;
	unsigned int nb_sent = 0, nb_tx;
	struct rte_mbuf *tx_pkts = NULL;
	struct rte_mbuf *pkt;
	struct rte_event ev;
	uint32_t *data;
	int rc;

	nb_tx = 1;
	portid = info->portid;
	rc = init_traffic(mbufpool[portid], &tx_pkts, &pkt_ipv4_gcm128_spi1_cipher);
	if (rc != 0)
		return -1;

	create_default_ipsec_flow(portid);
	/* Start event dev */
	ut_eventdev_start();

	nb_sent = rte_eth_tx_burst(portid, 0, &tx_pkts, nb_tx);
	if (nb_sent != nb_tx) {
		printf("\nFailed to tx %u pkts", nb_tx);
		rc = -1;
		goto exit;
	}

	printf("Sent %u pkts\n", nb_sent);
	rte_delay_ms(100);

	/* Retry few times before giving up */
	j = 0;
	while (j++ < 10) {
		/* Read packet from event queues */
		nb_rx = rte_event_dequeue_burst(info->eventdev_id, info->event_port_id,
						&ev, 1, 0);
		if (nb_rx == 0) {
			rte_pause();
			continue;
		}
		switch (ev.event_type) {
		case RTE_EVENT_TYPE_ETHDEV:
			break;
		default:
			printf("Invalid event type %u", ev.event_type);
			rc = -1;
			goto exit;
		}
		pkt = ev.mbuf;
		break;
	}

	printf("Recv %u pkts\n", nb_rx);
	/* Check for minimum number of Rx packets expected */
	if (nb_rx != nb_tx) {
		printf("\nReceived less Rx pkts(%u) pkts\n", nb_rx);
		rc = -1;
		goto exit;
	}
	/* Get meta buffer pointer from WQE, mbuf + 128 is the WQE pointer */
	data = (uint32_t *)(*(uint64_t *)RTE_PTR_ADD(pkt, 128 + 72));
	data += is_plat_cn20k ? 0 : 1;
	if (data[0] != SA_COOKIE) {
		printf("SA cookie is not matched in the meta packet\n");
		rte_hexdump(stdout, NULL, data, pkt->pkt_len);
		rc = -1;
	}
	rte_pktmbuf_free(pkt);
exit:
	destroy_default_ipsec_flow(portid);
	return rc;
}

#define NB_INST		65
#define CPT_RES_ALIGN	sizeof(union rte_pmd_cnxk_cpt_res_s)
static int
pmd_cnxk_api_inl_dev_inst_submit(void *cptr)
{
	struct ipsec_test_packet *pkt = &pkt_ipv4_gcm128_spi1_cipher;
	struct rte_pmd_cnxk_cpt_q_stats stats, prev_stats;
	union rte_pmd_cnxk_cpt_res_s res, *hw_res;
	union roc_ot_ipsec_inb_param1 param1;
	struct cpt_inst_s *inst_mem, *inst;
	void *data_ptrs[NB_INST];
	uint64_t timeout, pkts;
	void *qptr, *dptr;
	int rc = 0, i;

	const union rte_pmd_cnxk_cpt_res_s res_init = {
		.cn10k.compcode = CPT_COMP_NOT_DONE,
	};

	inst_mem = rte_malloc(NULL, NB_INST * sizeof(struct cpt_inst_s), 0);
	if (inst_mem == NULL) {
		printf("Could not allocate instruction memory\n");
		return -ENOMEM;
	}
	rte_pmd_cnxk_cpt_q_stats_get(0, RTE_PMD_CNXK_CPT_Q_STATS_INL_DEV, &prev_stats, 0);
	for (i = 0; i < NB_INST; i++) {
		inst = RTE_PTR_ADD(inst_mem, i * sizeof(struct cpt_inst_s));

		memset(inst, 0, sizeof(struct cpt_inst_s));
		data_ptrs[i] = rte_zmalloc(NULL, MAX_PKT_LEN + CPT_RES_ALIGN, 0);
		if (data_ptrs[i] == NULL) {
			printf("Could not allocate memory for dptr\n");
			rc = -ENOMEM;
			goto exit;
		}
		hw_res = RTE_PTR_ALIGN_CEIL(data_ptrs[i], CPT_RES_ALIGN);

		inst->w3.s.qord = 1;

		dptr = RTE_PTR_ADD(hw_res, sizeof(union rte_pmd_cnxk_cpt_res_s));
		memcpy(dptr, pkt->data, pkt->len);
		inst->dptr = (uint64_t)((uintptr_t)dptr + RTE_ETHER_HDR_LEN);

		inst->w7.s.egrp = is_plat_cn20k ? CPT_DFLT_ENG_GRP_SE : CPT_DFLT_ENG_GRP_SE_IE;
		inst->w7.s.ctx_val = 1;
		inst->w7.s.cptr = (uint64_t)(uintptr_t)cptr;

		inst->w4.s.opcode_major = CPT_IE_OT_MAJOR_OP_PROCESS_INBOUND_IPSEC | (1 << 6);
		param1.u16 = 0;

		/* Disable IP checksum verification by default */
		param1.s.ip_csum_disable = 1;

		/* Disable L4 checksum verification by default */
		param1.s.l4_csum_disable = 1;

		param1.s.esp_trailer_disable = 1;

		inst->w4.s.param1 = param1.u16;
		inst->w4.s.dlen = pkt->len - RTE_ETHER_HDR_LEN;

		inst->res_addr = (uint64_t)hw_res;
		__atomic_store_n(&hw_res->u64[0], res_init.u64[0], __ATOMIC_RELAXED);
	}

	timeout = rte_rdtsc() + rte_get_tsc_hz() * 60;

	qptr = rte_pmd_cnxk_inl_dev_qptr_get();
	if (rte_pmd_cnxk_inl_dev_submit(qptr, inst_mem, NB_INST) != NB_INST) {
		printf("Couldn't submit CPT instructions to inline device\n");
		rc = -1;
		goto exit;
	}
	do {
		hw_res = RTE_PTR_ALIGN_CEIL(data_ptrs[NB_INST - 1], CPT_RES_ALIGN);
		res.u64[0] = __atomic_load_n(&hw_res->u64[0], __ATOMIC_RELAXED);
	} while ((res.cn10k.compcode == CPT_COMP_NOT_DONE) && (rte_rdtsc() < timeout));

	if (res.cn10k.compcode != CPT_COMP_GOOD  && res.cn10k.compcode != CPT_COMP_WARN) {
		printf("res.compcode: %d\n", res.cn10k.compcode);
		rc = -1;
	} else {
		rte_pmd_cnxk_cpt_q_stats_get(0, RTE_PMD_CNXK_CPT_Q_STATS_INL_DEV, &stats, 0);
		pkts = stats.dec_pkts - prev_stats.dec_pkts;
		if (pkts != NB_INST) {
			printf("Inbound packet count: %u is not matched with queue counter: %lu\n",
			       NB_INST, pkts);
			rc = -1;
		}
	}
exit:
	i--;
	for (; i >= 0; i--)
		rte_free(data_ptrs[i]);
	rte_free(inst_mem);

	return rc;
}

#define CUSTOM_SA_SZ  512
static int
rte_pmd_cnxk_api_test(void)
{
	union rte_pmd_cnxk_ipsec_hw_sa *sa, sa_dptr;
	uint16_t lcore_id = rte_lcore_id();
	unsigned int portid;
	int rc = 0;

	portid = lcore_cfg[lcore_id].portid;
	sa = rte_pmd_cnxk_hw_session_base_get(portid, true);
	/* Get the SA for spi 1 */
	sa = RTE_PTR_ADD(sa, CUSTOM_SA_SZ);
	memset(sa, 0, CUSTOM_SA_SZ);

	pmd_cnxk_api_inb_session_fill(&sa_dptr.inb);

	/* Copy word0 from sa_dptr to populate ctx_push_sz ctx_size fields */
	memcpy(sa, &sa_dptr.inb, 8);
	sa_dptr.inb.w2.s.valid = 1;

	rc = rte_pmd_cnxk_hw_sa_write(portid, sa, &sa_dptr, CUSTOM_SA_SZ, true);
	if (rc) {
		printf("Couldn't create the SA\n");
		return rc;
	}
	/* Verify the inline device instruction submit API */
	rc = pmd_cnxk_api_inl_dev_inst_submit(sa);
	if (rc)
		goto exit;

	/* Verify the custom_inb_sa, driver wouldn't do the post processing
	 * of inline IPsec inbound packet.
	 */
	rc = pmd_cnxk_api_custom_inb_sa_verify();

exit:
	/* Destroy the SA */
	ipsec_inb_sa_init(&sa_dptr.inb);
	if (rte_pmd_cnxk_hw_sa_write(portid, sa, &sa_dptr, CUSTOM_SA_SZ, true))
		printf("Couldn't destroy the SA\n");

	return rc;
}

static int
ut_ipsec_encap_decap(struct test_ipsec_vector *vector, enum rte_security_ipsec_tunnel_type tun_type,
		     uint8_t alg)
{
	struct rte_security_session *out_ses = NULL, *in_ses = NULL;
	uint32_t in_sa_index = 0, out_sa_index = 0, spi = 0;
	struct rte_security_session_conf conf = {0};
	struct rte_security_ctx *sec_ctx = NULL;
	uint32_t index_count = 0, sa_index = 0;
	uint16_t lcore_id = rte_lcore_id();
	struct ipsec_session_data sa_data;
	unsigned int portid, nb_rx = 0, j;
	unsigned int nb_sent = 0, nb_tx;
	struct rte_mbuf *tx_pkts = NULL;
	struct rte_mbuf *rx_pkts = NULL;
	uint16_t sa_hi = 0, sa_lo = 0;
	uint64_t userdata;
	int ret = 0;

	nb_tx = 1;
	portid = lcore_cfg[lcore_id].portid;
	ret = init_traffic(mbufpool[portid], &tx_pkts, vector->frags);
	if (ret != 0) {
		ret = -1;
		goto out;
	}

	switch (alg) {
	case RTE_PMD_CNXK_SEC_ACTION_ALG0:
		/* Allocate 1 index and use it */
		index_count = 1;
		out_sa_index =
			cnxk_sa_index_alloc(portid, RTE_SECURITY_IPSEC_SA_DIR_EGRESS, index_count);
		in_sa_index =
			cnxk_sa_index_alloc(portid, RTE_SECURITY_IPSEC_SA_DIR_INGRESS, index_count);
		sa_index = in_sa_index;
		spi = (0x1 << 28 | in_sa_index);
		sa_hi = (spi >> 16) & 0xffff;
		sa_lo = 0x0;
		break;
	case RTE_PMD_CNXK_SEC_ACTION_ALG1:
		/* Allocate 2 index and use higher index */
		index_count = 2;
		out_sa_index =
			cnxk_sa_index_alloc(portid, RTE_SECURITY_IPSEC_SA_DIR_EGRESS, index_count);
		in_sa_index =
			cnxk_sa_index_alloc(portid, RTE_SECURITY_IPSEC_SA_DIR_INGRESS, index_count);
		sa_index = in_sa_index + 1;
		spi = (sa_index << 28) | 0x0000001;
		sa_hi = (spi >> 16) & 0xffff;
		sa_lo = 0x0001;
		break;
	case RTE_PMD_CNXK_SEC_ACTION_ALG2:
		/* Allocate 3 index and use higher index */
		index_count = 3;
		out_sa_index =
			cnxk_sa_index_alloc(portid, RTE_SECURITY_IPSEC_SA_DIR_EGRESS, index_count);
		in_sa_index =
			cnxk_sa_index_alloc(portid, RTE_SECURITY_IPSEC_SA_DIR_INGRESS, index_count);
		sa_index = in_sa_index + 2;
		spi = (sa_index << 25) | 0x00000001;
		sa_hi = (spi >> 16) & 0xffff;
		sa_lo = 0x0001;
		break;
	case RTE_PMD_CNXK_SEC_ACTION_ALG3:
		/* Allocate 3 index and use higher index */
		index_count = 3;
		out_sa_index =
			cnxk_sa_index_alloc(portid, RTE_SECURITY_IPSEC_SA_DIR_EGRESS, index_count);
		in_sa_index =
			cnxk_sa_index_alloc(portid, RTE_SECURITY_IPSEC_SA_DIR_INGRESS, index_count);
		sa_index = in_sa_index + 2;
		spi = (sa_index << 25) | 0x00000001;
		sa_hi = (spi >> 16) & 0xffff;
		sa_lo = 0x0001;
		break;
	case RTE_PMD_CNXK_SEC_ACTION_ALG4:
		/* Allocate 4 index and use higher index */
		index_count = 4;
		out_sa_index =
			cnxk_sa_index_alloc(portid, RTE_SECURITY_IPSEC_SA_DIR_EGRESS, index_count);
		in_sa_index =
			cnxk_sa_index_alloc(portid, RTE_SECURITY_IPSEC_SA_DIR_INGRESS, index_count);
		sa_index = in_sa_index + 3;
		spi = 0x100;
		sa_hi = 0;
		sa_lo = 0;
		break;
	default:
		ret = -1;
		goto out;
	}

	sec_ctx = (struct rte_security_ctx *)rte_eth_dev_get_sec_ctx(portid);

	memcpy(&sa_data, vector->sa_data, sizeof(sa_data));
	sa_data.ipsec_xform.spi = out_sa_index;
	/* Create Inline IPsec outbound session. */
	ret = create_inline_ipsec_session(&sa_data, portid, &out_ses,
					  RTE_SECURITY_IPSEC_SA_DIR_EGRESS, tun_type);
	if (ret)
		goto out;
	printf("Created Outbound session with sa_index = 0x%x\n", sa_data.ipsec_xform.spi);

	/* Update the real spi value */
	sa_data.ipsec_xform.spi = spi;
	sa_data.ipsec_xform.direction = RTE_SECURITY_IPSEC_SA_DIR_EGRESS;
	conf.action_type = RTE_SECURITY_ACTION_TYPE_INLINE_PROTOCOL;
	conf.protocol = RTE_SECURITY_PROTOCOL_IPSEC;
	memcpy(&conf.ipsec, &sa_data.ipsec_xform, sizeof(struct rte_security_ipsec_xform));
	conf.crypto_xform = &sa_data.xform.aead;
	ret = rte_security_session_update(sec_ctx, out_ses, &conf);
	if (ret) {
		printf("Security session update failed outbound\n");
		goto out;
	}
	printf("Updated Outbound session with SPI = 0x%x\n", sa_data.ipsec_xform.spi);

	rte_security_set_pkt_metadata(sec_ctx, out_ses, tx_pkts, NULL);
	tx_pkts->ol_flags |= RTE_MBUF_F_TX_SEC_OFFLOAD;
	tx_pkts->l2_len = RTE_ETHER_HDR_LEN;

	memcpy(&sa_data, vector->sa_data, sizeof(sa_data));
	sa_data.ipsec_xform.spi = sa_index;
	/* Create Inline IPsec inbound session. */
	ret = create_inline_ipsec_session(&sa_data, portid, &in_ses,
					  RTE_SECURITY_IPSEC_SA_DIR_INGRESS, tun_type);
	if (ret)
		goto out;
	printf("Created Inbound session with sa_index = 0x%x\n", sa_data.ipsec_xform.spi);

	sa_data.ipsec_xform.spi = spi;
	sa_data.ipsec_xform.direction = RTE_SECURITY_IPSEC_SA_DIR_INGRESS;
	conf.action_type = RTE_SECURITY_ACTION_TYPE_INLINE_PROTOCOL;
	conf.protocol = RTE_SECURITY_PROTOCOL_IPSEC;
	memcpy(&conf.ipsec, &sa_data.ipsec_xform, sizeof(struct rte_security_ipsec_xform));
	conf.crypto_xform = &sa_data.xform.aead;
	conf.userdata = (void *)(uint64_t)(alg);
	ret = rte_security_session_update(sec_ctx, in_ses, &conf);
	if (ret) {
		printf("Security session update failed inbound\n");
		goto out;
	}
	printf("Updated Inbound session with SPI = 0x%x\n", sa_data.ipsec_xform.spi);

	ret = create_default_flow(portid, alg, spi, sa_lo, sa_hi, sa_index);
	if (ret) {
		printf("Flow creation failed\n");
		goto out;
	}

	nb_sent = rte_eth_tx_burst(portid, 0, &tx_pkts, nb_tx);
	if (nb_sent != nb_tx) {
		ret = -1;
		printf("\nFailed to tx %u pkts", nb_tx);
		goto out;
	}

	printf("Sent %u pkts\n", nb_sent);
	rte_delay_ms(100);

	/* Retry few times before giving up */
	nb_rx = 0;
	j = 0;
	do {
		nb_rx += rte_eth_rx_burst(portid, 0, &rx_pkts, nb_tx - nb_rx);
		j++;
		if (nb_rx >= nb_tx)
			break;
		rte_delay_ms(100);
	} while (j < 10);

	printf("Recv %u pkts\n", nb_rx);
	/* Check for minimum number of Rx packets expected */
	if (nb_rx != nb_tx) {
		printf("\nReceived less Rx pkts(%u) pkts\n", nb_rx);
		ret = -1;
		goto out;
	}

	if (rx_pkts->ol_flags & RTE_MBUF_F_RX_SEC_OFFLOAD_FAILED ||
	    !(rx_pkts->ol_flags & RTE_MBUF_F_RX_SEC_OFFLOAD)) {
		printf("\nSecurity offload failed\n");
		ret = -1;
		goto out;
	}

	/* Check for userdata match */
	userdata = *rte_security_dynfield(rx_pkts);
	if (userdata != alg) {
		printf("\nDecrypted packet userdata mismatch %lx != %x\n",
		       userdata, alg);
		ret = -1;
		goto out;
	}

	if (vector->full_pkt->len != rx_pkts->pkt_len) {
		printf("\nDecrypted packet length mismatch\n");
		ret = -1;
		goto out;
	}
	ret = compare_pkt_data(rx_pkts, vector->full_pkt->data, vector->full_pkt->len);
out:
	destroy_default_flow(portid);

	cnxk_sa_index_free(portid, RTE_SECURITY_IPSEC_SA_DIR_EGRESS, out_sa_index, index_count);
	cnxk_sa_index_free(portid, RTE_SECURITY_IPSEC_SA_DIR_INGRESS, in_sa_index, index_count);

	/* Clear session data. */
	if (out_ses)
		rte_security_session_destroy(sec_ctx, out_ses);
	if (in_ses)
		rte_security_session_destroy(sec_ctx, in_ses);

	rte_pktmbuf_free(tx_pkts);
	rte_pktmbuf_free(rx_pkts);
	return ret;
}

static int
ut_ipsec_ipv4_burst_encap_decap(void)
{
	struct test_ipsec_vector ipv4_nofrag_case = {
		.sa_data = sess_conf,
		.full_pkt = &pkt_ipv4_plain,
		.frags = &pkt_ipv4_plain,
	};
	int rc;

	/* Start event dev */
	ut_eventdev_start();

	rc = ut_ipsec_encap_decap(&ipv4_nofrag_case, RTE_SECURITY_IPSEC_TUNNEL_IPV4,
				  RTE_PMD_CNXK_SEC_ACTION_ALG0);
	printf("Test RTE_PMD_CNXK_SEC_ACTION_ALG0: %s\n", rc ? "FAILED" : "PASS");
	if (rc)
		return rc;
	rc = ut_ipsec_encap_decap(&ipv4_nofrag_case, RTE_SECURITY_IPSEC_TUNNEL_IPV4,
				  RTE_PMD_CNXK_SEC_ACTION_ALG1);
	printf("Test RTE_PMD_CNXK_SEC_ACTION_ALG1: %s\n", rc ? "FAILED" : "PASS");
	if (rc)
		return rc;
	rc = ut_ipsec_encap_decap(&ipv4_nofrag_case, RTE_SECURITY_IPSEC_TUNNEL_IPV4,
				  RTE_PMD_CNXK_SEC_ACTION_ALG2);
	printf("Test RTE_PMD_CNXK_SEC_ACTION_ALG2: %s\n", rc ? "FAILED" : "PASS");
	if (rc)
		return rc;
	rc = ut_ipsec_encap_decap(&ipv4_nofrag_case, RTE_SECURITY_IPSEC_TUNNEL_IPV4,
				  RTE_PMD_CNXK_SEC_ACTION_ALG3);
	printf("Test RTE_PMD_CNXK_SEC_ACTION_ALG3: %s\n", rc ? "FAILED" : "PASS");
	if (rc)
		return rc;
	rc = ut_ipsec_encap_decap(&ipv4_nofrag_case, RTE_SECURITY_IPSEC_TUNNEL_IPV4,
				  RTE_PMD_CNXK_SEC_ACTION_ALG4);
	printf("Test RTE_PMD_CNXK_SEC_ACTION_ALG4: %s\n", rc ? "FAILED" : "PASS");
	if (rc)
		return rc;
	return 0;
}

static void
destroy_outb_exp_sa(struct outb_sa_exp_info *outb_exp_sa)
{
	struct ipsec_session_data *sa_data = outb_exp_sa->sa_data;
	struct lcore_cfg *info = &lcore_cfg[rte_lcore_id()];
	uint32_t port_id = outb_exp_sa->port_id;
	struct rte_security_session *outb_ses;
	struct rte_security_ctx *sec_ctx;
	int spi, ret;

	sec_ctx = rte_eth_dev_get_sec_ctx(port_id);
	spi = sa_data->ipsec_xform.spi;

	outb_ses = outb_sas[spi].sa;
	if (outb_ses == NULL) {
		printf("Invalid OUTB SA reported\n");
		return;
	}
	rte_spinlock_lock(&exp_ses_dest_lock);
	if (rte_security_session_destroy(sec_ctx, outb_ses)) {
		printf("Session Destroy failed for SPI: %d\n", spi);
		return;
	}

	ret = create_ipsec_perf_session(sa_data, port_id, &outb_sas[spi].sa);

	if (!ret)
		info->num_outb_sas += 1;
	rte_spinlock_unlock(&exp_ses_dest_lock);
}

static void
print_inb_outb_stats(void)
{
	struct outb_sa_exp_info *sa_exp, *sa_exp_next;
	uint64_t last_rx = 0, last_tx = 0;
	uint64_t curr_rx = 0, curr_tx = 0;
	struct rte_security_ctx *sec_ctx;
	struct rte_security_stats stats;
	uint64_t curr_ipsec_failed = 0;
	uint64_t curr_rx_ipsec = 0;
	uint64_t curr_inb_sas = 0;
	uint64_t last_inb_sas = 0;
	uint64_t curr_outb_sas = 0;
	uint64_t last_outb_sas = 0;
	uint32_t portid = 0;
	uint16_t lcore_id;
	struct timespec tv;
	struct timeval now;
	int i;

	while (!force_quit) {
		curr_rx = 0;
		curr_tx = 0;
		curr_rx_ipsec = 0;
		curr_ipsec_failed = 0;
		curr_inb_sas = 0;
		curr_outb_sas = 0;
		RTE_LCORE_FOREACH(lcore_id) {
			curr_rx += lcore_cfg[lcore_id].rx_pkts;
			curr_tx += lcore_cfg[lcore_id].tx_pkts;
			curr_rx_ipsec += lcore_cfg[lcore_id].rx_ipsec_pkts;
			curr_ipsec_failed += lcore_cfg[lcore_id].ipsec_failed;
			curr_inb_sas += lcore_cfg[lcore_id].num_inb_sas;
			curr_outb_sas += lcore_cfg[lcore_id].num_outb_sas;
		}

		printf("%" PRIu64 " Rx pps(%" PRIu64 " ipsec pkts), %" PRIu64 " Tx pps,\n"
		       "%" PRIu64 " drops, %" PRIu64 " ipsec_failed, " "%" PRIu64 " Inb SAs ps, "
		       "%" PRIu64 " Outb SAs ps\n", (curr_rx - last_rx) / stats_tmo,
		       curr_rx_ipsec, (curr_tx - last_tx) / stats_tmo,
		       curr_rx - curr_tx, curr_ipsec_failed,
		       (curr_inb_sas - last_inb_sas) / stats_tmo,
		       (curr_outb_sas - last_outb_sas) / stats_tmo);

		if (ipsec_stats) {
			sec_ctx = rte_eth_dev_get_sec_ctx(portid);
			for (i = 0; i <= (int)num_sas; i++) {
				if (inb_sas[i].sa) {
					rte_security_session_stats_get(sec_ctx, inb_sas[i].sa,
								       &stats);
					printf("[SPI 0x%x] %" PRIu64 " inb_pkts, ",
					       inb_sas[i].sa_data->spi, stats.ipsec.ipackets);
				}
				if (outb_sas[i].sa) {
					rte_security_session_stats_get(sec_ctx, outb_sas[i].sa,
								       &stats);
					printf("[SPI 0x%x] %" PRIu64 " outb_pkts",
					       outb_sas[i].sa_data->spi, stats.ipsec.opackets);
				}

				if (inb_sas[i].sa || outb_sas[i].sa)
					printf("\n");
			}
		}
		printf("\n");

		gettimeofday(&now, NULL);
		tv.tv_sec = now.tv_sec + stats_tmo; /* Wait for 5 seconds */
		tv.tv_nsec = now.tv_usec * 1000;

wait_timeout:
		pthread_mutex_lock(&mutex);
		int result = pthread_cond_timedwait(&cond, &mutex, &tv);

		if (result == 0) {
			for (sa_exp = TAILQ_FIRST(&sa_exp_q); sa_exp; ) {
				destroy_outb_exp_sa(sa_exp);
				sa_exp_next = TAILQ_NEXT(sa_exp, next);
				TAILQ_REMOVE(&sa_exp_q, sa_exp, next);
				free(sa_exp);
				sa_exp = sa_exp_next;
			}
		}
		pthread_mutex_unlock(&mutex);
		if (result == 0)
			goto wait_timeout;

		last_rx = curr_rx;
		last_tx = curr_tx;
		last_inb_sas = curr_inb_sas;
		last_outb_sas = curr_outb_sas;
	}
}


static void
print_stats(void)
{
	uint64_t last_rx = 0, last_tx = 0;
	uint64_t curr_rx = 0, curr_tx = 0;
	uint64_t curr_ipsec_failed = 0;
	uint64_t curr_rx_ipsec = 0;
	uint64_t curr_inb_sas = 0;
	uint64_t last_inb_sas = 0;
	uint16_t lcore_id;

	while (!force_quit) {
		curr_rx = 0;
		curr_tx = 0;
		curr_rx_ipsec = 0;
		curr_ipsec_failed = 0;
		curr_inb_sas = 0;
		RTE_LCORE_FOREACH(lcore_id) {
			curr_rx += lcore_cfg[lcore_id].rx_pkts;
			curr_tx += lcore_cfg[lcore_id].tx_pkts;
			curr_rx_ipsec += lcore_cfg[lcore_id].rx_ipsec_pkts;
			curr_ipsec_failed += lcore_cfg[lcore_id].ipsec_failed;
			curr_inb_sas += lcore_cfg[lcore_id].num_inb_sas;
		}

		printf("%" PRIu64 " Rx pps(%" PRIu64 " ipsec pkts), %" PRIu64 " Tx pps,\n"
		       "%" PRIu64 " drops, %" PRIu64 " ipsec_failed, " "%" PRIu64
		       " Inb SAs ps,\n\n", (curr_rx - last_rx) / stats_tmo,
		       curr_rx_ipsec, (curr_tx - last_tx) / stats_tmo,
		       curr_rx - curr_tx, curr_ipsec_failed,
		       (curr_inb_sas - last_inb_sas) / stats_tmo);

		sleep(stats_tmo);

		last_rx = curr_rx;
		last_tx = curr_tx;
		last_inb_sas = curr_inb_sas;
	}
}

/*
 * Event mode exposes various operating modes depending on the
 * capabilities of the event device and the operating mode
 * selected.
 */

static void
ipsec_event_port_flush(uint8_t eventdev_id __rte_unused, struct rte_event ev,
		       void *args __rte_unused)
{
	rte_pktmbuf_free(ev.mbuf);
}

static __rte_always_inline bool
pkt_type_valid(struct rte_mbuf *pkt)
{
	enum pkt_type type;
	uint8_t *nlp;

	/* Check the packet type */
	type = process_ipsec_get_pkt_type(pkt, &nlp);

	switch (type) {
	case PKT_TYPE_PLAIN_IPV4:
		return true;
	default:
		/*
		 * Only plain IPv4 packets are allowed
		 * drop the rest.
		 */
		rte_pktmbuf_free(pkt);
	}
	return false;
}

static int
poll_mode_inb_outb_worker(void *args)
{
	struct rte_mbuf *pkts[MAX_PKT_BURST], *pkt;
	struct rte_mbuf *tx_pkts[MAX_PKT_BURST];
	struct rte_security_ctx *sec_ctx;
	struct rte_security_session *sa;
	uint32_t nb_rx, nb_tx, j, k;
	struct lcore_cfg *lconf;
	uint16_t sa_index = 0;
	uint32_t lcore_id;
	uint16_t portid;
	uint16_t queueid;
	uint64_t ol_flags;

	(void)args;
	lcore_id = rte_lcore_id();
	lconf = &lcore_cfg[lcore_id];
	queueid = lconf->queueid;

	printf("IPSEC: entering main loop on lcore %u\n", lcore_id);

	portid = lconf->portid;

	while (!force_quit) {

		/* Read packets from RX queues */
		nb_rx = rte_eth_rx_burst(portid, queueid,
					 pkts, MAX_PKT_BURST);

		if (nb_rx <= 0)
			continue;

		lconf->rx_pkts += nb_rx;

		sec_ctx = rte_eth_dev_get_sec_ctx(portid);
		/* Send pkts out */
		for (j = 0, k = 0; j < nb_rx; j++) {
			pkt = pkts[j];
			ol_flags = pkt->ol_flags;
			/* Drop packets received with offload failure */
			if (unlikely(ol_flags & RTE_MBUF_F_RX_SEC_OFFLOAD_FAILED)) {
				lconf->ipsec_failed += 1;
				rte_pktmbuf_free(pkt);
				continue;
			}

			if (likely(ol_flags & RTE_MBUF_F_RX_SEC_OFFLOAD)) {
				struct ipsec_session_data *sa_data;

#if !defined(MSNS_CN9K)
				if (unlikely(softexp))
					handle_inb_soft_exp(portid, pkt, lcore_id);
#endif
				lconf->rx_ipsec_pkts += 1;
				sa_data = (struct ipsec_session_data *) *rte_security_dynfield(pkt);
				sa_index = sa_data->spi;
			} else {
				sa_index = rte_rand_max(num_sas - 1) + 1;
			}
			sa = outb_sas[sa_index].sa;
			rte_security_set_pkt_metadata(sec_ctx, sa, pkt, NULL);
			pkt->ol_flags = RTE_MBUF_F_TX_SEC_OFFLOAD;
			pkt->l2_len = RTE_ETHER_HDR_LEN;

			tx_pkts[k++] = pkt;
		}
		nb_tx = rte_eth_tx_burst(portid, queueid, tx_pkts, k);

		lconf->tx_pkts += nb_tx;

		if (unlikely(nb_tx < k)) {
			do {
				rte_pktmbuf_free(tx_pkts[nb_tx]);
			} while (++nb_tx < k);
		}
	}

	return 0;
}

static void
free_event(struct rte_event *ev)
{
	struct rte_event_vector *vec;
	int i;

	if (ev->event_type == RTE_EVENT_TYPE_ETHDEV) {
		if (ev->mbuf)
			rte_pktmbuf_free(ev->mbuf);
	} else if (ev->event_type == RTE_EVENT_TYPE_VECTOR) {
		vec = ev->vec;
		for (i = 0; i < vec->nb_elem; i++)
			rte_pktmbuf_free(vec->mbufs[i]);
		rte_mempool_put(rte_mempool_from_obj(vec), vec);
	}
}

static int
event_inb_laoutb_worker(void *args)
{
	uint32_t lcore_id = rte_lcore_id();
	struct lcore_cfg *info = &lcore_cfg[lcore_id];
	unsigned int nb_rx = 0, nb_tx;
	struct rte_mbuf *pkt;
	struct rte_event ev;
	uint16_t sa_index = 0;
	int ret;

	(void)args;

	printf("Launching event mode worker on lcore=%u, event_port_id=%u\n", lcore_id,
	       info->event_port_id);

	while (!force_quit) {
		/* Read packet from event queues */
		nb_rx = rte_event_dequeue_burst(info->eventdev_id, info->event_port_id,
						&ev, 1, 0);
		if (nb_rx == 0)
			continue;

		switch (ev.event_type) {
		case RTE_EVENT_TYPE_ETHDEV:
			break;
		case RTE_EVENT_TYPE_CRYPTODEV:
			ret = ipsec_ev_cryptodev_process(&ev);
			if (unlikely(ret != 1))
				continue;
			nb_tx = rte_event_eth_tx_adapter_enqueue(info->eventdev_id,
							 info->event_port_id,
							 &ev, /* events */
							 1,   /* nb_events */
							 0 /* flags */);
			if (!nb_tx)
				rte_pktmbuf_free(ev.mbuf);
			info->tx_pkts += nb_tx;
			continue;
		default:
			printf("Invalid event type %u", ev.event_type);
			continue;
		}

		pkt = ev.mbuf;

		if (unlikely(!pkt_type_valid(pkt)))
			continue;

		info->rx_pkts += nb_rx;
		info->rx_ipsec_pkts += !!(pkt->ol_flags & RTE_MBUF_F_RX_SEC_OFFLOAD);
#if !defined(MSNS_CN9K)
		if (unlikely(pkt->ol_flags & RTE_MBUF_F_RX_SEC_OFFLOAD && softexp))
			handle_inb_soft_exp(0, ev.mbuf, lcore_id);
#endif

		if (unlikely(pkt->ol_flags & RTE_MBUF_F_RX_SEC_OFFLOAD && inl_inb_oop))
			handle_inb_oop(ev.mbuf);

		rte_prefetch0(rte_pktmbuf_mtod(pkt, void *));
		/* Drop packets received with offload failure */
		if (unlikely(pkt->ol_flags & RTE_MBUF_F_RX_SEC_OFFLOAD_FAILED)) {
			info->ipsec_failed += 1;
#if !defined(MSNS_CN9K)
			union rte_pmd_cnxk_cpt_res_s *res;

			res = rte_pmd_cnxk_inl_ipsec_res(pkt);
			if (res && verbose)
				printf("compcode = %x\n", res->cn10k.uc_compcode);
#endif
			rte_pktmbuf_free(ev.mbuf);
			continue;
		}
		if (likely(pkt->ol_flags & RTE_MBUF_F_RX_SEC_OFFLOAD)) {
			struct ipsec_session_data *sa_data;

			sa_data = (struct ipsec_session_data *) *rte_security_dynfield(pkt);
			sa_index = sa_data->spi;
		} else {
			sa_index = rte_rand_max(num_sas - 1) + 1;
		}
		/* prepare pkt - advance start to L3 */
		rte_pktmbuf_adj(pkt, RTE_ETHER_HDR_LEN);

		event_crypto_enqueue(pkt, info, sa_index);
	}

	if (ev.u64) {
		ev.op = RTE_EVENT_OP_RELEASE;
		rte_event_enqueue_burst(info->eventdev_id,
					info->event_port_id, &ev, 1);
	}

	rte_event_port_quiesce(info->eventdev_id, info->event_port_id,
			       ipsec_event_port_flush, NULL);
	return 0;
}

static __rte_always_inline int
handle_inb_outb_event(uint32_t lcore_id, struct rte_security_ctx *sec_ctx, struct rte_mbuf *pkt)
{
	struct lcore_cfg *info = &lcore_cfg[lcore_id];
	uint64_t ol_flags = pkt->ol_flags;
	struct rte_security_session *sa;
	uint16_t sa_index = 0;

	if (unlikely(!pkt_type_valid(pkt)))
		return -1;

	info->rx_ipsec_pkts += !!(ol_flags & RTE_MBUF_F_RX_SEC_OFFLOAD);
#if !defined(MSNS_CN9K)
	if (unlikely(ol_flags & RTE_MBUF_F_RX_SEC_OFFLOAD && softexp))
		handle_inb_soft_exp(0, pkt, lcore_id);
#endif

	if (unlikely(ol_flags & RTE_MBUF_F_RX_SEC_OFFLOAD && inl_inb_oop))
		handle_inb_oop(pkt);

	rte_prefetch0(rte_pktmbuf_mtod(pkt, void *));
	/* Drop packets received with offload failure */
	if (unlikely(ol_flags & RTE_MBUF_F_RX_SEC_OFFLOAD_FAILED)) {
		info->ipsec_failed += 1;

#if !defined(MSNS_CN9K)
		union rte_pmd_cnxk_cpt_res_s *res;

		res = rte_pmd_cnxk_inl_ipsec_res(pkt);
		if (res && verbose)
			printf("compcode = %x\n", res->cn10k.uc_compcode);
#endif
		rte_pktmbuf_free(pkt);
		return -1;
	}

	if (likely(ol_flags & RTE_MBUF_F_RX_SEC_OFFLOAD)) {
		struct ipsec_session_data *sa_data;

		sa_data = (struct ipsec_session_data *) *rte_security_dynfield(pkt);
		sa_index = sa_data->spi;
	} else {
		sa_index = rte_rand_max(num_sas - 1) + 1;
	}
	sa = outb_sas[sa_index].sa;
	rte_security_set_pkt_metadata(sec_ctx, sa, pkt, NULL);

	/* Provide L2 len for Outbound processing */
	pkt->l2_len = RTE_ETHER_HDR_LEN;
	pkt->ol_flags = RTE_MBUF_F_TX_SEC_OFFLOAD;
	return 0;
}

static int
event_inb_outb_worker(void *args)
{
	uint32_t lcore_id = rte_lcore_id();
	struct lcore_cfg *info = &lcore_cfg[lcore_id];
	struct rte_security_ctx *sec_ctx = NULL;
	struct rte_event_vector *vec;
	unsigned int nb_rx = 0, nb_tx;
	struct rte_mbuf *pkt;
	struct rte_event ev;
	uint16_t i, j;

	(void)args;

	printf("Launching event mode worker on lcore=%u, event_port_id=%u\n", lcore_id,
	       info->event_port_id);

	while (!force_quit) {
		/* Read packet from event queues */
		nb_rx = rte_event_dequeue_burst(info->eventdev_id, info->event_port_id,
						&ev, 1, 0);
		if (nb_rx == 0)
			continue;

		switch (ev.event_type) {
		case RTE_EVENT_TYPE_ETHDEV:
		case RTE_EVENT_TYPE_VECTOR:
			break;
		default:
			printf("Invalid event type %u", ev.event_type);
			continue;
		}

		if (ev.event_type == RTE_EVENT_TYPE_VECTOR) {
			vec = ev.vec;
			nb_rx = vec->nb_elem;
			info->rx_pkts += nb_rx;
			pkt = vec->mbufs[0];
			sec_ctx = rte_eth_dev_get_sec_ctx(pkt->port);
			vec->attr_valid = 1;
			vec->port = pkt->port;

			/* Process vector events */
			j = 0;
			for (i = 0; i < nb_rx; i++) {
				pkt = vec->mbufs[i];
				if (unlikely(handle_inb_outb_event(lcore_id, sec_ctx, pkt)))
					continue;
				vec->mbufs[j++] = pkt;
			}
			if (unlikely(!j)) {
				/* All packets were dropped */
				rte_mempool_put(rte_mempool_from_obj(vec), vec);
				continue;
			}
			vec->nb_elem = j;
			nb_tx = j;
		} else {
			/* Process single event */
			info->rx_pkts += nb_rx;
			pkt = ev.mbuf;
			sec_ctx = rte_eth_dev_get_sec_ctx(pkt->port);
			if (unlikely(handle_inb_outb_event(lcore_id, sec_ctx, pkt)))
				continue;

			/* Save eth queue for Tx */
			rte_event_eth_tx_adapter_txq_set(pkt, 0);
			nb_tx = 1;
		}

		/*
		 * Since tx internal port is available, events can be
		 * directly enqueued to the adapter and it would be
		 * internally submitted to the eth device.
		 */
		if (!rte_event_eth_tx_adapter_enqueue(info->eventdev_id,
						      info->event_port_id,
						      &ev, /* events */
						      1,   /* nb_events */
						      0 /* flags */)) {
			free_event(&ev);
			continue;
		}

		info->tx_pkts += nb_tx;
	}

	if (ev.u64) {
		ev.op = RTE_EVENT_OP_RELEASE;
		rte_event_enqueue_burst(info->eventdev_id,
					info->event_port_id, &ev, 1);
	}

	rte_event_port_quiesce(info->eventdev_id, info->event_port_id,
			       ipsec_event_port_flush, NULL);
	return 0;
}

static __rte_always_inline int
handle_inb_event(uint32_t lcore_id, struct rte_mbuf *pkt)
{
	struct lcore_cfg *info = &lcore_cfg[lcore_id];
	uint64_t ol_flags = pkt->ol_flags;

	info->rx_ipsec_pkts += !!(ol_flags & RTE_MBUF_F_RX_SEC_OFFLOAD);
#if !defined(MSNS_CN9K)
	if (ol_flags & RTE_MBUF_F_RX_SEC_OFFLOAD && softexp)
		handle_inb_soft_exp(0, pkt, lcore_id);
#endif

	/* Drop packets received with offload failure */
	if (unlikely(ol_flags & RTE_MBUF_F_RX_SEC_OFFLOAD_FAILED)) {
		info->ipsec_failed += 1;
#if !defined(MSNS_CN9K)
			union rte_pmd_cnxk_cpt_res_s *res;

			res = rte_pmd_cnxk_inl_ipsec_res(pkt);
			if (res && verbose)
				printf("compcode = %x\n", res->cn10k.uc_compcode);
#endif
		rte_pktmbuf_free(pkt);
		return -1;
	}
	return 0;
}

static int
event_inb_worker(void *args)
{
	uint32_t lcore_id = rte_lcore_id();
	struct lcore_cfg *info = &lcore_cfg[lcore_id];
	unsigned int nb_rx = 0, nb_tx;
	struct rte_event_vector *vec;
	struct rte_mbuf *pkt;
	struct rte_event ev;
	uint16_t i, j;

	(void)args;

	printf("Launching event mode worker on lcore=%u, event_port_id=%u\n", lcore_id,
	       info->event_port_id);

	while (!force_quit) {
		/* Read packet from event queues */
		nb_rx = rte_event_dequeue_burst(info->eventdev_id, info->event_port_id,
						&ev, 1, 0);
		if (nb_rx == 0)
			continue;

		switch (ev.event_type) {
		case RTE_EVENT_TYPE_ETHDEV:
		case RTE_EVENT_TYPE_VECTOR:
			break;
		default:
			printf("Invalid event type %u", ev.event_type);
			continue;
		}

		if (ev.event_type == RTE_EVENT_TYPE_VECTOR) {
			vec = ev.vec;
			nb_rx = vec->nb_elem;
			info->rx_pkts += nb_rx;
			pkt = vec->mbufs[0];
			vec->attr_valid = 1;
			vec->port = pkt->port;

			/* Process vector events */
			j = 0;
			for (i = 0; i < nb_rx; i++) {
				pkt = vec->mbufs[i];
				if (unlikely(handle_inb_event(lcore_id, pkt)))
					continue;
				vec->mbufs[j++] = pkt;
			}
			if (unlikely(!j)) {
				/* All packets were dropped */
				rte_mempool_put(rte_mempool_from_obj(vec), vec);
				continue;
			}
			vec->nb_elem = j;
			nb_tx = j;
		} else {
			/* Process single event */
			info->rx_pkts += nb_rx;
			pkt = ev.mbuf;
			rte_prefetch0(rte_pktmbuf_mtod(pkt, void *));

			if (unlikely(handle_inb_event(lcore_id, pkt)))
				continue;

			/* Save eth queue for Tx */
			rte_event_eth_tx_adapter_txq_set(pkt, 0);
			nb_tx = 1;
		}

		/*
		 * Since tx internal port is available, events can be
		 * directly enqueued to the adapter and it would be
		 * internally submitted to the eth device.
		 */
		if (!rte_event_eth_tx_adapter_enqueue(info->eventdev_id,
						      info->event_port_id,
						      &ev, /* events */
						      1,   /* nb_events */
						      0 /* flags */)) {
			free_event(&ev);
			continue;
		}
		info->tx_pkts += nb_tx;
	}

	if (ev.u64) {
		ev.op = RTE_EVENT_OP_RELEASE;
		rte_event_enqueue_burst(info->eventdev_id,
					info->event_port_id, &ev, 1);
	}

	rte_event_port_quiesce(info->eventdev_id, info->event_port_id,
			       ipsec_event_port_flush, NULL);
	return 0;
}

static __rte_always_inline int
handle_outb_event(uint32_t lcore_id, struct rte_security_ctx *sec_ctx, struct rte_mbuf *pkt)
{
	struct rte_security_session *sa;
	uint16_t sa_index = 0;

	RTE_SET_USED(lcore_id);
	if (unlikely(!pkt_type_valid(pkt)))
		return -1;

	sa_index = rte_rand_max(num_sas - 1) + 1;
	sa = outb_sas[sa_index].sa;
	rte_security_set_pkt_metadata(sec_ctx, sa, pkt, NULL);

	/* Provide L2 len for Outbound processing */
	pkt->l2_len = RTE_ETHER_HDR_LEN;
	pkt->ol_flags = RTE_MBUF_F_TX_SEC_OFFLOAD;
	return 0;
}

static int
event_outb_worker(void *args)
{
	uint32_t lcore_id = rte_lcore_id();
	struct lcore_cfg *info = &lcore_cfg[lcore_id];
	struct rte_security_ctx *sec_ctx = NULL;
	unsigned int nb_rx = 0, nb_tx;
	struct rte_event_vector *vec;
	struct rte_mbuf *pkt;
	struct rte_event ev;
	uint16_t i, j;

	(void)args;

	printf("Launching event mode worker on lcore=%u, event_port_id=%u\n", lcore_id,
	       info->event_port_id);

	while (!force_quit) {
		/* Read packet from event queues */
		nb_rx = rte_event_dequeue_burst(info->eventdev_id, info->event_port_id,
						&ev, 1, 0);
		if (nb_rx == 0)
			continue;

		switch (ev.event_type) {
		case RTE_EVENT_TYPE_ETHDEV:
		case RTE_EVENT_TYPE_VECTOR:
			break;
		default:
			printf("Invalid event type %u", ev.event_type);
			continue;
		}

		if (ev.event_type == RTE_EVENT_TYPE_VECTOR) {
			vec = ev.vec;
			nb_rx = vec->nb_elem;
			info->rx_pkts += nb_rx;
			pkt = vec->mbufs[0];
			sec_ctx = rte_eth_dev_get_sec_ctx(pkt->port);
			vec->attr_valid = 1;
			vec->port = pkt->port;

			/* Process vector events */
			j = 0;
			for (i = 0; i < nb_rx; i++) {
				pkt = vec->mbufs[i];
				if (unlikely(handle_outb_event(lcore_id, sec_ctx, pkt)))
					continue;
				vec->mbufs[j++] = pkt;
			}
			if (unlikely(!j)) {
				/* All packets were dropped */
				rte_mempool_put(rte_mempool_from_obj(vec), vec);
				continue;
			}
			vec->nb_elem = j;
			nb_tx = j;
		} else {
			/* Process single event */
			info->rx_pkts += nb_rx;
			pkt = ev.mbuf;
			sec_ctx = rte_eth_dev_get_sec_ctx(pkt->port);
			rte_prefetch0(rte_pktmbuf_mtod(pkt, void *));

			if (unlikely(handle_outb_event(lcore_id, sec_ctx, pkt)))
				continue;

			/* Save eth queue for Tx */
			rte_event_eth_tx_adapter_txq_set(pkt, 0);
			nb_tx = 1;
		}

		/*
		 * Since tx internal port is available, events can be
		 * directly enqueued to the adapter and it would be
		 * internally submitted to the eth device.
		 */
		if (!rte_event_eth_tx_adapter_enqueue(info->eventdev_id,
						      info->event_port_id,
						      &ev, /* events */
						      1,   /* nb_events */
						      0 /* flags */)) {
			free_event(&ev);
			continue;
		}
		info->tx_pkts += nb_tx;
	}

	if (ev.u64) {
		ev.op = RTE_EVENT_OP_RELEASE;
		rte_event_enqueue_burst(info->eventdev_id,
					info->event_port_id, &ev, 1);
	}

	rte_event_port_quiesce(info->eventdev_id, info->event_port_id,
			       ipsec_event_port_flush, NULL);
	return 0;
}


static int
poll_mode_inb_worker(void *args)
{
	struct rte_mbuf *pkts[MAX_PKT_BURST], *pkt;
	struct rte_mbuf *tx_pkts[MAX_PKT_BURST];
	uint32_t nb_rx, nb_tx, j, k;
	struct lcore_cfg *lconf;
	uint64_t ol_flags;
	uint32_t lcore_id;
	uint16_t portid;
	uint16_t queueid;

	(void)args;
	lcore_id = rte_lcore_id();
	lconf = &lcore_cfg[lcore_id];
	queueid = lconf->queueid;

	printf("IPSEC: entering main loop on lcore %u\n", lcore_id);

	portid = lconf->portid;

	while (!force_quit) {

		/* Read packets from RX queues */
		nb_rx = rte_eth_rx_burst(portid, queueid,
					 pkts, MAX_PKT_BURST);

		if (nb_rx <= 0)
			continue;

		lconf->rx_pkts += nb_rx;

		/* Send pkts out */
		for (j = 0, k = 0; j < nb_rx; j++) {
			pkt = pkts[j];
			ol_flags = pkt->ol_flags;
			lconf->rx_ipsec_pkts += !!(ol_flags & RTE_MBUF_F_RX_SEC_OFFLOAD);
			/* Drop packets received with offload failure */
			if (unlikely(ol_flags & RTE_MBUF_F_RX_SEC_OFFLOAD_FAILED)) {
				lconf->ipsec_failed += 1;
#if !defined(MSNS_CN9K)
				union rte_pmd_cnxk_cpt_res_s *res;

				res = rte_pmd_cnxk_inl_ipsec_res(pkt);
				if (res && verbose)
					printf("uc_compcode = %x compcode = %x\n",
					       res->cn10k.uc_compcode, res->cn10k.compcode);
#endif
				rte_pktmbuf_free(pkt);
				continue;
			}

			tx_pkts[k++] = pkt;
		}
		nb_tx = rte_eth_tx_burst(portid, queueid, tx_pkts, k);

		lconf->tx_pkts += nb_tx;

		if (unlikely(nb_tx < k)) {
			do {
				rte_pktmbuf_free(tx_pkts[nb_tx]);
			} while (++nb_tx < k);
		}
	}

	return 0;
}


static int
poll_mode_outb_worker(void *args)
{
	struct rte_mbuf *pkts[MAX_PKT_BURST], *pkt;
	struct rte_mbuf *tx_pkts[MAX_PKT_BURST];
	struct rte_security_ctx *sec_ctx;
	struct rte_security_session *sa;
	uint32_t nb_rx, nb_tx, j, k;
	struct lcore_cfg *lconf;
	uint16_t sa_index = 0;
	uint32_t lcore_id;
	uint16_t portid;
	uint16_t queueid;

	(void)args;
	lcore_id = rte_lcore_id();
	lconf = &lcore_cfg[lcore_id];
	queueid = lconf->queueid;

	printf("IPSEC: entering main loop on lcore %u\n", lcore_id);

	portid = lconf->portid;

	while (!force_quit) {

		/* Read packets from RX queues */
		nb_rx = rte_eth_rx_burst(portid, queueid,
					 pkts, MAX_PKT_BURST);

		if (nb_rx <= 0)
			continue;

		lconf->rx_pkts += nb_rx;

		sec_ctx = rte_eth_dev_get_sec_ctx(portid);
		/* Send pkts out */
		for (j = 0, k = 0; j < nb_rx; j++) {
			pkt = pkts[j];
			sa_index = rte_rand_max(num_sas - 1) + 1;

			sa = outb_sas[sa_index].sa;
			rte_security_set_pkt_metadata(sec_ctx, sa, pkt, NULL);
			pkt->ol_flags = RTE_MBUF_F_TX_SEC_OFFLOAD;
			pkt->l2_len = RTE_ETHER_HDR_LEN;

			tx_pkts[k++] = pkt;
		}
		nb_tx = rte_eth_tx_burst(portid, queueid, tx_pkts, k);

		lconf->tx_pkts += nb_tx;

		if (unlikely(nb_tx < k)) {
			do {
				rte_pktmbuf_free(tx_pkts[nb_tx]);
			} while (++nb_tx < k);
		}
	}

	return 0;
}

static int
outb_sa_exp_event_callback(uint16_t port_id, enum rte_eth_event_type type, void *param,
			   void *ret_param)
{
	struct rte_eth_event_ipsec_desc *event_desc = NULL;
	struct outb_sa_exp_info *sa_exp;

	if (type != RTE_ETH_EVENT_IPSEC)
		return -1;

	RTE_SET_USED(param);

	event_desc = ret_param;
	if (event_desc == NULL) {
		printf("Event descriptor not set\n");
		return -1;
	}
	switch (event_desc->subtype) {
	case RTE_ETH_EVENT_IPSEC_SA_PKT_EXPIRY:
		break;
	default:
		return -1;
	}
	sa_exp = malloc(sizeof(*sa_exp));
	if (!sa_exp)
		return -1;

	memset(sa_exp, 0, sizeof(*sa_exp));
	sa_exp->port_id = port_id;
	sa_exp->sa_data = (struct ipsec_session_data *)event_desc->metadata;

	pthread_mutex_lock(&mutex);
	TAILQ_INSERT_TAIL(&sa_exp_q, sa_exp, next);
	pthread_cond_signal(&cond);
	pthread_mutex_unlock(&mutex);

	return 0;
}

static int
setup_ipsec_inb_sessions(int portid, struct ipsec_session_data *conf,
			 enum rte_security_ipsec_tunnel_type tun_type)
{
	enum rte_security_ipsec_sa_direction dir = RTE_SECURITY_IPSEC_SA_DIR_INGRESS;
	const struct rte_security_capability *sec_cap;
	struct ipsec_session_data *sa_data;
	struct rte_security_ctx *sec_ctx;
	uint32_t sa_index = 0;
	int ret, i;

	sec_ctx = rte_eth_dev_get_sec_ctx(portid);

	sec_cap = rte_security_capabilities_get(sec_ctx);
	if (sec_cap == NULL) {
		printf("No capabilities registered\n");
		return -1;
	}

	/* iterate until ESP tunnel*/
	while (sec_cap->action != RTE_SECURITY_ACTION_TYPE_NONE) {
		if (sec_cap->action == RTE_SECURITY_ACTION_TYPE_INLINE_PROTOCOL &&
		    sec_cap->protocol == RTE_SECURITY_PROTOCOL_IPSEC &&
		    sec_cap->ipsec.mode == conf->ipsec_xform.mode &&
		    sec_cap->ipsec.direction == dir)
			break;
		sec_cap++;
	}

	if (sec_cap->action == RTE_SECURITY_ACTION_TYPE_NONE) {
		printf("No suitable security capability found\n");
		return -1;
	}

	for (i = 1; i <= (int)num_sas; i++) {
		sa_index = i;

		sa_data = rte_zmalloc(NULL, sizeof(*sa_data), 0);
		if (sa_data == NULL) {
			ret = -ENOMEM;
			goto exit;
		}

		memcpy(sa_data, conf, sizeof(*sa_data));

		sa_data->ipsec_xform.spi = sa_index;
		sa_data->ipsec_xform.direction = dir;
		sa_data->ipsec_xform.tunnel.type = tun_type;
		if (softexp) {
			sa_data->ipsec_xform.life.packets_soft_limit = soft_limit - 1;
			sa_data->ipsec_xform.options.stats = 1;
		}
		if (inl_inb_oop)
			sa_data->ipsec_xform.options.ingress_oop = 1;

		/* Create Inline IPsec inbound session. */
		ret = create_ipsec_perf_session(sa_data, portid, &inb_sas[sa_index].sa);
		if (ret) {
			rte_free(inb_sas[sa_index].sa_data);
			goto exit;
		}
		inb_sas[sa_index].sa_data = sa_data;
	}
	return 0;

exit:
	i--;
	for (; i > 0; i--) {
		if (inb_sas[i].sa)
			rte_security_session_destroy(sec_ctx, inb_sas[i].sa);
		rte_free(inb_sas[i].sa_data);
	}
	return ret;
}

static int
setup_ipsec_outb_sessions(int portid, struct ipsec_session_data *conf,
			  enum rte_security_ipsec_tunnel_type tun_type)
{
	enum rte_security_ipsec_sa_direction dir = RTE_SECURITY_IPSEC_SA_DIR_EGRESS;
	const struct rte_security_capability *sec_cap;
	enum rte_security_session_action_type action;
	struct ipsec_session_data *sa_data;
	uint32_t sa_index = 0;
	void *sec_ctx;
	int ret = 0, i;

	if (testmode == EVENT_IPSEC_INB_LAOUTB_PERF) {
		sec_ctx = rte_cryptodev_get_sec_ctx(0);
		action = RTE_SECURITY_ACTION_TYPE_LOOKASIDE_PROTOCOL;
	} else {
		sec_ctx = rte_eth_dev_get_sec_ctx(portid);
		action = RTE_SECURITY_ACTION_TYPE_INLINE_PROTOCOL;
	}

	sec_cap = rte_security_capabilities_get(sec_ctx);
	if (sec_cap == NULL) {
		printf("No capabilities registered\n");
		return -1;
	}

	/* iterate until ESP tunnel*/
	while (sec_cap->action != RTE_SECURITY_ACTION_TYPE_NONE) {
		if (sec_cap->action == action &&
		    sec_cap->protocol == RTE_SECURITY_PROTOCOL_IPSEC &&
		    sec_cap->ipsec.mode == conf->ipsec_xform.mode &&
		    sec_cap->ipsec.direction == dir)
			break;
		sec_cap++;
	}

	if (sec_cap->action == RTE_SECURITY_ACTION_TYPE_NONE) {
		printf("No suitable security capability found\n");
		return -1;
	}
	for (i = 1; i <= (int)num_sas; i++) {
		sa_index = i;

		sa_data = rte_zmalloc(NULL, sizeof(*sa_data), 0);
		if (sa_data == NULL)
			goto exit;

		memcpy(sa_data, conf, sizeof(*sa_data));

		sa_data->ipsec_xform.direction = dir;
		sa_data->ipsec_xform.tunnel.type = tun_type;
		sa_data->ipsec_xform.spi = sa_index;
		if (softexp) {
			sa_data->ipsec_xform.life.packets_soft_limit = soft_limit - 1;
			sa_data->ipsec_xform.options.stats = 1;
		}
		/* Create Inline IPsec inbound session. */
		if (testmode == EVENT_IPSEC_INB_LAOUTB_PERF)
			ret = create_ipsec_laoutb_perf_session(sa_data, 0, &outb_sas[sa_index].sa);
		else
			ret = create_ipsec_perf_session(sa_data, portid, &outb_sas[sa_index].sa);

		if (ret) {
			rte_free(outb_sas[sa_index].sa_data);
			goto exit;
		}
		outb_sas[sa_index].sa_data = sa_data;
	}
	if (softexp && testmode != EVENT_IPSEC_INB_LAOUTB_PERF)
		rte_eth_dev_callback_register(portid, RTE_ETH_EVENT_IPSEC,
					      outb_sa_exp_event_callback, NULL);

	return 0;

exit:
	i--;
	for (; i > 0; i--) {
		if (outb_sas[i].sa)
			rte_security_session_destroy(sec_ctx, outb_sas[i].sa);
		rte_free(outb_sas[i].sa_data);
	}
	return ret;
}

static int
event_ipsec_inb_laoutb_perf(void)
{
	enum rte_security_ipsec_tunnel_type tun_type = RTE_SECURITY_IPSEC_TUNNEL_IPV4;
	struct rte_security_ctx *sec_ctx;
	unsigned int portid = 0;
	uint16_t lcore_id;
	int ret = 0, i;
	void *la_ctx;

	TAILQ_INIT(&sa_exp_q);

	sec_ctx = rte_eth_dev_get_sec_ctx(portid);
	if (sec_ctx == NULL) {
		printf("Ethernet device doesn't support security features.\n");
		return -1;
	}
	la_ctx = rte_cryptodev_get_sec_ctx(0);
	if (la_ctx == NULL) {
		printf("Crypto device doesn't support security features.\n");
		return -1;
	}

	dump_alg_data(sess_conf);
	/* Create one ESP rule per alg on port 0 and it would apply on all ports
	 * due to custom_act
	 */
	ret = setup_ipsec_inb_sessions(portid, sess_conf, tun_type);
	if (ret) {
		printf("IPsec inbound sessions creation failed\n");
		return ret;
	}
	ret = setup_ipsec_outb_sessions(portid, sess_conf, tun_type);
	if (ret) {
		printf("IPsec outbound sessions creation failed\n");
		goto inb_sas_destroy;
	}

	if (action_alg == DEFAULT_SEC_ACTION_ALG)
		create_default_ipsec_flow(portid);

	printf("\n");

	/* Start event dev */
	ut_eventdev_start();

	/* launch per-lcore init on every lcore */
	rte_eal_mp_remote_launch(event_inb_laoutb_worker, NULL, SKIP_MAIN);
	/* Print stats */
	print_inb_outb_stats();

	RTE_LCORE_FOREACH_WORKER(lcore_id) {
		if (rte_eal_wait_lcore(lcore_id) < 0)
			break;
	}

	if (action_alg == DEFAULT_SEC_ACTION_ALG)
		destroy_default_ipsec_flow(portid);
	else
		destroy_default_flow(portid);

	for (i = 1; i <= (int)num_sas; i++) {
		if (outb_sas[i].sa)
			rte_security_session_destroy(la_ctx, outb_sas[i].sa);
		rte_free(outb_sas[i].sa_data);
	}
inb_sas_destroy:
	for (i = 1; i <= (int)num_sas; i++) {
		if (inb_sas[i].sa)
			rte_security_session_destroy(sec_ctx, inb_sas[i].sa);
		rte_free(inb_sas[i].sa_data);
	}

	return ret;
}

static int
ipsec_inb_outb_perf(void)
{
	enum rte_security_ipsec_tunnel_type tun_type = RTE_SECURITY_IPSEC_TUNNEL_IPV4;
	struct rte_security_ctx *sec_ctx;
	unsigned int portid = 0;
	uint16_t lcore_id;
	int ret = 0, i;

	TAILQ_INIT(&sa_exp_q);

	sec_ctx = rte_eth_dev_get_sec_ctx(portid);
	if (sec_ctx == NULL) {
		printf("Ethernet device doesn't support security features.\n");
		return -1;
	}

	dump_alg_data(sess_conf);
	/* Create one ESP rule per alg on port 0 and it would apply on all ports
	 * due to custom_act
	 */
	ret = setup_ipsec_inb_sessions(portid, sess_conf, tun_type);
	if (ret) {
		printf("IPsec inbound sessions creation failed\n");
		return ret;
	}
	ret = setup_ipsec_outb_sessions(portid, sess_conf, tun_type);
	if (ret) {
		printf("IPsec outbound sessions creation failed\n");
		goto inb_sas_destroy;
	}

	if (action_alg == DEFAULT_SEC_ACTION_ALG)
		create_default_ipsec_flow(portid);

	printf("\n");

	/* launch per-lcore init on every lcore */
	if (event_en) {
		/* Start event dev */
		ut_eventdev_start();

		rte_eal_mp_remote_launch(event_inb_outb_worker, NULL, SKIP_MAIN);
	} else if (poll_mode)
		rte_eal_mp_remote_launch(poll_mode_inb_outb_worker, NULL, SKIP_MAIN);

	/* Print stats */
	print_inb_outb_stats();

	RTE_LCORE_FOREACH_WORKER(lcore_id) {
		if (rte_eal_wait_lcore(lcore_id) < 0)
			break;
	}

	if (action_alg == DEFAULT_SEC_ACTION_ALG)
		destroy_default_ipsec_flow(portid);
	else
		destroy_default_flow(portid);

	if (softexp)
		rte_eth_dev_callback_unregister(portid, RTE_ETH_EVENT_IPSEC,
						outb_sa_exp_event_callback, NULL);
	for (i = 0; i <= (int)num_sas; i++) {
		if (outb_sas[i].sa)
			rte_security_session_destroy(sec_ctx, outb_sas[i].sa);
		rte_free(outb_sas[i].sa_data);
	}
inb_sas_destroy:
	for (i = 0; i <= (int)num_sas; i++) {
		if (inb_sas[i].sa)
			rte_security_session_destroy(sec_ctx, inb_sas[i].sa);
		rte_free(inb_sas[i].sa_data);
	}

	return ret;
}

static int
ipsec_inb_perf(void)
{
	enum rte_security_ipsec_tunnel_type tun_type = RTE_SECURITY_IPSEC_TUNNEL_IPV4;
	struct rte_security_ctx *sec_ctx;
	unsigned int portid = 0;
	uint16_t lcore_id;
	int ret = 0, i;

	dump_alg_data(sess_conf);

	sec_ctx = rte_eth_dev_get_sec_ctx(portid);
	if (sec_ctx == NULL) {
		printf("Ethernet device doesn't support security features.\n");
		return -1;
	}
	ret = setup_ipsec_inb_sessions(portid, sess_conf, tun_type);
	if (ret) {
		printf("IPsec inbound sessions creation failed\n");
		return ret;
	}

	if (action_alg == DEFAULT_SEC_ACTION_ALG)
		create_default_ipsec_flow(portid);

	printf("\n");

	if (event_en) {
		/* Start event dev */
		ut_eventdev_start();

		/* launch per-lcore init on every lcore */
		rte_eal_mp_remote_launch(event_inb_worker, NULL, SKIP_MAIN);
	} else if (poll_mode) {
		/* launch per-lcore init on every lcore */
		rte_eal_mp_remote_launch(poll_mode_inb_worker, NULL, SKIP_MAIN);
	}

	/* Print stats */
	print_stats();

	RTE_LCORE_FOREACH_WORKER(lcore_id) {
		if (rte_eal_wait_lcore(lcore_id) < 0)
			break;
	}

	if (action_alg == DEFAULT_SEC_ACTION_ALG)
		destroy_default_ipsec_flow(portid);
	else
		destroy_default_flow(portid);

	for (i = 0; i <= (int)num_sas; i++) {
		if (inb_sas[i].sa)
			rte_security_session_destroy(sec_ctx, inb_sas[i].sa);
		rte_free(inb_sas[i].sa_data);
	}

	return ret;
}

static int
ipsec_outb_perf(void)
{
	enum rte_security_ipsec_tunnel_type tun_type = RTE_SECURITY_IPSEC_TUNNEL_IPV4;
	struct rte_security_ctx *sec_ctx;
	unsigned int portid = 0;
	uint16_t lcore_id;
	int ret = 0, i;

	TAILQ_INIT(&sa_exp_q);

	sec_ctx = rte_eth_dev_get_sec_ctx(portid);
	if (sec_ctx == NULL) {
		printf("Ethernet device doesn't support security features.\n");
		return -1;
	}

	dump_alg_data(sess_conf);
	ret = setup_ipsec_outb_sessions(portid, sess_conf, tun_type);
	if (ret) {
		printf("IPsec sessions creation failed\n");
		return -1;
	}

	printf("\n");

	/* launch per-lcore init on every lcore */
	if (event_en) {
		/* Start event dev */
		ut_eventdev_start();

		rte_eal_mp_remote_launch(event_outb_worker, NULL, SKIP_MAIN);
	} else if (poll_mode) {
		rte_eal_mp_remote_launch(poll_mode_outb_worker, NULL, SKIP_MAIN);
	}

	/* Print stats */
	print_inb_outb_stats();

	RTE_LCORE_FOREACH_WORKER(lcore_id) {
		if (rte_eal_wait_lcore(lcore_id) < 0)
			break;
	}

	if (softexp)
		rte_eth_dev_callback_unregister(portid, RTE_ETH_EVENT_IPSEC,
						outb_sa_exp_event_callback, NULL);
	for (i = 0; i < (int)num_sas; i++) {
		if (outb_sas[i].sa)
			rte_security_session_destroy(sec_ctx, outb_sas[i].sa);
		rte_free(outb_sas[i].sa_data);
	}

	return ret;
}

static int
event_ipsec_inb_msns_perf(void)
{
	struct rte_security_session *in_ses[RTE_MAX_ETHPORTS][RTE_PMD_CNXK_SEC_ACTION_ALG3 + 1];
	enum rte_security_ipsec_tunnel_type tun_type = RTE_SECURITY_IPSEC_TUNNEL_IPV4;
	struct rte_security_session_conf conf = {0};
	enum rte_security_ipsec_sa_direction dir;
	struct rte_security_ctx *sec_ctx = NULL;
	uint32_t sa_indices[RTE_MAX_ETHPORTS];
	uint32_t sa_index = 0;
	struct ipsec_session_data sa_data;
	unsigned int portid;
	uint16_t sa_hi = 0, sa_lo = 0;
	uint16_t lcore_id;
	uint32_t spi = 0;
	int ret = 0;
	uint8_t alg;

	memset(&in_ses, 0, sizeof(in_ses));
	memset(sa_indices, 0xFF, sizeof(sa_indices));

	dump_alg_data(sess_conf);
	/* Create one ESP rule per alg on port 0 and it would apply on all ports
	 * due to custom_act
	 */
	dir = RTE_SECURITY_IPSEC_SA_DIR_INGRESS;
	RTE_ETH_FOREACH_DEV(portid) {
		if ((ethdev_port_mask & RTE_BIT64(portid)) == 0)
			continue;
		sec_ctx = (struct rte_security_ctx *)rte_eth_dev_get_sec_ctx(portid);

		sa_index = cnxk_sa_index_alloc(0, dir, 16);
		for (alg = RTE_PMD_CNXK_SEC_ACTION_ALG0; alg <= RTE_PMD_CNXK_SEC_ACTION_ALG3;
		     alg++) {

			switch (alg) {
			case RTE_PMD_CNXK_SEC_ACTION_ALG0:
				spi = (0x2 << 28 | sa_index);
				sa_hi = (spi >> 16) & 0xffff;
				sa_lo = 0x0;
				break;
			case RTE_PMD_CNXK_SEC_ACTION_ALG1:
				/* Only SPI[31:28] are considered as SA[3:0] hence use.
				 * rest from SPI[15:4].
				 */
				spi = ((sa_index & 0xF) << 28) | ((sa_index >> 4) << 4);
				sa_hi = (spi >> 16) & 0xffff;
				sa_lo = 0x0000;
				break;
			case RTE_PMD_CNXK_SEC_ACTION_ALG2:
				/* Only SPI[27:25] are considered as SA[2:0] hence use.
				 * rest from SPI[15:3].
				 */
				spi = ((sa_index & 0x7) << 25) | ((sa_index >> 3) << 3);
				sa_hi = (spi >> 16) & 0xffff;
				sa_lo = 0x0000;
				break;
			case RTE_PMD_CNXK_SEC_ACTION_ALG3:
				/* Only SPI[28:25] are considered as SA[3:0] hence use.
				 * rest from SPI[15:4].
				 */
				spi = ((sa_index & 0xF) << 25) | ((sa_index >> 4) << 4);
				sa_hi = (spi >> 16) & 0xffff;
				sa_lo = 0x0000;
				break;
			default:
				break;
			}

			memcpy(&sa_data, sess_conf, sizeof(sa_data));
			sa_data.ipsec_xform.spi = sa_index;
			/* Create Inline IPsec inbound session. */
			ret = create_inline_ipsec_session(&sa_data, portid, &in_ses[portid][alg],
							  dir, tun_type);
			if (ret)
				goto out;
			printf("Port %d: Created alg %d Inbound session with sa_index = 0x%x\n",
			       portid, alg, sa_data.ipsec_xform.spi);

			sa_data.ipsec_xform.spi = spi;
			sa_data.ipsec_xform.direction = dir;
			conf.action_type = RTE_SECURITY_ACTION_TYPE_INLINE_PROTOCOL;
			conf.protocol = RTE_SECURITY_PROTOCOL_IPSEC;
			memcpy(&conf.ipsec, &sa_data.ipsec_xform,
			       sizeof(struct rte_security_ipsec_xform));
			conf.crypto_xform = &sa_data.xform.aead;
			ret = rte_security_session_update(sec_ctx, in_ses[portid][alg], &conf);
			if (ret) {
				printf("Security session update failed inbound\n");
				goto out;
			}
			printf("Port %d: Updated alg %d Inbound session with SPI = 0x%x\n",
			       portid, alg, sa_data.ipsec_xform.spi);

			/* Create all flow rules on port 0 and it would get applied on all ports due
			 * to channel mask.
			 */
			ret = create_default_flow(portid, alg, sa_data.ipsec_xform.spi,
						  sa_lo, sa_hi, sa_index);
			if (ret) {
				printf("Flow creation failed\n");
				goto out;
			}
			sa_index++;
		}
	}

	printf("\n");

	/* Start event dev */
	ut_eventdev_start();

	/* launch per-lcore init on every lcore */
	rte_eal_mp_remote_launch(event_inb_worker, NULL, SKIP_MAIN);

	/* Print stats */
	print_stats();

	RTE_LCORE_FOREACH_WORKER(lcore_id) {
		if (rte_eal_wait_lcore(lcore_id) < 0)
			return -1;
	}
out:
	RTE_ETH_FOREACH_DEV(portid) {
		if ((ethdev_port_mask & RTE_BIT64(portid)) == 0)
			continue;
		destroy_default_flow(portid);

		if (sa_indices[portid] != UINT32_MAX)
			cnxk_sa_index_free(portid, dir, sa_indices[portid], 16);
		sa_indices[portid] = UINT32_MAX;

		/* Clear session data. */
		for (alg = 0; alg <= RTE_PMD_CNXK_SEC_ACTION_ALG3; alg++) {
			if (in_ses[portid][alg])
				rte_security_session_destroy(sec_ctx, in_ses[portid][alg]);
		}
	}
	return ret;
}

int
main(int argc, char **argv)
{
	const char *pattern = "cn20k";
	int rc = 0;

	signal(SIGINT, signal_handler);
	signal(SIGTERM, signal_handler);

	rc = ut_setup(argc, argv);
	if (rc) {
		printf("TEST FAILED: ut_setup\n");
		return rc;
	}

	is_plat_cn20k = strstr(rte_pmd_cnxk_model_str_get(), pattern) ? true : false;
	printf("\n");
	switch (testmode) {
	case EVENT_IPSEC_INB_MSNS_PERF:
		printf("Test Mode: %s\n", ipsec_test_mode_to_string(testmode));
		rc = event_ipsec_inb_msns_perf();
		if (rc)
			printf("Failed to run mode: %s\n", ipsec_test_mode_to_string(testmode));
		break;
	case EVENT_IPSEC_INB_PERF:
	case POLL_IPSEC_INB_PERF:
		printf("Test Mode: %s\n", ipsec_test_mode_to_string(testmode));
		rc = ipsec_inb_perf();
		if (rc)
			printf("Failed to run mode: %s\n", ipsec_test_mode_to_string(testmode));
		break;
	case EVENT_IPSEC_INB_LAOUTB_PERF:
		printf("Test Mode: %s\n", ipsec_test_mode_to_string(testmode));
		if (rte_cryptodev_count() == 0) {
			printf("No cryptodevs found\n");
			rc = -1;
		}
		rc = event_ipsec_inb_laoutb_perf();
		if (rc)
			printf("Failed to run mode: %s\n", ipsec_test_mode_to_string(testmode));
		break;
	case EVENT_IPSEC_OUTB_PERF:
	case POLL_IPSEC_OUTB_PERF:
		printf("Test Mode: %s\n", ipsec_test_mode_to_string(testmode));
		rc = ipsec_outb_perf();
		if (rc)
			printf("Failed to run mode: %s\n", ipsec_test_mode_to_string(testmode));
		break;
	case EVENT_IPSEC_INB_OUTB_PERF:
	case POLL_IPSEC_INB_OUTB_PERF:
		printf("Test Mode: %s\n", ipsec_test_mode_to_string(testmode));
		rc = ipsec_inb_outb_perf();
		if (rc)
			printf("Failed to run mode: %s\n", ipsec_test_mode_to_string(testmode));
		break;
	case IPSEC_MSNS:
		rc = ut_ipsec_ipv4_burst_encap_decap();
		if (rc)
			printf("TEST FAILED: ut_ipsec_ipv4_burst_encap_decap\n");
		break;
	case IPSEC_RTE_PMD_CNXK_API_TEST:
		printf("Model: %s Test Mode: %s\n", rte_pmd_cnxk_model_str_get(),
		       ipsec_test_mode_to_string(testmode));
		rc = rte_pmd_cnxk_api_test();
		printf("Test %s: %s\n", ipsec_test_mode_to_string(testmode), rc ? "FAILED" : "PASS");
		break;
	}
	ut_teardown();
	return rc;
}
