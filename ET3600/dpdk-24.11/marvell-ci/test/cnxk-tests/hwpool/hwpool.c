/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2023 Marvell.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <inttypes.h>
#include <errno.h>
#include <signal.h>
#include <stdbool.h>

#include <rte_common.h>
#include <rte_eal.h>
#include <rte_debug.h>
#include <rte_mempool.h>
#include <rte_mbuf.h>
#include <rte_mbuf_pool_ops.h>
#include <rte_log.h>
#include <rte_pmd_cnxk_mempool.h>

#define HWPOOL_NUM_POOLS  10
#define HWPOOL_NUM_BUFS   10000
#define HWPOOL_BUF_SIZE   1024
#define HWPOOL_ALLOC_ITER 100

#define HW_POOL_OPS_NAME "cn10k_hwpool_ops"

#define ERROR(...)  rte_log(RTE_LOG_ERR, RTE_LOGTYPE_USER1, __VA_ARGS__)
#define NOTICE(...) rte_log(RTE_LOG_NOTICE, RTE_LOGTYPE_USER1, __VA_ARGS__)
#define EXIT(...)   rte_exit(EXIT_FAILURE, __VA_ARGS__)

static void
signal_handler(int signum)
{
	if (signum == SIGINT || signum == SIGTERM)
		ERROR("\n\nSignal %d received, preparing to exit..\n", signum);
}

static struct rte_mempool *
create_pktmbuf_pool(const char *name, int num_bufs, int buf_sz, int cache_sz)
{
	struct rte_pktmbuf_pool_private mbp_priv;
	struct rte_mempool *mp;
	uint16_t first_skip;
	int rc;

	mp = rte_mempool_create_empty(name, num_bufs, buf_sz, cache_sz,
				      sizeof(struct rte_pktmbuf_pool_private), SOCKET_ID_ANY, 0);
	if (!mp) {
		ERROR("Failed to create empty mbuf pool\n");
		return NULL;
	}

	rc = rte_mempool_set_ops_byname(mp, rte_mbuf_platform_mempool_ops(), NULL);
	if (rc) {
		ERROR("Failed to set ops for mbuf pool\n");
		goto free_pool;
	}

	/* Init mempool private area */
	first_skip = sizeof(struct rte_mbuf) + RTE_PKTMBUF_HEADROOM;
	memset(&mbp_priv, 0, sizeof(mbp_priv));
	mbp_priv.mbuf_data_room_size = (buf_sz - first_skip + RTE_PKTMBUF_HEADROOM);
	rte_pktmbuf_pool_init(mp, &mbp_priv);

	rc = rte_mempool_populate_default(mp);
	if (rc < 0) {
		ERROR("Failed to populate mbuf pool\n");
		goto free_pool;
	}

	rte_mempool_obj_iter(mp, rte_pktmbuf_init, NULL);

	return mp;
free_pool:
	rte_mempool_free(mp);
	return NULL;
}

static struct rte_mempool *
create_hwpool(const char *name, struct rte_mempool *mp, int num_bufs, int buf_sz, int cache_sz)
{
	struct rte_mempool *hp;
	int rc;

	hp = rte_mempool_create_empty(name, num_bufs, buf_sz, cache_sz,
				      sizeof(struct rte_pktmbuf_pool_private),
				      SOCKET_ID_ANY, 0);
	if (!hp) {
		ERROR("Failed to create empty hwpool\n");
		return NULL;
	}

	rc = rte_mempool_set_ops_byname(hp, HW_POOL_OPS_NAME, mp);
	if (rc) {
		ERROR("Failed to set ops for hwpool\n");
		goto free_pool;
	}

	rc = rte_mempool_populate_default(hp);
	if (rc < 0) {
		ERROR("Failed to populate hwpool\n");
		goto free_pool;
	}

	return hp;
free_pool:
	rte_mempool_free(hp);
	return NULL;
}

static struct rte_mbuf *
pktmbuf_alloc(struct rte_mempool *pool)
{
	unsigned int count_mp1, count_mp2, count_hp1, count_hp2;
	struct rte_mempool *hp, *mp;
	struct rte_mbuf *m;

	if (!rte_pmd_cnxk_mempool_is_hwpool(pool))
		return rte_pktmbuf_alloc(pool);

	/* If its a hwpool, make sure that the count in the master pool and hwpool
	 * are decrementing appropriately after alloc
	 */
	hp = pool;
	mp = (struct rte_mempool *)((uint64_t)hp->pool_config & ~0xFUL);
	count_hp1 = rte_mempool_avail_count(hp);
	count_mp1 = rte_mempool_avail_count(mp);
	m = rte_pktmbuf_alloc(hp);
	if (!m)
		return NULL;

	count_hp2 = rte_mempool_avail_count(hp);
	count_mp2 = rte_mempool_avail_count(mp);

	if ((count_hp1 - count_hp2 != 1) || (count_mp1 - count_mp2 != 1))
		EXIT("Count not decrementing properly after alloc hwpool=%s (prev=%u, curr=%u) "
		     "mpool=%s (prev=%u, curr=%u)\n", hp->name, count_hp1, count_hp2, mp->name,
		     count_mp1, count_mp2);
	return m;
}

static void
pktmbuf_free(struct rte_mbuf *m)
{
	unsigned int count_mp1, count_mp2, count_hp1, count_hp2;
	struct rte_mempool *hp, *mp;

	if (!rte_pmd_cnxk_mempool_is_hwpool(m->pool))
		return rte_pktmbuf_free(m);

	/* If its a hwpool, make sure that the count in the master pool and hwpool
	 * are incrementing appropriately after free.
	 */
	hp = m->pool;
	mp = (struct rte_mempool *)((uint64_t)hp->pool_config & ~0xFUL);
	count_hp1 = rte_mempool_avail_count(hp);
	count_mp1 = rte_mempool_avail_count(mp);
	rte_pktmbuf_free(m);
	count_hp2 = rte_mempool_avail_count(hp);
	count_mp2 = rte_mempool_avail_count(mp);

	if ((count_hp2 - count_hp1 != 1) || (count_mp2 - count_mp1 != 1))
		EXIT("Count not incrementing properly after free hwpool=%s (prev=%u, curr=%u) "
		     "mpool=%s (prev=%u, curr=%u)\n", hp->name, count_hp1, count_hp2, mp->name,
		     count_mp1, count_mp2);
}

static void
test_mbuf_exchange(void)
{
	struct rte_mempool **pools;
	struct rte_mbuf **mbufs;
	struct rte_mempool *mp;
	int i, j;

	/* Create master pool */
	mp = create_pktmbuf_pool("master_pool", HWPOOL_NUM_BUFS, HWPOOL_BUF_SIZE, 0);
	if (mp == NULL)
		EXIT("Cannot create main pool\n");

	/* Allocate storage area for pool pointers and allocated mbufs */
	pools = malloc(HWPOOL_NUM_POOLS * sizeof(struct rte_mempool *));
	if (!pools)
		EXIT("Failed to alloc memory for pools\n");

	mbufs = malloc(HWPOOL_NUM_BUFS * sizeof(struct rte_mbuf *));
	if (!mbufs)
		EXIT("Failed to alloc memory for mbufs\n");

	/* Randomly create hwpools / normal pktmbuf pools */
	for (i = 0; i < HWPOOL_NUM_POOLS; i++) {
		char name[16];

		if (rand() & 0x1) {
			snprintf(name, sizeof(name), "hp_%d", i);
			pools[i] = create_hwpool(name, mp, HWPOOL_NUM_BUFS, HWPOOL_BUF_SIZE, 0);
		} else {
			snprintf(name, sizeof(name), "mpool_%d", i);
			pools[i] = create_pktmbuf_pool(name, HWPOOL_NUM_BUFS, HWPOOL_BUF_SIZE, 0);
		}

		if (pools[i] == NULL)
			EXIT("Failed to create pool %s\n", pools[i]->name);

		/* Disable range check for pools */
		if (rte_pmd_cnxk_mempool_range_check_disable(pools[i]))
			EXIT("Failed to disable range check for pool %s\n", pools[i]->name);
	}

	srand(time(0));
	for (i = 0; i < HWPOOL_ALLOC_ITER; i++) {
		unsigned int hwpool_allocs = 0;

		/* Randomly select pools and allocate buffers from those pools */
		for (j = 0; j < HWPOOL_NUM_BUFS; j++) {
			int m = rand() % HWPOOL_NUM_POOLS;

			/* Count the allocs made from hwpools */
			hwpool_allocs += rte_pmd_cnxk_mempool_is_hwpool(pools[m]);

			mbufs[j] = pktmbuf_alloc(pools[m]);
			if (!mbufs[j])
				EXIT("Failed to allocate mbuf\n");
		}

		/* Make sure that master pool has depleted by the number of hwpool allocs */
		if (rte_mempool_avail_count(mp) != HWPOOL_NUM_BUFS - hwpool_allocs)
			EXIT("Master pool not reflecting allocs from hwpools");

		/* Exchange the randomly allocated mbufs */
		for (j = 0; j < HWPOOL_NUM_BUFS / 2; j++) {
			if (rte_pmd_cnxk_mempool_mbuf_exchange(mbufs[j * 2], mbufs[j * 2 + 1]))
				EXIT("Mbuf exchange failed for mbufs %p and %p\n", mbufs[j * 2],
				     mbufs[j * 2 + 1]);
		}

		/* Free all the buffers back */
		for (j = 0; j < HWPOOL_NUM_BUFS; j++)
			pktmbuf_free(mbufs[j]);

		/* Make sure that master pool has got replenished */
		if (rte_mempool_avail_count(mp) != HWPOOL_NUM_BUFS)
			EXIT("Master pool not replenished\n");

		/* Make sure that all other pools also has replenished */
		for (j = 0; j < HWPOOL_NUM_POOLS; j++)
			if (rte_mempool_avail_count(pools[j]) != HWPOOL_NUM_BUFS)
				EXIT("Pool %s not replenished\n", pools[j]->name);
	}

	for (i = 0; i < HWPOOL_NUM_POOLS; i++)
		rte_mempool_free(pools[i]);

	if (rte_mempool_avail_count(mp) != HWPOOL_NUM_BUFS)
		EXIT("Master pool not full after hwpool destroy\n");

	free(mbufs);
	free(pools);
	rte_mempool_free(mp);
}

static void
test_hwpool_mbuf_alloc_free(void)
{
	struct rte_mempool **pools;
	struct rte_mbuf **mbufs;
	int i, j;

	pools = malloc((HWPOOL_NUM_POOLS + 1) * sizeof(struct rte_mempool *));
	if (!pools)
		EXIT("Failed to alloc memory for pools\n");

	/* Allocate the master pool, hwpools and storage area for allocated mbufs */
	pools[0] = create_pktmbuf_pool("master_pool", HWPOOL_NUM_BUFS, HWPOOL_BUF_SIZE, 0);
	if (pools[0] == NULL)
		EXIT("Cannot create master pool\n");

	for (i = 0; i < HWPOOL_NUM_POOLS; i++) {
		char name[16];

		snprintf(name, sizeof(name), "hp_%d", i);
		pools[i + 1] = create_hwpool(name, pools[0], HWPOOL_NUM_BUFS, HWPOOL_BUF_SIZE, 0);
		if (pools[i + 1] == NULL)
			EXIT("Failed to create hwpool %s\n", pools[i + 1]->name);
	}

	mbufs = malloc(HWPOOL_NUM_BUFS * sizeof(struct rte_mbuf *));
	if (!mbufs)
		EXIT("Failed to alloc memory for mbufs\n");

	srand(time(0));
	for (i = 0; i < HWPOOL_ALLOC_ITER; i++) {
		/* Allocate buffers randomly from any of the hwpools */
		for (j = 0; j < HWPOOL_NUM_BUFS; j++) {
			int k = rand() % HWPOOL_NUM_POOLS + 1;

			mbufs[j] = pktmbuf_alloc(pools[k]);
			if (!mbufs[j])
				EXIT("Failed to allocate mbuf\n");
		}

		/* Make sure that all pools are depleted */
		for (j = 0; j < HWPOOL_NUM_POOLS + 1; j++)
			if (rte_mempool_avail_count(pools[j]))
				EXIT("Pool %s not depleted\n", pools[j]->name);

		/* Free all allocated mbufs */
		for (j = 0; j < HWPOOL_NUM_BUFS; j++)
			pktmbuf_free(mbufs[j]);

		/* Make sure that all pools are replenished */
		for (j = 0; j < HWPOOL_NUM_POOLS + 1; j++)
			if (rte_mempool_avail_count(pools[j]) != HWPOOL_NUM_BUFS)
				EXIT("Pool %s not replenished\n", pools[j]->name);
	}

	/* Free all the pools in reverse order making sure that master pools is freed at last */
	for (i = HWPOOL_NUM_POOLS; i >= 1; i--)
		rte_mempool_free(pools[i]);

	if (rte_mempool_avail_count(pools[0]) != HWPOOL_NUM_BUFS)
		EXIT("Master pool not full after hwpool destroy\n");

	rte_mempool_free(pools[0]);

	free(mbufs);
	free(pools);
}

static void
test_hwpool_create(void)
{
	struct rte_mempool *mp_cache, *mp;
	struct rte_mempool *hp;

	mp_cache = create_pktmbuf_pool("mpool_w_cache", HWPOOL_NUM_BUFS, HWPOOL_BUF_SIZE, 128);
	mp = create_pktmbuf_pool("mpool_wo_cache", HWPOOL_NUM_BUFS, HWPOOL_BUF_SIZE, 0);
	if (mp == NULL || mp_cache == NULL)
		EXIT("Cannot create main pools\n");

	NOTICE("BEGIN: Hwpool Create Negative Test cases.\n");
	/* Negative Test - Test hwpool attach to master pool with cache */
	hp = create_hwpool("hwpool_invalid_0", mp_cache, HWPOOL_NUM_BUFS, HWPOOL_BUF_SIZE, 0);
	if (hp)
		EXIT("Hwpool should not be allowed to be attached to master pool with cache\n");

	/* Negative Test - Test creation of hwpool with cache */
	hp = create_hwpool("hwpool_invalid_1", mp, HWPOOL_NUM_BUFS, HWPOOL_BUF_SIZE, 128);
	if (hp)
		EXIT("Hwpool should not be allowed to be create with cache\n");

	/* Negative test - Test creation of hwpool with different number of buffers */
	hp = create_hwpool("hwpool_invalid_2", mp, HWPOOL_NUM_BUFS - 128, HWPOOL_BUF_SIZE, 0);
	if (hp)
		EXIT("Hwpool should not allowed to be created with different num bufs\n");

	/* Negative test - Test creation of hwpool with different number of buffers */
	hp = create_hwpool("hwpool_invalid_3", mp, HWPOOL_NUM_BUFS, HWPOOL_BUF_SIZE - 128, 0);
	if (hp)
		EXIT("Hwpool should not allowed to be created with different buf size\n");

	NOTICE("END: Hwpool Create Negative Test cases.\n");

	/* Valid hwpool creation */
	hp = create_hwpool("hwpool_valid", mp, HWPOOL_NUM_BUFS, HWPOOL_BUF_SIZE, 0);
	if (!hp)
		EXIT("Failed to create hwpool\n");

	rte_mempool_free(hp);
	rte_mempool_free(mp);
	rte_mempool_free(mp_cache);
}

int
main(int argc, char **argv)
{
	int ret;

	signal(SIGINT, signal_handler);
	signal(SIGTERM, signal_handler);
	ret = rte_eal_init(argc, argv);
	if (ret < 0)
		EXIT("Invalid EAL arguments\n");

	test_hwpool_create();
	test_hwpool_mbuf_alloc_free();
	test_mbuf_exchange();

	rte_eal_cleanup();

	return 0;
}
