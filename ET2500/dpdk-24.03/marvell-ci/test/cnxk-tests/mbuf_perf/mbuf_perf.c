/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2022 Marvell.
 */

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <inttypes.h>
#include <stdarg.h>
#include <errno.h>
#include <sys/queue.h>

#include <rte_common.h>
#include <rte_log.h>
#include <rte_debug.h>
#include <rte_memory.h>
#include <rte_launch.h>
#include <rte_cycles.h>
#include <rte_eal.h>
#include <rte_per_lcore.h>
#include <rte_lcore.h>
#include <rte_branch_prediction.h>
#include <rte_mempool.h>
#include <rte_spinlock.h>
#include <rte_malloc.h>
#include <rte_mbuf.h>
#include <rte_mbuf_pool_ops.h>

/*
 * Mbuf pool performance
 * =====================
 *
 *    Each core get *n_keep* mbufs per bulk of *n_get_bulk*. Then,
 *    mbufs are put back in the pool per bulk of *n_put_bulk*.
 *
 *    This sequence is done during TIME_S seconds.
 *
 *    This test is done on the following configurations:
 *
 *    - Cores configuration (*cores*)
 *
 *      - One core with cache
 *      - Two cores with cache
 *      - Max. cores with cache
 *      - One core without cache
 *      - Two cores without cache
 *      - Max. cores without cache
 *
 *    - Bulk size (*n_get_bulk*, *n_put_bulk*)
 *
 *      - Bulk get from 1 to 32
 *      - Bulk put from 1 to 32
 *      - Bulk get and put from 1 to 32, compile time constant
 *
 *    - Number of kept objects (*n_keep*)
 *
 *      - 32
 *      - 128
 *      - 512
 */

#define N 65536
#define MTU 1500
#define TIME_S 5
#define MAX_KEEP N
#define MEMPOOL_SIZE ((rte_lcore_count()*(MAX_KEEP+RTE_MEMPOOL_CACHE_MAX_SIZE*3))-1)

/* Number of pointers fitting into one cache line. */
#define CACHE_LINE_BURST (RTE_CACHE_LINE_SIZE / sizeof(uintptr_t))

#define LOG_ERR() printf("test failed at %s():%d\n", __func__, __LINE__)

static uint32_t synchro;

/* number of objects in one bulk operation (get or put) */
static unsigned int n_get_bulk;
static unsigned int n_put_bulk;

/* number of mbufs retrieved from mbuf pool before putting them back */
static unsigned int n_keep;

/* true if we want to test with constant n_get_bulk and n_put_bulk */
static int use_constant_values;

/* number of enqueues / dequeues */
struct mbuf_perf_test_stats {
	uint64_t enq_count;
	uint64_t alloc_cycles;
} __rte_cache_aligned;

static struct mbuf_perf_test_stats stats[RTE_MAX_LCORE];

static __rte_always_inline int
test_loop(struct rte_mempool *mp, unsigned int x_keep, unsigned int x_get_bulk,
	  unsigned int x_put_bulk, struct rte_mbuf **mbufs)
{
	unsigned int lcore_id = rte_lcore_id();
	uint64_t start_cycles;
	unsigned int idx;
	unsigned int i;
	int ret;

	for (i = 0; likely(i < (N / x_keep)); i++) {
		/* get x_keep mbufs by bulk of x_get_bulk */
		start_cycles = rte_get_timer_cycles();
		for (idx = 0; idx < x_keep; idx += x_get_bulk) {
			ret = rte_pktmbuf_alloc_bulk(mp, &mbufs[idx], x_get_bulk);
			if (unlikely(ret < 0)) {
				rte_mempool_dump(stdout, mp);
				return ret;
			}
		}
		stats[lcore_id].alloc_cycles += rte_get_timer_cycles() - start_cycles;

		/* put the mbufs back by bulk of x_put_bulk */
		for (idx = 0; idx < x_keep; idx += x_put_bulk)
			rte_pktmbuf_free_bulk(&mbufs[idx], x_put_bulk);
	}

	return 0;
}

static int
per_lcore_mbuf_perf_test(void *arg)
{
	uint64_t time_diff = 0, hz = rte_get_timer_hz();
	unsigned int lcore_id = rte_lcore_id();
	uint64_t start_cycles, end_cycles;
	struct rte_mempool *mp = arg;
	void *mbufs;
	int ret = -1;

	/* n_get_bulk and n_put_bulk must be divisors of n_keep */
	if (((n_keep / n_get_bulk) * n_get_bulk) != n_keep ||
	    ((n_keep / n_put_bulk) * n_put_bulk) != n_keep)
		goto out;

	memset(&stats[lcore_id], 0, sizeof(struct mbuf_perf_test_stats));

	/* wait synchro for workers */
	if (lcore_id != rte_get_main_lcore())
		rte_wait_until_equal_32(&synchro, 1, __ATOMIC_RELAXED);

	mbufs = rte_zmalloc(NULL, MAX_KEEP * sizeof(struct rte_mbuf *), RTE_CACHE_LINE_SIZE);
	if (!mbufs)
		goto out;

	start_cycles = rte_get_timer_cycles();
	while (time_diff/hz < TIME_S) {
		ret = test_loop(mp, n_keep, n_get_bulk, n_put_bulk, mbufs);
		if (ret < 0) {
			free(mbufs);
			goto out;
		}

		end_cycles = rte_get_timer_cycles();
		time_diff = end_cycles - start_cycles;
		stats[lcore_id].enq_count += N;
	}
	rte_free(mbufs);
	ret = 0;
out:
	return ret;
}

/* launch all the per-lcore test, and display the result */
static int
launch_cores(struct rte_mempool *mp, unsigned int cores)
{
	uint64_t hz = rte_get_timer_hz();
	unsigned int cores_save = cores;
	unsigned int lcore_id;
	uint64_t rate;
	int ret;

	__atomic_store_n(&synchro, 0, __ATOMIC_RELAXED);

	/* reset stats */
	memset(stats, 0, sizeof(stats));

	printf("mbuf_perf_autotest cache=%-4u cores=%-2u n_get_bulk=%-2u n_put_bulk=%-2u "
	       "n_keep=%-4u ", mp->cache_size, cores, n_get_bulk, n_put_bulk, n_keep);

	if (rte_mempool_avail_count(mp) != MEMPOOL_SIZE) {
		printf("mempool is not full\n");
		return -1;
	}

	RTE_LCORE_FOREACH_WORKER(lcore_id) {
		if (cores == 1)
			break;
		cores--;
		rte_eal_remote_launch(per_lcore_mbuf_perf_test, mp, lcore_id);
	}

	/* start synchro and launch test on main */
	__atomic_store_n(&synchro, 1, __ATOMIC_RELAXED);

	ret = per_lcore_mbuf_perf_test(mp);

	cores = cores_save;
	RTE_LCORE_FOREACH_WORKER(lcore_id) {
		if (cores == 1)
			break;
		cores--;
		if (rte_eal_wait_lcore(lcore_id) < 0)
			ret = -1;
	}

	if (ret < 0) {
		printf("per-lcore test returned -1\n");
		return -1;
	}

	rate = 0;
	for (lcore_id = 0; lcore_id < RTE_MAX_LCORE; lcore_id++)
		rate += (stats[lcore_id].enq_count / TIME_S);

	printf("rate_persec=%-10" PRIu64, rate);

	rate = 0;
	for (lcore_id = 0; lcore_id < RTE_MAX_LCORE; lcore_id++)
		rate += (stats[lcore_id].enq_count / (stats[lcore_id].alloc_cycles / hz));

	printf(" alloc_rate_persec=%-10" PRIu64 "\n", rate);

	return 0;
}

/* for a given number of core, launch all test cases */
static int
do_one_mbuf_perf_test(struct rte_mempool *mp, unsigned int cores)
{
	unsigned int bulk_tab_get[] = { 1, CACHE_LINE_BURST, 32, 0 };
	unsigned int bulk_tab_put[] = { 1, CACHE_LINE_BURST, 32, 0 };
	unsigned int keep_tab[] = { RTE_MEMPOOL_CACHE_MAX_SIZE / 2, RTE_MEMPOOL_CACHE_MAX_SIZE,
				    RTE_MEMPOOL_CACHE_MAX_SIZE * 2, RTE_MEMPOOL_CACHE_MAX_SIZE * 3,
				    MAX_KEEP, 0 };
	unsigned int *get_bulk_ptr, *put_bulk_ptr, *keep_ptr;
	int ret;

	for (keep_ptr = keep_tab; *keep_ptr; keep_ptr++) {
		for (get_bulk_ptr = bulk_tab_get; *get_bulk_ptr; get_bulk_ptr++) {
			for (put_bulk_ptr = bulk_tab_put; *put_bulk_ptr; put_bulk_ptr++) {
				use_constant_values = 0;
				n_get_bulk = *get_bulk_ptr;
				n_put_bulk = *put_bulk_ptr;
				n_keep = *keep_ptr;
				ret = launch_cores(mp, cores);
				if (ret < 0)
					return -1;
			}
		}
	}
	return 0;
}

int
main(int argc, char **argv)
{
	struct rte_mempool *mp_cache = NULL;
	struct rte_mempool *mp_nocache = NULL;
	int ret = -1;

	ret = rte_eal_init(argc, argv);
	if (ret < 0)
		goto exit;

	/* create a mbuf pool (without cache) */
	mp_nocache = rte_pktmbuf_pool_create("perf_test_nocache", MEMPOOL_SIZE,
					     0, 0, MTU, SOCKET_ID_ANY);
	if (mp_nocache == NULL)
		goto err;

	/* create a mbuf pool (with cache) */
	mp_cache = rte_pktmbuf_pool_create("perf_test_cache", MEMPOOL_SIZE,
				      RTE_MEMPOOL_CACHE_MAX_SIZE, 0, MTU,
				      SOCKET_ID_ANY);
	if (mp_cache == NULL)
		goto err;

	/* performance test with 1, 2 and max cores */
	printf("start performance test (without cache)\n");

	if (do_one_mbuf_perf_test(mp_nocache, 1) < 0)
		goto err;

	if (do_one_mbuf_perf_test(mp_nocache, 2) < 0)
		goto err;

	if (do_one_mbuf_perf_test(mp_nocache, rte_lcore_count()) < 0)
		goto err;

	/* performance test with 1, 2 and max cores */
	printf("start performance test (with cache)\n");

	if (do_one_mbuf_perf_test(mp_cache, 1) < 0)
		goto err;

	if (do_one_mbuf_perf_test(mp_cache, 2) < 0)
		goto err;

	if (do_one_mbuf_perf_test(mp_cache, rte_lcore_count()) < 0)
		goto err;

	rte_mempool_list_dump(stdout);

	ret = 0;

err:
	rte_mempool_free(mp_cache);
	rte_mempool_free(mp_nocache);
	rte_eal_cleanup();
exit:
	return ret;
}

