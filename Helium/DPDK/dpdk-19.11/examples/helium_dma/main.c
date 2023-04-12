/* SPDX-License-Identifier: BSD-3-Clause
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <inttypes.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/queue.h>
#include <netinet/in.h>
#include <setjmp.h>
#include <stdarg.h>
#include <ctype.h>
#include <errno.h>
#include <getopt.h>
#include <signal.h>
#include <stdbool.h>

#include <rte_common.h>
#include <rte_log.h>
#include <rte_malloc.h>
#include <rte_memory.h>
#include <rte_memcpy.h>
#include <rte_eal.h>
#include <rte_launch.h>
#include <rte_atomic.h>
#include <rte_cycles.h>
#include <rte_prefetch.h>
#include <rte_lcore.h>
#include <rte_per_lcore.h>
#include <rte_branch_prediction.h>
#include <rte_interrupts.h>
#include <rte_random.h>
#include <rte_debug.h>
#include <rte_ether.h>
#include <rte_ethdev.h>
#include <rte_mbuf_pool_ops.h>
#include <rte_mempool.h>
#include <rte_mbuf.h>
#include <rte_rawdev.h>

#include <otx2_dpi_rawdev.h>

#define DPI_MAX_COMP_ENTRIES	1024
#define DPI_BURST_REQ	10

#define DPI_MAX_DATA_SZ_PER_PTR	65535
#define DPI_MAX_PFS 2

static volatile bool force_quit;

static struct dpi_cring_data_s cring[DPI_MAX_PFS * DPI_MAX_VFS];
uint64_t raddr, laddr;
uint64_t data_size = 256;
uint64_t inb_data_size = 128;
uint64_t outb_data_size = 128;
int mode, n_iter = 1, perf_mode = 0;
int ptrs_per_instr = 1;
static void *chunk_pool;
uint64_t dma_submit_cnt[DPI_MAX_PFS * DPI_MAX_VFS] = { 0 };
uint64_t last_dma_submit_cnt[DPI_MAX_PFS * DPI_MAX_VFS] = { 0 };
uint64_t total_dma_cnt = 0;
static uint64_t timer_period = 1; /* default period is 1 seconds */
uint16_t nb_ports;
uint16_t pem_id = 0;

#define RTE_LOGTYPE_L2FWD RTE_LOGTYPE_USER1

static void
signal_handler(int signum)
{
	if (signum == SIGINT || signum == SIGTERM) {
		printf("\n\nSignal %d received, preparing to exit...\n",
				signum);
		force_quit = true;
	}
}

static uint8_t buffer_fill(uint8_t *addr, int len, uint8_t val)
{
        int j = 0;

        memset(addr, 0, len);
        for (j = 0; j < len; j++)
                *(addr + j) = val++;

        return val;
}

static inline void dump_buffer(uint8_t *addr, int len)
{
	int i;

	for (i = 0; i < len; i++) {
		if (!i || (i % 16) == 0)
			printf("\n%04x ", i);
		printf("%02x ", addr[i]);
	}
}

static int validate_buffer(uint8_t *saddr, uint8_t *daddr, int len)
{
        int j = 0, ret = 0;

        for (j = 0; j < len; j++) {
                if (*(saddr + j) != *(daddr + j)) {
                        printf("FAIL: Data Integrity failed\n");
                        printf("index: %d, Expected: 0x%x, Actaul: 0x%x\n",
                               j, *(saddr + j), *(daddr + j));
                        ret = -1;
                        break;
                }
        }
        return ret;
}

static inline int dma_test_outbound(int dma_port, int buf_size)
{
	uint8_t *fptr;
	union dpi_dma_ptr_u rptr = {0};
	union dpi_dma_ptr_u wptr = {0};
	struct rte_rawdev_buf *bufp[1];
	struct rte_rawdev_buf buf = {0};
	struct dpi_dma_buf_ptr_s cmd = {0};
	struct dpi_dma_req_compl_s *comp_data;
	struct dpi_dma_queue_ctx_s ctx = {0};
	void *d_buf[1];
	int ret;

	fptr = (uint8_t *)rte_malloc("dummy", buf_size, 128);
	comp_data = rte_malloc("dummy", buf_size, 128);
	if (!fptr) {
		printf("Unable to allocate internal memory\n");
		return -ENOMEM;
	}
	buffer_fill(fptr, buf_size, 2);
	memset(comp_data, 0, buf_size);
	rptr.s.ptr = (uint64_t)raddr;
	rptr.s.length = buf_size;
	wptr.s.ptr = (uint64_t)rte_malloc_virt2iova(fptr);
	wptr.s.length = buf_size;
	cmd.rptr[0] = &wptr;
	cmd.wptr[0] = &rptr;
	cmd.rptr_cnt = 1;
	cmd.wptr_cnt = 1;
	cmd.comp_ptr = comp_data;
	buf.buf_addr = (void *)&cmd;
	bufp[0] = &buf;

	ctx.xtype = DPI_XTYPE_OUTBOUND;
	ctx.pt = 0;
	ctx.pem_id = pem_id;
	ctx.c_ring = &cring[dma_port];

	ret = rte_rawdev_enqueue_buffers(dma_port,
					 (struct rte_rawdev_buf **)bufp, 1,
					 &ctx);
	if (ret < 0) {
		printf("Enqueue request failed\n");
		return 0;
	}

	/* Wait and dequeue completion */
	do {
		sleep(1);
		ret = rte_rawdev_dequeue_buffers(dma_port,
					 (struct rte_rawdev_buf **)&d_buf, 1,
					 &ctx);

		if (!ret) {
			printf("Dequeue request not completed\n");
		} else
			break;
		if (force_quit) {
//			dump_buffer(fptr, buf_size);
			goto free_buf;
		}
	} while (1);

free_buf:
	printf("Outbound DMA [%d] transfer successfully completed\n", dma_port);
	dump_buffer(fptr, buf_size);

	if (fptr)
		rte_free(fptr);
	if (comp_data)
		rte_free(comp_data);

	return 0;
}

static inline void dump_stats(void)
{
	int i;
	uint64_t tot = 0;

	for (i = 0; i < nb_ports; i++) {
		printf("DMA %d Count %ld %s %2.2f Gbps\n", i,
			(dma_submit_cnt[i] - last_dma_submit_cnt[i]),
			(mode==3 ? (i%2 ? "Outb":"Inb"):""),
			((dma_submit_cnt[i] - last_dma_submit_cnt[i]) *
		       		data_size*ptrs_per_instr * 8) /
		       		1000000000.0);
		tot += dma_submit_cnt[i];
		last_dma_submit_cnt[i] = dma_submit_cnt[i];
	}
	printf("\ntot %ld tot_dma %ld Total: %ld Perf:%2.2f Gbps\n", tot,
	       total_dma_cnt, (tot - total_dma_cnt),
	       ((tot - total_dma_cnt)*data_size*ptrs_per_instr*8)/1000000000.0);

	total_dma_cnt = tot;
}

static inline int perf_dma_test(void)
{
	uint8_t *fptr[DPI_BURST_REQ][DPI_MAX_POINTER];
	uint8_t *lptr[DPI_BURST_REQ][DPI_MAX_POINTER];
	union dpi_dma_ptr_u rptr[DPI_BURST_REQ][DPI_MAX_POINTER] = {0};
	union dpi_dma_ptr_u wptr[DPI_BURST_REQ][DPI_MAX_POINTER] = {0};
	struct rte_rawdev_buf *bufp[DPI_BURST_REQ];
	struct rte_rawdev_buf buf[DPI_BURST_REQ] = { {0} };
	struct dpi_dma_buf_ptr_s cmd[DPI_BURST_REQ] = {0};
	struct dpi_dma_req_compl_s *comp_data[DPI_BURST_REQ];
	struct dpi_dma_queue_ctx_s ctx = {0};
	void *d_buf[1];
	int ret, i, j, xfer_mode;
	uint64_t prev_tsc = 0, diff_tsc = 0, cur_tsc = 0;
	unsigned dma_port = rte_lcore_id();
	uint8_t max_ptr = ptrs_per_instr;
	uint8_t *remote_addr = (uint8_t *)raddr + (dma_port * 0x4000000ull);
	/* If lcore >= nb_ports skip processing */
	if (dma_port >= nb_ports)
		return 0;

	/* for dual mode use even ports for inbound DMA
	 * and odd ports for outbound DMA
	 */
	if (mode == 3)
		xfer_mode = (dma_port % 2) ? 2 : 1;
	else
		xfer_mode = mode;

	for (j = 0; j < DPI_BURST_REQ; j++) {
		comp_data[j] = rte_malloc("dummy", data_size, 128);
		memset(comp_data[j], 0, data_size);

		for (i = 0; i < max_ptr; i++) {
			lptr[j][i] = remote_addr;
			fptr[j][i] = (uint8_t *)rte_malloc("dummy", data_size,
							   128);
			if (!fptr[j][i]) {
				printf("Unable to allocate internal memory\n");
				return -ENOMEM;
			}
			wptr[j][i].s.length = data_size;
			buffer_fill(fptr[j][i], wptr[j][i].s.length, 0);
			wptr[j][i].s.ptr =
				(uint64_t)rte_malloc_virt2iova(fptr[j][i]);
			rptr[j][i].s.length = data_size;
			if (!xfer_mode) {
				lptr[j][i] = (uint8_t *)rte_malloc("dummy",
								   data_size,
								   128);
				if (!lptr[j][i]) {
					printf("Unable to allocate internal memory\n");
					return -ENOMEM;
				}
				memset(lptr[j][i], 0, data_size);
				rptr[j][i].s.ptr =
				     (uint64_t)rte_malloc_virt2iova(lptr[j][i]);
			} else {
				lptr[j][i] = lptr[j][i] + (i * 64 * 1024);
				rptr[j][i].s.ptr = (uint64_t)lptr[j][i];
			}
			if (xfer_mode == 1) {
				cmd[j].wptr[i] = &wptr[j][i];
				cmd[j].rptr[i] = &rptr[j][i];
			} else {
				cmd[j].wptr[i] = &rptr[j][i];
				cmd[j].rptr[i] = &wptr[j][i];
			}
		}
		cmd[j].rptr_cnt = max_ptr;
		cmd[j].wptr_cnt = max_ptr;

		cmd[j].comp_ptr = comp_data[j];
		buf[j].buf_addr = (void *)&cmd[j];
		bufp[j] = &buf[j];
	}

	if (xfer_mode == 1)
		ctx.xtype = DPI_XTYPE_INBOUND;
	else if (xfer_mode == 2)
		ctx.xtype = DPI_XTYPE_OUTBOUND;
	else
		ctx.xtype = DPI_XTYPE_INTERNAL_ONLY;

	ctx.pt = 0;
	ctx.pem_id = pem_id;
	ctx.c_ring = &cring[dma_port];

	ret = rte_rawdev_enqueue_buffers(dma_port,
					 (struct rte_rawdev_buf **)bufp, 1,
					 &ctx);
	if (ret < 0) {
		printf("Enqueue request failed\n");
		return 0;
	}

	i = 0;
	j = 1;
	/* Wait and dequeue completion */
	do {
		cur_tsc = rte_rdtsc();
		diff_tsc = cur_tsc - prev_tsc;
		if ((timer_period > 0) && (diff_tsc > timer_period) &&
			dma_port == rte_get_master_lcore()) {
			dump_stats();
			prev_tsc = cur_tsc;
		}
//		sleep(1);
		ret = rte_rawdev_dequeue_buffers(dma_port,
					 (struct rte_rawdev_buf **)&d_buf, 1,
					 &ctx);

		if (!ret) {
		//	printf("Dequeue request not completed\n");
		} else {
//			printf("%d requests completed\n", ++i);
			dma_submit_cnt[dma_port]++;
			ret = rte_rawdev_enqueue_buffers(dma_port,
					 (struct rte_rawdev_buf **)&bufp[j], 1,
					 &ctx);
			if (ret < 0) {
				printf("Enqueue request failed\n");
				return 0;
			}
			j = (j + 1) % DPI_BURST_REQ;
		}
		if (force_quit) {
//			dump_buffer(fptr[0], data_size);
			goto free_buf;
		}
	} while (1);

free_buf:
	printf("DMA transfer successfully completed\n");

	for (j = 0; j < DPI_BURST_REQ; j++) {
		for (i = 0; i < max_ptr; i++) {
			if (fptr[j][i])
				rte_free(fptr[j][i]);
			if (!xfer_mode && lptr[j][i])
				rte_free(lptr[j][i]);
		}
		if (comp_data[j])
			rte_free(comp_data[j]);
	}

	return 0;
}

static int
launch_one_lcore(__attribute__((unused)) void *dummy)
{
	perf_dma_test();
	return 0;
}
static inline int dma_test_inbound(int dma_port, int buf_size)
{
	uint8_t *fptr;
	union dpi_dma_ptr_u rptr = {0};
	union dpi_dma_ptr_u wptr = {0};
	struct rte_rawdev_buf *bufp[1];
	struct rte_rawdev_buf buf = {0};
	struct dpi_dma_buf_ptr_s cmd = {0};
	struct dpi_dma_req_compl_s *comp_data;
	struct dpi_dma_queue_ctx_s ctx = {0};
	void *d_buf[1];
	int ret;

	fptr = (uint8_t *)rte_malloc("dummy", buf_size, 128);
	comp_data = rte_malloc("dummy", buf_size, 128);
	if (!fptr) {
		printf("Unable to allocate internal memory\n");
		return -ENOMEM;
	}
	buffer_fill(fptr, buf_size, 0);
	memset(comp_data, 0, buf_size);
	rptr.s.ptr = (uint64_t)raddr;
	rptr.s.length = buf_size;
	wptr.s.ptr = (uint64_t)rte_malloc_virt2iova(fptr);
	wptr.s.length = buf_size;
	cmd.rptr[0] = &rptr;
	cmd.wptr[0] = &wptr;
	cmd.rptr_cnt = 1;
	cmd.wptr_cnt = 1;
	cmd.comp_ptr = comp_data;
	buf.buf_addr = (void *)&cmd;
	bufp[0] = &buf;

	ctx.xtype = DPI_XTYPE_INBOUND;
	ctx.pt = 0;
	ctx.pem_id = pem_id;
	ctx.c_ring = &cring[dma_port];

	ret = rte_rawdev_enqueue_buffers(dma_port,
					 (struct rte_rawdev_buf **)bufp, 1,
					 &ctx);
	if (ret < 0) {
		printf("Enqueue request failed\n");
		return 0;
	}

	/* Wait and dequeue completion */
	do {
		sleep(1);
		ret = rte_rawdev_dequeue_buffers(dma_port,
					 (struct rte_rawdev_buf **)&d_buf, 1,
					 &ctx);

		if (!ret) {
			printf("Dequeue request not completed\n");
		} else
			break;
		if (force_quit) {
//			dump_buffer(fptr, buf_size);
			goto free_buf;
		}
	} while (1);

free_buf:
	if (!ret)
		printf("Inbound DMA transfer failed or interrupted\n");
	else
		printf("Inbound DMA transfer successfully completed\n");
	dump_buffer(fptr, buf_size);

	if (fptr)
		rte_free(fptr);
	if (comp_data)
		rte_free(comp_data);

	return 0;
}

static inline int dma_test_internal(int dma_port, int buf_size)
{
	uint8_t *fptr, *lptr;
	union dpi_dma_ptr_u rptr = {0};
	union dpi_dma_ptr_u wptr = {0};
	struct rte_rawdev_buf *bufp[1];
	struct rte_rawdev_buf buf = {0};
	struct dpi_dma_buf_ptr_s cmd = {0};
	struct dpi_dma_req_compl_s *comp_data;
	struct dpi_dma_queue_ctx_s ctx = {0};
	void *d_buf[1];
	int ret;

	fptr = (uint8_t *)rte_malloc("dummy", buf_size, 128);
	lptr = (uint8_t *)rte_malloc("dummy", buf_size, 128);
	comp_data = rte_malloc("dummy", buf_size, 128);
	if (!fptr || !lptr) {
		printf("Unable to allocate internal memory\n");
		return -ENOMEM;
	}
	buffer_fill(fptr, buf_size, 0);
	memset(lptr, 0, buf_size);
	memset(comp_data, 0, buf_size);
	rptr.s.ptr = (uint64_t)rte_malloc_virt2iova(fptr);
	rptr.s.length = buf_size;
	wptr.s.ptr = (uint64_t)rte_malloc_virt2iova(lptr);
	wptr.s.length = buf_size;
	cmd.rptr[0] = &rptr;
	cmd.wptr[0] = &wptr;
	cmd.rptr_cnt = 1;
	cmd.wptr_cnt = 1;
	cmd.comp_ptr = comp_data;
	buf.buf_addr = (void *)&cmd;
	bufp[0] = &buf;

	ctx.xtype = DPI_XTYPE_INTERNAL_ONLY;
	ctx.pt = 0;
	ctx.c_ring = &cring[dma_port];

	ret = rte_rawdev_enqueue_buffers(dma_port,
					 (struct rte_rawdev_buf **)bufp, 1,
					 &ctx);
	if (ret < 0) {
		printf("Enqueue request failed\n");
		return 0;
	}

	/* Wait and dequeue completion */
	do {
		sleep(1);
		ret = rte_rawdev_dequeue_buffers(dma_port,
					 (struct rte_rawdev_buf **)&d_buf, 1,
					 &ctx);

		if (!ret) {
			printf("Dequeue request not completed\n");
		} else
			break;
		if (force_quit) {
			dump_buffer(fptr, buf_size);
			dump_buffer(lptr, buf_size);
			goto free_buf;
		}
	} while (1);

	if (validate_buffer(fptr, lptr, buf_size)) {
		printf("DMA transfer failed\n");
		return -1;
	} else
		printf("Internal Only DMA transfer successfully completed\n");

free_buf:
	if (lptr)
		rte_free(lptr);
	if (fptr)
		rte_free(fptr);
	if (comp_data)
		rte_free(comp_data);

	return 0;
}

static int fill_dpi_cmd(int dma_port, int ptr_sz, int xtype,
			struct dpi_dma_req_compl_s **comp_data,
			uint8_t **fptr, union dpi_dma_ptr_u *wptr,
			union dpi_dma_ptr_u *rptr,
			struct dpi_dma_buf_ptr_s *cmd,
			struct dpi_dma_queue_ctx_s *ctx)
{
	int i;

	*comp_data = rte_malloc("dummy", ptr_sz, 128);
	if (!*comp_data) {
		printf("Unable to allocate internal memory for comp data\n");
		return -ENOMEM;
	}
	memset(*comp_data, 0, ptr_sz);

	for (i = 0; i < ptrs_per_instr; i++) {
		fptr[i] = (uint8_t *)rte_malloc("dummy", ptr_sz, 128);
		if (!fptr[i]) {
			printf("Unable to allocate internal memory\n");
			return i;
		}
		buffer_fill(fptr[i], ptr_sz, 0);

		wptr[i].s.length = ptr_sz;
		wptr[i].s.ptr = (uint64_t)rte_malloc_virt2iova(fptr[i]);
		rptr[i].s.length = ptr_sz;
		rptr[i].s.ptr = (uint64_t)raddr + (i * ptr_sz);

		if (xtype == DPI_XTYPE_INBOUND) {
			cmd->wptr[i] = &wptr[i];
			cmd->rptr[i] = &rptr[i];
		} else {
			cmd->wptr[i] = &rptr[i];
			cmd->rptr[i] = &wptr[i];
		}
	}
	cmd->rptr_cnt = ptrs_per_instr;
	cmd->wptr_cnt = ptrs_per_instr;
	cmd->comp_ptr = *comp_data;

	ctx->xtype = xtype;
	ctx->pt = 0;
	ctx->pem_id = pem_id;
	ctx->c_ring = &cring[dma_port];

	return 0;
}

static inline void run_dpi_cmd(int dma_port, struct rte_rawdev_buf **bufp,
				 struct dpi_dma_queue_ctx_s *ctx)
{
	int ret;
	void *d_buf[1];

	ret = rte_rawdev_enqueue_buffers(dma_port,
					 (struct rte_rawdev_buf **)bufp,
					 1,
					 ctx);
	if (ret >= 0) {
		do {
			ret = rte_rawdev_dequeue_buffers(dma_port,
				(struct rte_rawdev_buf **)&d_buf, 1,
				ctx);
			if (ret)
				break;
		} while(!force_quit);
	}
}

static inline int dma_test_latency(int dma_port, int xtype)
{
	uint8_t *fptr[DPI_MAX_POINTER] = {0};
	union dpi_dma_ptr_u rptr[DPI_MAX_POINTER] = {0};
	union dpi_dma_ptr_u wptr[DPI_MAX_POINTER] = {0};
	struct dpi_dma_buf_ptr_s cmd = {0};
	struct rte_rawdev_buf buf = { &cmd };
	struct rte_rawdev_buf *bufp[1] = { &buf };
	struct dpi_dma_req_compl_s *comp_data = NULL;
	struct dpi_dma_queue_ctx_s ctx = {0};
	int i, b;
	int ptr_sz = data_size / ptrs_per_instr;
	uint64_t s_tsc, e_tsc = 0, latency = 0, bs_tsc, be_tsc;

	printf("\n%s latency.\n",
		(xtype == DPI_XTYPE_INBOUND) ? "Inbound" : "Outbound");

	i = fill_dpi_cmd(dma_port, ptr_sz, xtype, &comp_data,
			 fptr, wptr, rptr, &cmd, &ctx);
	if (i != 0)
		goto free_bufs;

	bs_tsc = rte_rdtsc();
	for (b = 0; b < n_iter; b++) {
		s_tsc = rte_rdtsc();
		run_dpi_cmd(dma_port, bufp, &ctx);
		e_tsc = rte_rdtsc();
		if (force_quit) {
			printf("Test abandoned.\n");
			goto free_bufs;
		}

		latency += (e_tsc - s_tsc);
	}
	be_tsc = rte_rdtsc();
	printf("Avg. burst: [%06ld cycles][%04ld usecs]\n"
		"Total     : [%06ld cycles][%04ld usecs]\n",
		latency / n_iter, ((latency / n_iter) * 1000000) / timer_period,
		be_tsc - bs_tsc, ((be_tsc - bs_tsc) * 1000000) / timer_period);

free_bufs:
	for (i = 0; i < ptrs_per_instr; i++) {
		if (fptr[i])
			rte_free(fptr[i]);
	}
	if (comp_data)
		rte_free(comp_data);

	return 0;
}

static inline int dma_test_roundtrip_latency(int dma_port, int xtype)
{
	uint8_t *fptr_in[DPI_MAX_POINTER] = {0};
	union dpi_dma_ptr_u rptr_in[DPI_MAX_POINTER] = {0};
	union dpi_dma_ptr_u wptr_in[DPI_MAX_POINTER] = {0};
	struct dpi_dma_buf_ptr_s cmd_in = {0};
	struct rte_rawdev_buf buf_in = { &cmd_in };
	struct rte_rawdev_buf *bufp_in[1] = { &buf_in };
	struct dpi_dma_req_compl_s *comp_data_in = NULL;
	struct dpi_dma_queue_ctx_s ctx_in = {0};
	uint8_t *fptr_out[DPI_MAX_POINTER] = {0};
	union dpi_dma_ptr_u rptr_out[DPI_MAX_POINTER] = {0};
	union dpi_dma_ptr_u wptr_out[DPI_MAX_POINTER] = {0};
	struct dpi_dma_buf_ptr_s cmd_out = {0};
	struct rte_rawdev_buf buf_out = { &cmd_out };
	struct rte_rawdev_buf *bufp_out[1] = { &buf_out };
	struct dpi_dma_req_compl_s *comp_data_out = NULL;
	struct dpi_dma_queue_ctx_s ctx_out = {0};
	int i, b;
	int ptr_sz = data_size / ptrs_per_instr;
	uint64_t s_tsc, e_tsc = 0, latency = 0, bs_tsc, be_tsc;

	printf("\n%s roundtrip latency.\n",
		(xtype == DPI_XTYPE_INBOUND) ? "Inbound" : "Outbound");

	i = fill_dpi_cmd(dma_port, ptr_sz, DPI_XTYPE_INBOUND,
			 &comp_data_in, fptr_in, wptr_in, rptr_in, &cmd_in,
			 &ctx_in);
	if (i != 0)
		goto free_bufs;

	i = fill_dpi_cmd(dma_port, ptr_sz, DPI_XTYPE_OUTBOUND,
			 &comp_data_out, fptr_out, wptr_out, rptr_out,
			 &cmd_out, &ctx_out);
	if (i != 0)
		goto free_bufs;

	if (xtype == DPI_XTYPE_INBOUND) {
		bs_tsc = rte_rdtsc();
		for (b = 0; b < n_iter; b++) {
			s_tsc = rte_rdtsc();
			run_dpi_cmd(dma_port, bufp_in, &ctx_in);
			run_dpi_cmd(dma_port, bufp_out, &ctx_out);
			e_tsc = rte_rdtsc();
			if (force_quit) {
				printf("Test abandoned.\n");
				goto free_bufs;
			}

			latency += (e_tsc - s_tsc);
		}
		be_tsc = rte_rdtsc();
	} else {
		bs_tsc = rte_rdtsc();
		for (b = 0; b < n_iter; b++) {
			s_tsc = rte_rdtsc();
			run_dpi_cmd(dma_port, bufp_out, &ctx_out);
			run_dpi_cmd(dma_port, bufp_in, &ctx_in);
			e_tsc = rte_rdtsc();
			if (force_quit) {
				printf("Test abandoned.\n");
				goto free_bufs;
			}

			latency += (e_tsc - s_tsc);
		}
		be_tsc = rte_rdtsc();
	}
	printf("Avg. burst: [%06ld cycles][%04ld usecs]\n"
		"Total     : [%06ld cycles][%04ld usecs]\n",
		latency / n_iter, ((latency / n_iter) * 1000000) / timer_period,
		be_tsc - bs_tsc, ((be_tsc - bs_tsc) * 1000000) / timer_period);

free_bufs:
	for (i = 0; i < ptrs_per_instr; i++) {
		if (fptr_in[i])
			rte_free(fptr_in[i]);
		if (fptr_out[i])
			rte_free(fptr_out[i]);
	}
	if (comp_data_in)
		rte_free(comp_data_in);
	if (comp_data_out)
		rte_free(comp_data_out);

	return 0;
}

static int dpi_create_mempool(void)
{
	char pool_name[25];
	unsigned int mp_flags = 0;
	const char *mempool_ops;
	int nb_chunks = (4 * 4096), ret;

	snprintf(pool_name, sizeof(pool_name), "dpi_chunk_pool");

	chunk_pool = (void *)rte_mempool_create_empty(pool_name, nb_chunks,
			DPI_CHUNK_SIZE, 0, 0, rte_socket_id(), mp_flags);

	if (!chunk_pool) {
		printf("Unable to create chunkpool.");
		return -ENOMEM;
	}
	printf("Mempool %p created successfully\n", chunk_pool);

	mempool_ops = rte_mbuf_best_mempool_ops();
	ret = rte_mempool_set_ops_byname(chunk_pool, mempool_ops, NULL);
	if (ret != 0) {
		printf("Unable to set chunkpool ops.");
		return -ENOMEM;
	}

	ret = rte_mempool_populate_default(chunk_pool);
	if (ret < 0) {
		printf("Unable to set populate chunkpool.");
		return -ENOMEM;
	}

	return 0;
}

static uint64_t dpi_parse_addr(const char *q_arg)
{
	char *end = NULL;
	uint64_t n;

	/* parse number string */
	n = strtoul(q_arg, &end, 0);
	if ((q_arg[0] == '\0') || (end == NULL) || (*end != '\0'))
		return 0;

	return n;
}

/* display usage */
static void dpi_usage(const char *prgname)
{
	printf("%s [EAL options] -- \n"
	       "  -r <remote address>: Remote pointer\n"
	       "  -l <first address>: This is also remote address valid for external only mode\n"
	       "  -m <mode>: Mode of transfer\n"
	       "             0: Internal Only\n"
               "             1: Inbound\n"
	       "             2: Outbound\n"
	       "             3: Dual - both inbound and outbound (supported only in perf test)\n"
               "             4: Inbound Latency\n"
	       "             5: Outbound Latency\n"
	       "             6: Inbound roundtrip Latency\n"
	       "             7: Outbound roundtrip Latency\n"
	       "             8: All modes 4, 5, 6, 7\n"
	       "		Max data size for latency tests :\n"
	       "			(65535*15) = 983025 bytes\n"
	       "  -i <iteration>: No.of iterations\n"
	       "  -s <data size>: Size of data to be DMA'ed (Default is 256)\n"
	       "  -b <pem number>: PEM connected to host\n"
	       "  -p: Performance test\n"
	       "  -t <num>: Number of pointers per instruction (Default is 1)\n"
	       "  --inb_sz <data size>: Size of Inbound data size in mode 3\n"
	       "  --outb_sz <data size>: Size of Outbound data size in mode 3\n",
       prgname);
}

/* Parse the argument given in the command line of the application */
static int dpi_parse_args(int argc, char **argv)
{
	int opt, ret, opt_idx;
	char **argvopt;
	char *prgname = argv[0];
	char *end;

	static struct option lgopts[] = {
		{ "inb_sz", 1, 0, 0},
		{ "outb_sz", 1, 0, 0},
		{0, 0, 0, 0 },
	};

	argvopt = argv;

	//while ((opt = getopt(argc, argvopt, "r:s:l:m:i:pb:t:")) != EOF) {
	while ((opt = getopt_long(argc, argvopt, "r:s:l:m:i:pb:t:",lgopts,
				  &opt_idx)) != EOF) {

		switch (opt) {
		/* portmask */
		case 'r':
			raddr = dpi_parse_addr(optarg);
			if ((long)raddr == 0) {
				printf("invalid remote address\n");
				dpi_usage(prgname);
				return -1;
			}
			printf("raddr: 0x%lx\n", raddr);
			break;
		case 's':
			data_size = dpi_parse_addr(optarg);
			if ((long)data_size == 0) {
				printf("invalid data Size\n");
				dpi_usage(prgname);
				return -1;
			}
			printf("data_size: 0x%lx\n", data_size);
			break;
		case 'l':
			laddr = dpi_parse_addr(optarg);
			if ((long)laddr < 0) {
				printf("invalid local address\n");
				dpi_usage(prgname);
				return -1;
			}
			break;
		case 'm':
			mode = atoi(optarg);
			printf("Mode: %d\n", mode);
			break;
		case 'i':
			n_iter = atoi(optarg);
			break;
		case 'b':
			pem_id = atoi(optarg);
			if (pem_id)
				pem_id = 1;
			break;
		case 'p':
			perf_mode = 1;
			break;
		case 't':
			ptrs_per_instr = atoi(optarg);
			printf("Pointers per instr: %d\n", ptrs_per_instr);
			if (ptrs_per_instr > DPI_MAX_POINTER) {
				printf("Max pointers can be only %d\n",
				       DPI_MAX_POINTER);
				return -1;
			}
			break;
		case 0: /* long options */
			if (!strcmp(lgopts[opt_idx].name, "inb_sz")) {
				printf("This option is not yet supported\n");
				return -1;
				inb_data_size = strtoul(optarg, &end, 0);
				printf("Inbound xfer size %ld\n",
				       inb_data_size);
			}
			if (!strcmp(lgopts[opt_idx].name, "outb_sz")) {
				printf("This option is not yet supported\n");
				return -1;
				outb_data_size = strtoul(optarg, &end, 0);
				printf("Outbound xfer size %ld\n",
				       outb_data_size);
			}
			break;
		default:
			dpi_usage(prgname);
			return -1;
		}
	}

	if (optind >= 0)
		argv[optind-1] = prgname;

	ret = optind-1;
	optind = 1; /* reset getopt lib */
	return ret;
}

int main(int argc, char **argv)
{
	int ret, i, size = 1024;
	struct rte_rawdev_info rdev_info = {0};
	struct dpi_rawdev_conf_s conf = {0};
	unsigned lcore_id;

	/* init EAL */
	ret = rte_eal_init(argc, argv);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Invalid EAL arguments\n");
	argc -= ret;
	argv += ret;

	force_quit = false;
	signal(SIGINT, signal_handler);
	signal(SIGTERM, signal_handler);

	/* parse application arguments (after the EAL ones) */
	ret = dpi_parse_args(argc, argv);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Invalid App arguments\n");

	/* Create FPA memory pool */
	dpi_create_mempool();

	nb_ports = rte_rawdev_count();
	if (nb_ports == 0)
		rte_exit(EXIT_FAILURE, "No Rawdev orts - bye\n");

	/* convert to number of cycles */
	timer_period *= rte_get_timer_hz();

	printf("%d rawdev ports detected\n", nb_ports);
	/* Configure rawdev ports */
	for (i = 0; i < nb_ports; i++) {
		conf.chunk_pool = chunk_pool;
		rdev_info.dev_private = &conf;
		ret = rte_rawdev_configure(i, (rte_rawdev_obj_t)&rdev_info);
		if (ret)
			rte_exit(EXIT_FAILURE, "Unable to configure DPIVF %d\n",
				 i);
		printf("rawdev %d configured successfully\n", i);
		cring[i].compl_data = rte_malloc("dummy",
				 (sizeof(void *) * DPI_MAX_COMP_ENTRIES), 128);
		if (!cring[i].compl_data)
			rte_exit(EXIT_FAILURE, "Completion alloc failed\n");
		cring[i].max_cnt = DPI_MAX_COMP_ENTRIES;
		cring[i].head = 0;
		cring[i].tail = 0;
	}

	if (!perf_mode) {
		if (mode >= 4 && mode <= 8) {
			ptrs_per_instr = data_size / DPI_MAX_DATA_SZ_PER_PTR;
			if (data_size % DPI_MAX_DATA_SZ_PER_PTR)
				ptrs_per_instr++;
			if (ptrs_per_instr > DPI_MAX_POINTER) {
				printf("Data too big.\n"
					"Max data size: (%d bytes/ptr * "
					"%d ptrs) = %d bytes\n",
					DPI_MAX_DATA_SZ_PER_PTR,
					DPI_MAX_POINTER,
					DPI_MAX_DATA_SZ_PER_PTR *
					DPI_MAX_POINTER);
				goto close_devs;
			}

			printf("\nData size: %ld, bursts: %d, "
				"ptrs/burst: %d, sz/ptr: %ld\n",
				data_size, n_iter, ptrs_per_instr,
				data_size / ptrs_per_instr);

			for (i = 0; i < nb_ports; i++) {
				printf("\nPort %d\n", i);
				if (mode == 4)
					dma_test_latency(i, DPI_XTYPE_INBOUND);
				else if (mode == 5)
					dma_test_latency(i, DPI_XTYPE_OUTBOUND);
				else if (mode == 6)
					dma_test_roundtrip_latency(i,
							DPI_XTYPE_INBOUND);
				else if (mode == 7)
					dma_test_roundtrip_latency(i,
							DPI_XTYPE_OUTBOUND);
				else {
					dma_test_latency(i, DPI_XTYPE_INBOUND);
					dma_test_roundtrip_latency(i,
							DPI_XTYPE_INBOUND);
					dma_test_latency(i, DPI_XTYPE_OUTBOUND);
					dma_test_roundtrip_latency(i,
							DPI_XTYPE_OUTBOUND);
				}
				if (force_quit)
					break;
			}
			goto close_devs;
		}
		for (i = 0; i < nb_ports; i++) {
			int j;

			for (j = 0; j < n_iter; j++) {
				if (mode == 1)
					ret = dma_test_inbound(i, size);
				else if (mode == 2)
					ret = dma_test_outbound(i, size);
				else if (mode == 3) {
					printf("Dual mode is only supported in perf test\n");
					return 0;
				} else
					ret = dma_test_internal(i, size);
				if (ret) {
					printf("DMA transfer (mode: %d) "
						"failed for queue %d\n",
						mode, i);
					return 0;
				}
			}
			break;
		}
	}
	if (perf_mode) {
		/* launch per-lcore init on every lcore */
		rte_eal_mp_remote_launch(launch_one_lcore, NULL, CALL_MASTER);
		RTE_LCORE_FOREACH_SLAVE(lcore_id) {
			if (rte_eal_wait_lcore(lcore_id) < 0) {
				ret = -1;
				break;
			}
		}
	}

close_devs:
	for (i = 0; i < nb_ports; i++) {
		if (rte_rawdev_close(i))
			printf("Dev close failed for port %d\n", i);
	}
	if (chunk_pool)
		rte_mempool_free(chunk_pool);
	printf("Bye...\n");

	return ret;
}
