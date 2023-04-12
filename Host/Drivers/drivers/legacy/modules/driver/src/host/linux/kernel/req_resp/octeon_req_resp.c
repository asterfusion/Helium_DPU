/*
 *
 * CNNIC SDK
 *
 * Copyright (c) 2018 Cavium Networks. All rights reserved.
 *
 * This file, which is part of the CNNIC SDK which also includes the
 * CNNIC SDK Package from Cavium Networks, contains proprietary and
 * confidential information of Cavium Networks and in some cases its
 * suppliers. 
 *
 * Any licensed reproduction, distribution, modification, or other use of
 * this file or the confidential information or patented inventions
 * embodied in this file is subject to your license agreement with Cavium
 * Networks. Unless you and Cavium Networks have agreed otherwise in
 * writing, the applicable license terms "OCTEON SDK License Type 5" can be
 * found under the directory: $CNNIC_ROOT/licenses/
 *
 * All other use and disclosure is prohibited.
 *
 * Contact Cavium Networks at info@caviumnetworks.com for more information.
 *
 */

#include "cavium_sysdep.h"
#include "cavium_defs.h"
#include "cavium_release.h"
#include "octeon-opcodes.h"
#include "octeon_hw.h"
#include "linux/seq_file.h"

MODULE_AUTHOR("Cavium Networks");
MODULE_LICENSE("Cavium Networks");

/* #define  DEBUG_MODE_ON */
/* #define  REQUEST_PROFILE */

/*-------- Defaults --------------*/

/* Default octeon device id. */
#define OCTEON_ID              0

/* Default number of threads to create. */
#define NO_OF_THREADS          1

/* Default number of requests to submit to driver before the test thread relinquishes
   the CPU. */
#define PKT_BURST              10000

/* Default Input Queue number. */
#define TEST_IQ_NO             0

#define CREATE_ONCE

#define  MAX_THREADS           4

/* Time (in jiffies) the test thread waits between packet bursts. */
#define TIME_BETWEEN_BURSTS    1

/* Enable this definition to add signature data to input buffers which gets
   verified from the output buffers on response. The core application is
   responsible for copying the input buffer contents to the output buffers.
*/
#define VERIFY_DATA            1

/* Maximum number of input buffers. All requests will have MAX_INBUFS input
   buffers. This value should not exceed 15.
*/
#define MAX_INBUFS             1

/* Default Size of each input buffer.
   Input size should not exceed 16359 bytes for DMA_DIRECT and
   65511 for DMA_GATHER.
*/
#define INBUF_SIZE             1024

/* Maximum number of output buffers. All requests will have MAX_OUTBUFS output
   buffers. This value should not exceed 13.
*/
#define MAX_OUTBUFS            1

/* Size of each output buffer. Includes 16 bytes reserved for response header
   and status bytes.
   Choose values such that (outbuf_size * MAX_OUTBUFS) does not exceed
   16383 bytes for DIRECT and 122760 bytes for DMA_SCATTER.
 */
#define OUTBUF_SIZE            1024

/* DMA mode to use for requests. Pick one of
   OCTEON_DMA_DIRECT; OCTEON_DMA_GATHER; OCTEON_DMA_SCATTER;
   OCTEON_DMA_SCATTER_GATHER.

*/
#define  OCTEON_TEST_DMA_MODE     OCTEON_DMA_DIRECT

/* Response order to use for requests. Pick one of
   OCTEON_RESP_NORESPONSE; OCTEON_RESP_ORDERED; OCTEON_RESP_UNORDERED;
*/
#define  OCTEON_TEST_RESP_ORDER  OCTEON_RESP_NORESPONSE	// OCTEON_RESP_ORDERED

/* Response mode to use for requests. Pick one of
   OCTEON_RESP_NON_BLOCKING; OCTEON_RESP_BLOCKING;
*/
#define OCTEON_TEST_RESP_MODE    OCTEON_RESP_NON_BLOCKING

/* NOTE:
     Do not set response order/response mode to
     OCTEON_RESP_UNORDERED/OCTEON_RESP_NON_BLOCKING. For UNORDERED requests,
     the driver expects the caller to query for completion. This application
     does not send queries for UNORDERED/NON_BLOCKING requests. It does
     send queries for UNORDERED/BLOCKING requests. UNORDERED/NON_BLOCKING
     requests are not recommended for kernel-mode applications.
*/

/* Request Timeout value. Keep this high (in seconds) if any sort of prints
   are enabled in the core application.
*/
#define OCTEON_TEST_REQ_TIMEOUT   600

#define  BUFFER_ALIGNMENT

#define  DISPLAY_INTERVAL   (10 * HZ)

#ifdef DEBUG_MODE_ON
#define CVM_DBG(format, ...)   printk(format, ## __VA_ARGS__);
#else
#define CVM_DBG(format, ...)   do{}while(0);
#endif

int inbuf_size = INBUF_SIZE;
module_param(inbuf_size, int, 0);

int outbuf_size = OUTBUF_SIZE;
module_param(outbuf_size, int, 0);

int inbuf_cnt = MAX_INBUFS;
module_param(inbuf_cnt, int, 0);

int outbuf_cnt = MAX_OUTBUFS;
module_param(outbuf_cnt, int, 0);

int pkt_burst = PKT_BURST;
module_param(pkt_burst, int, 0);

int oct_id = OCTEON_ID;
module_param(oct_id, int, 0);

int num_threads = NO_OF_THREADS;
module_param(num_threads, int, 0);

char *dma = 0ULL;
module_param(dma, charp, 0);

char *resporder = 0ULL;
module_param(resporder, charp, 0);

char *respmode = 0ULL;
module_param(respmode, charp, 0);

int iq_no = TEST_IQ_NO;
module_param(iq_no, int, 0);

struct test_stats {

	/* Thread index */
	int idx;

	/* Store the pid's here. cleanup_module needs them */
/* For KERNEL_VERSION < 2,6,18, we store the pid here and the kthread task ptr
	for later releases. */
	unsigned long pid;

#ifdef REQUEST_PROFILE
	unsigned long long max_req_time;
	unsigned long long min_req_time;
	unsigned long long avg_req_time;
	unsigned long long total_req_time;
	unsigned long last_display_tick;
	unsigned long last_request_count;
#endif

	/* Requests for which we have received acknowledgement from driver. */
	cavium_atomic_t callback_received;

	/* Requests sent successfully to Octeon driver */
	cavium_atomic_t req_posted;

	uint64_t inner_loop_cnt;
	uint64_t outer_loop_cnt;
	uint64_t post_failed;
	uint64_t no_pkt_to_send;

	/* Total data bytes received */
	uint64_t total_bytes_received;

	/* Total data bytes sent */
	uint64_t total_bytes_sent;

	/* Frequency of requests sent with different input buffer counts */
	unsigned long incntfreq[MAX_BUFCNT + 1];

	/* Frequency of requests sent with different output buffer counts */
	unsigned long outcntfreq[MAX_BUFCNT + 1];

	/* The maximum size of input data that was sent in the test. */
	unsigned long maxdatasent;

	/* Requests that have passed verification. */
	unsigned long verify_passed;

	/* Requests that have failed verification. */
	unsigned long verify_failed;

	/* Requests that returned with errors */
	unsigned long req_status_errors;

	/* Requests that could not be posted. */
	unsigned long req_post_errors;

	unsigned long continuous_failures;
};

struct test_packet {
	struct test_stats *s;
	void *inbuf[MAX_BUFCNT];
	void *outbuf[MAX_BUFCNT];
	octeon_soft_request_t *sr;
#ifdef REQUEST_PROFILE
	unsigned long long r_start, r_end;
#endif
#ifdef CREATE_ONCE
	int in_use;
#endif
};

#define  MAX_CONTINUOUS_FAILURES  32

int dma_mode = OCTEON_TEST_DMA_MODE;
int resp_mode = OCTEON_TEST_RESP_MODE;
int resp_order = OCTEON_TEST_RESP_ORDER;
int thread_count = 0, test_ok_to_run = 0;
atomic_t test_exit;
struct test_stats tstats[MAX_THREADS];
struct proc_dir_entry *proc1;

int verify_output(octeon_soft_request_t * soft_req, int vcount);

uint64_t last_reqs_posted = 0, last_tot_callbacks = 0, last_post_failed = 0;
uint64_t last_out_loop_cnt = 0, last_in_loop_cnt = 0, last_no_pkt_to_send = 0;

unsigned long last_jiffies;

static int set_args(void)
{
	if (dma) {
		if (!strcmp(dma, "direct")) {
			dma_mode = OCTEON_DMA_DIRECT;
		} else if (!strcmp(dma, "gather")) {
			dma_mode = OCTEON_DMA_GATHER;
		} else if (!strcmp(dma, "scatter_gather")) {
			dma_mode = OCTEON_DMA_SCATTER_GATHER;
		} else if (!strcmp(dma, "scatter")) {
			dma_mode = OCTEON_DMA_SCATTER;
		} else {
			cavium_error("Invalid Option %s\n", dma);
			return 1;
		}
	}
	if (resporder) {
		if (!strcmp(resporder, "ordered")) {
			resp_order = OCTEON_RESP_ORDERED;
		} else if (!strcmp(resporder, "unordered")) {
			resp_order = OCTEON_RESP_UNORDERED;
		} else if (!strcmp(resporder, "noresponse")) {
			resp_order = OCTEON_RESP_NORESPONSE;
		} else {
			cavium_error("Invalid Option %s\n", resporder);
			return 1;
		}
	}
	if (respmode) {
		if (!strcmp(respmode, "blocking")) {
			resp_mode = OCTEON_RESP_BLOCKING;
		} else if (!strcmp(respmode, "nonblocking")) {
			resp_mode = OCTEON_RESP_NON_BLOCKING;
		} else {
			cavium_error("Invalid Option %s\n", respmode);
			return 1;
		}
	}
	return 0;
}

static void print_reqrespstats(struct seq_file *seqfile,
			       octeon_device_t * oct_dev)
{
	int i;
	uint64_t reqs_posted = 0, callbacks = 0, post_failed = 0;
	uint64_t outer_loop_cnt = 0, inner_loop_cnt = 0, no_pkt_to_send = 0;
	struct test_stats *s;

	CVM_MOD_INC_USE_COUNT;

	for (i = 0; i < num_threads; i++) {
		s = &tstats[i];
		seq_printf(seqfile,
			   "Thread[%d] Packets: %u Callbacks: %u Post Failed: %llu  Loop Count Outer: %llu Inner: %llu NoPktToSend: %llu\n",
			   i, cavium_atomic_read(&s->req_posted),
			   cavium_atomic_read(&s->callback_received),
			   s->post_failed, s->outer_loop_cnt, s->inner_loop_cnt,
			   s->no_pkt_to_send);

		reqs_posted += cavium_atomic_read(&s->req_posted);
		callbacks += cavium_atomic_read(&s->callback_received);
		post_failed += s->post_failed;
		outer_loop_cnt += s->outer_loop_cnt;
		inner_loop_cnt += s->inner_loop_cnt;
		no_pkt_to_send += s->no_pkt_to_send;
	}

	seq_printf(seqfile,
		   "\nTotal Packets: %llu Callbacks: %llu Post Failed: %llu Loop count outer: %llu inner: %llu NoPktToSend: %llu\n ",
		   reqs_posted, callbacks, post_failed, outer_loop_cnt,
		   inner_loop_cnt, no_pkt_to_send);

	seq_printf(seqfile,
		   "\nLast Packets: %llu Callbacks: %llu Post Failed: %llu Loop count outer: %llu inner: %llu NoPktToSend: %llu jiffies: %lu\n ",
		   reqs_posted - last_reqs_posted,
		   callbacks - last_tot_callbacks,
		   post_failed - last_post_failed,
		   outer_loop_cnt - last_out_loop_cnt,
		   inner_loop_cnt - last_in_loop_cnt,
		   no_pkt_to_send - last_no_pkt_to_send,
		   jiffies - last_jiffies);

	last_jiffies = jiffies;
	last_reqs_posted = reqs_posted;
	last_tot_callbacks = callbacks;
	last_post_failed = post_failed;
	last_out_loop_cnt = outer_loop_cnt;
	last_in_loop_cnt = inner_loop_cnt;
	last_no_pkt_to_send = no_pkt_to_send;

	CVM_MOD_DEC_USE_COUNT;
	return;
}

static void *reqresp_seq_start(struct seq_file *seqfile, loff_t * pos)
{
	if (*pos == 0)
		return SEQ_START_TOKEN;
	else
		return NULL;
}

static void *reqresp_seq_next(struct seq_file *seqfile, void *v, loff_t * pos)
{
	return NULL;
}

static void reqresp_seq_stop(struct seq_file *seqfile, void *v)
{
	return;
}

static int reqresp_seq_show(struct seq_file *seqfile, void *v)
{
	octeon_device_t *oct = (octeon_device_t *) seqfile->private;
	print_reqrespstats(seqfile, oct);
	return 0;
}

static struct seq_operations reqresp_seq_ops = {
	.start = reqresp_seq_start,
	.next = reqresp_seq_next,
	.stop = reqresp_seq_stop,
	.show = reqresp_seq_show
};

static int reqresp_proc_open(struct inode *inode, struct file *file)
{
	int ret = seq_open(file, &reqresp_seq_ops);
	if (!ret) {
		struct seq_file *seqfile = file->private_data;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,10,0)
		seqfile->private = PDE_DATA(file_inode(file));
#else
		struct proc_dir_entry *proc = PDE(inode);
		seqfile->private = proc->data;
#endif
	}
	return ret;
}

static struct file_operations reqresp_proc_ops = {
	.owner = THIS_MODULE,
	.open = reqresp_proc_open,
	.read = seq_read,
};

#if defined(CREATE_ONCE)
#define  MAX_PKTS      8192
struct test_packet *glbl_tp[MAX_THREADS][MAX_PKTS];
int pkt_idx[MAX_THREADS];

struct test_packet *get_test_pkt(int tidx)
{
	struct test_packet *tpkt;

	CVM_DBG("%s idx: %d  tp: %p\n", __FUNCTION__, pkt_idx[tidx],
		glbl_tp[tidx][pkt_idx[tidx]]);

	if (glbl_tp[tidx][pkt_idx[tidx]] == NULL)
		return NULL;

	tpkt = glbl_tp[tidx][pkt_idx[tidx]];
	pkt_idx[tidx]++;
	if (pkt_idx[tidx] == MAX_PKTS)
		pkt_idx[tidx] = 0;

	return tpkt;
}

void set_test_pkt(int tidx, struct test_packet *tpkt)
{
	if (glbl_tp[tidx][pkt_idx[tidx]] == NULL) {
		glbl_tp[tidx][pkt_idx[tidx]] = tpkt;
		CVM_DBG("%s idx: %d  tp: %p\n", __FUNCTION__, pkt_idx[tidx],
			glbl_tp[tidx][pkt_idx[tidx]]);
		pkt_idx[tidx]++;
		if (pkt_idx[tidx] == MAX_PKTS)
			pkt_idx[tidx] = 0;
	} else {
		printk
		    ("Attempt to insert tpkt (0x%p) in slot %d used by 0x%p\n",
		     tpkt, pkt_idx[tidx], glbl_tp[tidx][pkt_idx[tidx]]);
	}
}

#endif

void print_test_setup(void)
{
	cavium_print_msg("      Test for Octeon %d\n", oct_id);
	cavium_print_msg("--------------------------- \n");
	cavium_print_msg("Response Order : %s\n",
			 OCTEON_RESP_ORDER_STRING(resp_order));
	cavium_print_msg("Response Mode  : %s\n",
			 OCTEON_RESP_MODE_STRING(resp_mode));
	cavium_print_msg("DMA Mode       : %s\n",
			 OCTEON_DMA_MODE_STRING(dma_mode));

	cavium_print_msg("Max input bufs = %d Max Output bufs = %d\n",
			 inbuf_cnt, outbuf_cnt);
	cavium_print_msg("Inbuf size     : %d Outbuf size     : %d\n",
			 inbuf_size, outbuf_size);
	cavium_print_msg("--------------------------- \n");
}

static inline uint32_t get_verify_size(octeon_soft_request_t * soft_req)
{
	uint32_t insize = (soft_req->inbuf.cnt * inbuf_size);
	uint32_t outsize = (soft_req->outbuf.cnt * outbuf_size);
	uint32_t versize;
	/* deducting the response header & status bytes length */
	outsize -= 16;
	versize = ((insize > outsize) ? outsize : insize);
	CVM_DBG
	    ("get_ver_size: insize: %d outsize: %d Verify %d bytes of data\n",
	     insize, outsize, versize);
	return versize;
}

void oct_test_print_data(uint8_t * data, uint32_t size)
{
	int i;

	cavium_print_msg("OCTEON_TEST: Printing %d bytes @ %p\n", size, data);
	for (i = 0; i < size; i++) {
		if (!(i & 0x7))
			cavium_print_msg("\n");
		cavium_print_msg(" %02x", data[i]);
	}
	cavium_print_msg("\n");
}

static inline void free_test_packet(struct test_packet *tp)
{
	int i;
	if (tp->sr) {
		for (i = 0; i < tp->sr->inbuf.cnt; i++) {
			if (tp->inbuf[i])
				kfree(tp->inbuf[i]);
		}

		for (i = 0; i < tp->sr->outbuf.cnt; i++) {
			if (tp->outbuf[i])
				kfree(tp->outbuf[i]);
		}
		kfree(tp);
	}
}

void request_comp_callback(octeon_req_status_t status, void *arg)
{
	struct test_packet *tp = (struct test_packet *)arg;
	octeon_soft_request_t *soft_req;
	struct test_stats *s;
	int i;

	soft_req = tp->sr;
	s = tp->s;

	cavium_atomic_inc(&s->callback_received);

#ifdef REQUEST_PROFILE
	{
		unsigned long long r_diff;
		rdtscll(tp->r_end);
		r_diff = tp->r_end - tp->r_start;
		if (r_diff > s->max_req_time)
			s->max_req_time = r_diff;
		if (r_diff < s->min_req_time)
			s->min_req_time = r_diff;
		s->total_req_time += r_diff;
	}
#endif

	if (!status) {
#ifdef VERIFY_DATA
		if (resp_order != OCTEON_RESP_NORESPONSE) {
			if (verify_output(soft_req, get_verify_size(soft_req)))
				s->verify_failed++;
			else
				s->verify_passed++;
		}
#endif
	} else {
		cavium_error("OCTEON_TEST: Request status in callback: %x\n",
			     status);
		s->req_status_errors++;
	}

	for (i = 0; i < soft_req->inbuf.cnt; i++)
		s->total_bytes_sent += soft_req->inbuf.size[i];

	/* Add the output size to total_bytes_received only if the status
	   is OK.
	 */
	if (!status && (resp_order != OCTEON_RESP_NORESPONSE)) {
		for (i = 0; i < soft_req->outbuf.cnt; i++)
			s->total_bytes_received += soft_req->outbuf.size[i];
	}
#if !defined(CREATE_ONCE)
	free_test_packet(tp);
#else
	tp->in_use = 0;
#endif

}

int send_test_packet(struct test_stats *s, struct test_packet *tp)
{
	octeon_instr_status_t retval;
	octeon_query_request_t query;
	octeon_request_info_t req_info;
	octeon_soft_request_t *soft_req;
	uint64_t status = 0;

#ifdef REQUEST_PROFILE
	rdtscll(tp->r_start);
#endif

	soft_req = tp->sr;

	memcpy(&req_info, SOFT_REQ_INFO(soft_req), OCT_REQ_INFO_SIZE);
	retval = octeon_process_request(oct_id, soft_req);

	/* There is a good chance that the request callback would be called
	   before the octeon_process_request() call returns. We free the
	   soft_req structure in the callback. So copy the req_info before we
	   make the call to octeon_process_request().
	 */

	status = retval.s.status;

	if (!retval.s.error) {

		cavium_atomic_inc(&s->req_posted);

		if ((req_info.req_mask.resp_order == OCTEON_RESP_UNORDERED)
		    && (req_info.req_mask.resp_mode == OCTEON_RESP_BLOCKING)) {

			query.octeon_id = req_info.octeon_id;
			query.request_id = retval.s.request_id;

			do {
				if (octeon_query_request_status
				    (query.octeon_id, &query)
				    && query.status != OCTEON_REQUEST_PENDING) {
					break;
				}
				cavium_schedule();
			} while (query.status == OCTEON_REQUEST_PENDING);

			status = query.status;

		} else {
			/* For non-blocking calls return with status 0 if the
			   request did not fail. */
			status = 0;
		}
	} else {
		switch (status) {

		case OCTEON_REQUEST_NO_IQ_SPACE:
			cavium_print(PRINT_DEBUG, "No Space in IQ \n");
			break;
		case 40:	/* NO SPACE IN PENDING LIST */
			cavium_print(PRINT_DEBUG,
				     "No space in pending list \n");
			break;
		default:
			cavium_error("Unknown Status: %llx \n", status);

		}
		cavium_timeout(1);
	}

#ifdef CREATE_ONCE
	if ((resp_order == OCTEON_RESP_UNORDERED) &&
	    (resp_mode == OCTEON_RESP_BLOCKING))
		tp->in_use = 0;
	else
		tp->in_use = !status;
#endif

	return status;
}

struct test_packet *create_test_packet(int tidx, struct test_stats *s)
{
	int i, counter = cavium_atomic_read(&s->req_posted);
	struct test_packet *tp;
	octeon_soft_request_t *soft_req;
	octeon_request_info_t *req_info;

#if defined(CREATE_ONCE)
	tp = get_test_pkt(tidx);
	if (tp) {
		if (tp->in_use)
			return NULL;
		return tp;
	}
#endif

	tp = kmalloc(sizeof(struct test_packet) + OCT_SOFT_REQUEST_SIZE +
		     OCT_REQ_INFO_SIZE, GFP_KERNEL);
	if (!tp) {
		cavium_error("OCTEON_TEST: %s:%d Alloc failed\n",
			     __FUNCTION__, __LINE__);
		return NULL;
	}
	memset(tp, 0,
	       sizeof(struct test_packet) + OCT_SOFT_REQUEST_SIZE +
	       OCT_REQ_INFO_SIZE);

	tp->sr =
	    (octeon_soft_request_t *) ((uint8_t *) tp +
				       sizeof(struct test_packet));
	soft_req = tp->sr;

	req_info =
	    (octeon_request_info_t *) ((uint8_t *) soft_req +
				       sizeof(octeon_soft_request_t));
	SOFT_REQ_INFO(soft_req) = req_info;

	soft_req->ih.raw = 1;
	soft_req->ih.tag = 0x10101010 + counter;
	soft_req->ih.tagtype = 0x1;
	soft_req->irh.opcode = CVMCS_REQRESP_OP;
	soft_req->irh.param = 0x10;
	soft_req->irh.dport = 32;

	for (i = 0; i < inbuf_cnt; i++) {
		int j;
		tp->inbuf[i] = kmalloc(inbuf_size + 8, GFP_KERNEL);
		SOFT_REQ_INBUF(soft_req, i) = tp->inbuf[i];
		if (!SOFT_REQ_INBUF(soft_req, i)) {
			cavium_error("OCTEON_TEST: %s:%d Alloc failed\n",
				     __FUNCTION__, __LINE__);
			free_test_packet(tp);
			return NULL;
		}
#ifdef BUFFER_ALIGNMENT
		SOFT_REQ_INBUF(soft_req, i) += (cavium_jiffies & 7);
#endif
		soft_req->inbuf.size[i] = inbuf_size;
#ifdef VERIFY_DATA
		for (j = 0; j < inbuf_size; j++) {
			SOFT_REQ_INBUF(soft_req, i)[j] =
			    ((j & 0xff) == 0) ? 1 : j;
		}
#endif
		soft_req->inbuf.cnt++;
	}

	if ((dma_mode == OCTEON_DMA_GATHER)
	    || (dma_mode == OCTEON_DMA_SCATTER_GATHER))
		soft_req->ih.dlengsz = inbuf_cnt;
	else
		soft_req->ih.dlengsz = (inbuf_cnt * inbuf_size);

	if (resp_order != OCTEON_RESP_NORESPONSE) {
		for (i = 0; i < outbuf_cnt; i++) {
			if (outbuf_cnt == 1) {
				/* If outbuf_cnt=1, add space for ORH and status to it */
				tp->outbuf[i] =
				    kmalloc(outbuf_size + 8 + 16, GFP_KERNEL);
				soft_req->outbuf.size[i] = outbuf_size + 16;
			} else if (i == 0 || i == (outbuf_cnt - 1)) {
				/* If outbuf_cnt>1, add space for ORH to first buffer 
				 * and for status to last buffer */
				tp->outbuf[i] =
				    kmalloc(outbuf_size + 8 + 8, GFP_KERNEL);
				soft_req->outbuf.size[i] = outbuf_size + 8;
			} else {
				tp->outbuf[i] =
				    kmalloc(outbuf_size + 8, GFP_KERNEL);
				soft_req->outbuf.size[i] = outbuf_size;
			}
			SOFT_REQ_OUTBUF(soft_req, i) = tp->outbuf[i];
			if (!SOFT_REQ_OUTBUF(soft_req, i)) {
				cavium_error
				    ("OCTEON_TEST: %s:%d Alloc failed\n",
				     __FUNCTION__, __LINE__);
				free_test_packet(tp);
				return NULL;
			}
#ifdef BUFFER_ALIGNMENT
			SOFT_REQ_OUTBUF(soft_req, i) += (cavium_jiffies & 7);
#endif

			soft_req->outbuf.cnt++;
		}
		if ((dma_mode == OCTEON_DMA_SCATTER)
		    || (dma_mode == OCTEON_DMA_SCATTER_GATHER))
			soft_req->irh.rlenssz = outbuf_cnt;
		else {
			/* Adding 16 bytes extra for direct and gather cases, 
			   for scatter/scatter_gather it's already added above */
			soft_req->irh.rlenssz = (outbuf_cnt * outbuf_size) + 16;
		}
	}

	req_info->octeon_id = oct_id;
	req_info->callback = request_comp_callback;
	req_info->callback_arg = tp;
	req_info->request_id = 0xff;
	req_info->req_mask.dma_mode = dma_mode;
	req_info->req_mask.resp_mode = resp_mode;
	req_info->req_mask.resp_order = resp_order;
	req_info->timeout = OCTEON_TEST_REQ_TIMEOUT;

	SET_REQ_INFO_IQ_NO(req_info, iq_no);
//      SET_REQ_INFO_IQ_NO(req_info, tidx);

#if defined(CREATE_ONCE)
	set_test_pkt(tidx, tp);
#endif
	return tp;
}

/* soft_req - Request structure with input and output buffers.
   vcount   - number of bytes to verify.
*/
int verify_output(octeon_soft_request_t * soft_req, int vcount)
{
	uint32_t total_bytes = 0, in_idx = 0, out_idx = 0, i;
	uint32_t check_bytes = 0, in_bytes = 0, out_bytes = 0;
	uint8_t *inptr = SOFT_REQ_INBUF(soft_req, 0);
	uint8_t *outptr = SOFT_REQ_OUTBUF(soft_req, 0);
	int icntr = -1, ocntr = -1;

	CVM_DBG("Verifying %d bytes\n", vcount);
	CVM_DBG("Input ptrs are : \n");
	for (i = 0; i < soft_req->inbuf.cnt; i++)
		CVM_DBG("iptr[%d]: %p\n", i, SOFT_REQ_INBUF(soft_req, i));
	CVM_DBG("Output ptrs are : \n");
	for (i = 0; i < soft_req->outbuf.cnt; i++)
		CVM_DBG("optr[%d]: %p\n", i, SOFT_REQ_OUTBUF(soft_req, i));

	while (total_bytes < vcount) {
		if (out_bytes == 0) {
			if (out_idx < soft_req->outbuf.cnt) {
				ocntr++;
				out_bytes = soft_req->outbuf.size[out_idx];
				outptr = SOFT_REQ_OUTBUF(soft_req, out_idx);
				if (out_idx == 0) {
					outptr += 8;
					out_bytes -= 8;
				}
				out_idx++;
			} else
				goto verify_error;
		}

		/* For each input buffer. */
		if (in_bytes == 0) {
			if (in_idx < soft_req->inbuf.cnt) {
				icntr++;
				in_bytes = soft_req->inbuf.size[in_idx];
				inptr = SOFT_REQ_INBUF(soft_req, in_idx);
				in_idx++;
			} else
				goto verify_error;
		}
		check_bytes = (in_bytes < out_bytes) ? in_bytes : out_bytes;
		if (check_bytes > (vcount - total_bytes))
			check_bytes = vcount - total_bytes;
		CVM_DBG("inptr: %p outptr: %p verify %d bytes\n", inptr, outptr,
			check_bytes);
		if (memcmp(inptr, outptr, check_bytes))
			goto verify_error;
		in_bytes -= check_bytes;
		out_bytes -= check_bytes;
		inptr += check_bytes;
		outptr += check_bytes;
		total_bytes += check_bytes;
	}
	return 0;

verify_error:
	cavium_error("Verification mismatch at inbuf[%d], outbuf[%d]\n",
		     icntr, ocntr);
#ifdef DEBUG_MODE_ON
	CVM_DBG("%d bytes of Input buffer no. %d starting at %p\n",
		check_bytes, icntr, inptr);
	cavium_error_print(inptr, in_bytes);
	CVM_DBG("%d bytes of Output buffer no. %d starting at %p\n",
		check_bytes, ocntr, outptr);
	cavium_error_print(outptr, out_bytes);
	if ((ocntr + 1) != soft_req->outbuf.cnt) {
		for (i = ocntr + 1; i < soft_req->outbuf.cnt; i++) {
			CVM_DBG
			    ("Outbuf %d was not printed. Printing it now..\n",
			     i);
			cavium_error_print(SOFT_REQ_OUTBUF(soft_req, i),
					   soft_req->outbuf.size[i]);
		}
	}
#endif
	return 1;
}

void print_test_stats(struct test_stats *s)
{
	int i;

	cavium_print_msg("Thread 0x%lx: %d successful requests (%d failures)\n",
			 s->pid, cavium_atomic_read(&s->callback_received),
			 (cavium_atomic_read(&s->req_posted) -
			  cavium_atomic_read(&s->callback_received)));

	if (s->req_post_errors) {
		cavium_print_msg
		    ("Thread 0x%lx: ## %lu requests were not posted ##\n",
		     s->pid, s->req_post_errors);
	}

	if (s->req_status_errors) {
		cavium_print_msg
		    ("Thread 0x%lx: ## Driver reported %lu errors ##\n", s->pid,
		     s->req_status_errors);
	}

	cavium_print_msg("Thread 0x%lx: %llu bytes sent %llu bytes received\n",
			 s->pid, CVM_CAST64(s->total_bytes_sent),
			 CVM_CAST64(s->total_bytes_received));

	cavium_print_msg("Thread 0x%lx: Max data sent: %lu bytes\n",
			 s->pid, s->maxdatasent);
#ifdef VERIFY_DATA
	if (resp_order != OCTEON_RESP_NORESPONSE) {
		cavium_print_msg
		    ("Thread 0x%lx: Verification: %lu passed %lu failed \n",
		     s->pid, s->verify_passed, s->verify_failed);
	}
#endif

	cavium_print_msg("Thread 0x%lx: [Input buffers /requests sent]\n",
			 s->pid);
	for (i = 0; i <= inbuf_cnt; i++) {
		if (s->incntfreq[i])
			cavium_print_msg("[ %d/%lu ] ", i, s->incntfreq[i]);
	}
	cavium_print_msg("\nThread 0x%lx: [Output buffers /requests sent]\n",
			 s->pid);
	for (i = 0; i <= outbuf_cnt; i++) {
		if (s->outcntfreq[i])
			cavium_print_msg("[ %d/%lu ] ", i, s->outcntfreq[i]);
	}

	cavium_print_msg("\n");
}

static int oct_test_thread(void *arg)
{
	int req_count = 0, tidx;
	struct test_stats *s = (struct test_stats *)arg;
	struct test_packet *tp;
	unsigned long prev = jiffies;

#if LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,0)
	daemonize();
	reparent_to_init();
#endif
	tidx = s->idx;

	cavium_print_msg("OCTEON_TEST: Octeon test thread[%d] start OK\n",
			 tidx);
	print_test_setup();

	cavium_atomic_set(&s->callback_received, 0);
	cavium_atomic_set(&s->req_posted, 0);
	s->post_failed = 0;
	s->outer_loop_cnt = 0;
	s->inner_loop_cnt = 0;

#ifdef REQUEST_PROFILE
	s->min_req_time = -1UL;
#endif

	do {
		s->outer_loop_cnt++;
		do {

			s->inner_loop_cnt++;

#if 0
			/* This check may fail when total buffer size < 16,
			 * since we are not allocating 16 bytes extra for each buffer now*/

			/* Outbufsize should be >=  16 bytes when a response is expected */
			if (((resp_order != OCTEON_RESP_NORESPONSE)
			     && ((outbuf_cnt * outbuf_size) < 16))) {
				continue;
			}
#endif
			tp = create_test_packet(tidx, s);
			if (!tp) {
				s->no_pkt_to_send++;
				cavium_schedule();
				continue;
			}
			tp->s = s;

			if ((inbuf_cnt * inbuf_size) > s->maxdatasent)
				s->maxdatasent = (inbuf_cnt * inbuf_size);

			s->incntfreq[inbuf_cnt]++;
			s->outcntfreq[outbuf_cnt]++;

			if (!send_test_packet(s, tp)) {
				req_count++;
				s->continuous_failures = 0;
			} else {
				s->post_failed++;
				cavium_print(OCTEON_DEBUG,
					     "OCTEON_TEST: Request failed\n");
				s->req_post_errors++;
				//      free_test_packet(tp);
				s->continuous_failures++;
				if (s->continuous_failures >
				    MAX_CONTINUOUS_FAILURES)
					test_ok_to_run = 0;
				cavium_sleep_timeout(10);
				break;
			}

			/* dereferencing soft_req after this point is risky.
			   callback could have been called freeing up soft_req */
		} while (req_count < pkt_burst);

		req_count = 0;

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,18)
		if (signal_pending(current))
#else
		if (kthread_should_stop())
#endif
		{
			cavium_error
			    ("OCTEON_TEST: Thread[0x%lx] stopping now\n",
			     s->pid);
			goto terminate_test;
		}

		if (jiffies > (prev + HZ)) {
			cavium_sleep_timeout(1);
			prev = jiffies;
		}
#ifdef REQUEST_PROFILE
		if (cavium_check_timeout(jiffies,
					 (s->last_display_tick +
					  DISPLAY_INTERVAL))) {
			if (cavium_atomic_read(&s->callback_received)) {
				printk
				    ("%d Total requests %d since last Avg_time: %llu\n",
				     cavium_atomic_read(&s->callback_received),
				     (cavium_atomic_read(&s->callback_received)
				      - (unsigned int)(s->last_request_count)),
				     (s->total_req_time /
				      cavium_atomic_read
				      (&s->callback_received)));
			} else {
				printk("No requests\n");
			}
			s->last_display_tick = jiffies;
			s->last_request_count =
			    cavium_atomic_read(&s->callback_received);
		}
#endif

	} while (test_ok_to_run);

terminate_test:
	cavium_print_msg
	    ("reqresp: Waiting for responses (posted: %d received: %d)\n",
	     cavium_atomic_read(&s->req_posted),
	     cavium_atomic_read(&s->callback_received));

	{
		unsigned long time_to_quit =
		    jiffies + (OCTEON_TEST_REQ_TIMEOUT * 2);

		while ((cavium_atomic_read(&s->req_posted)
			!= cavium_atomic_read(&s->callback_received))
		       && (jiffies < time_to_quit)) {
			schedule_timeout(1);
		}
	}
	print_test_stats(s);
	cavium_print_msg("OCTEON TEST:  thread stopped!!!\n");
#if defined(CREATE_ONCE)
	{
		int k;
		for (k = 0; k < MAX_PKTS; k++) {
			if (glbl_tp[tidx][k])
				free_test_packet(glbl_tp[tidx][k]);
		}
	}
#endif
	atomic_inc(&test_exit);
	s->pid = 0;
	return 0;
}

int init_module()
{
	int i, retval = 0;
	const char *req_resp_cvs_tag = "$Name$";
	char req_resp_version[80];

	if (set_args())
		return -EINVAL;

	if (num_threads > MAX_THREADS) {
		cavium_error
		    ("\n  Alert::: Test Parameters Are Not Appropriate                    \n");
		cavium_error("  num_threads[ %d ] > MAX_THREADS [ %d ] \n",
			     num_threads, MAX_THREADS);
		cavium_error
		    ("  num_threads should not be more than MAX_THREADS.                  \n");
		return -EINVAL;

	}
#if defined(CREATE_ONCE)
	for (i = 0; i < num_threads; i++) {
		int k;
		for (k = 0; k < MAX_PKTS; k++) {
			glbl_tp[i][k] = NULL;
		}
		pkt_idx[i] = 0;
	}
#endif

	if ((resp_order != OCTEON_RESP_NORESPONSE) &&
	    ((inbuf_cnt * inbuf_size) != (outbuf_cnt * outbuf_size))) {
		cavium_error
		    ("\n     Alert::: Test Parameters Are Not Appropriate          \n");
		cavium_error
		    (" (inbuf_cnt * inbuf_size) != (outbuf_cnt * outbuf_size)    \n");
		cavium_error
		    ("\n ======================================================    \n");
		cavium_error
		    ("\n Please Set The Test Parameters Appropriately Such That    \n");
		cavium_error
		    (" (inbuf_cnt * inbuf_size) = (outbuf_cnt * outbuf_size)   \n\n");
		return -EINVAL;
	}

	if ((resp_order == OCTEON_RESP_NORESPONSE) &&
	    ((dma_mode == OCTEON_DMA_SCATTER)
	     || (dma_mode == OCTEON_DMA_SCATTER_GATHER))) {
		cavium_error("NORESPONSE REQUEST NOT SUPPORTED IN %s MODE\n",
			     OCTEON_DMA_MODE_STRING(dma_mode));
		return -EINVAL;
	}

	if ((resp_order == OCTEON_RESP_NORESPONSE) &&
	    (resp_mode == OCTEON_RESP_BLOCKING)) {
		cavium_error("NORESPONSE/BLOCKING MODE NOT SUPPORTED\n");
		return -EINVAL;
	}

	if ((resp_order == OCTEON_RESP_UNORDERED) &&
	    (resp_mode == OCTEON_RESP_NON_BLOCKING)) {
		cavium_error("UNORDERED/NON_BLOCKING MODE NOT SUPPORTED\n");
		return -EINVAL;
	}

	if ((resp_order == OCTEON_RESP_ORDERED) &&
	    (resp_mode == OCTEON_RESP_BLOCKING)) {
		cavium_error("ORDERED/BLOCKING MODE NOT SUPPORTED\n");
		return -EINVAL;
	}

	if (inbuf_cnt > MAX_BUFCNT || outbuf_cnt > MAX_BUFCNT) {
		cavium_error("Invalid settings of inbuf_cnt/outbuf_cnt\n");
		return -EINVAL;
	}

	if ((dma_mode == OCTEON_DMA_DIRECT) || (dma_mode == OCTEON_DMA_SCATTER)) {
		if ((dma_mode == OCTEON_DMA_SCATTER) && (inbuf_cnt > 1)) {
			cavium_error
			    ("inbuf_cnt (%d) > 1 not allowed for %s DMA \n",
			     inbuf_cnt, OCTEON_DMA_MODE_STRING(dma_mode));
			return -EINVAL;
		}

		if ((inbuf_cnt * inbuf_size) > OCT_MAX_DIRECT_DATA_SIZE) {
			cavium_error
			    ("%s DMA: Invalid {inbuf_cnt (%d), inbuf_size (%d)}\n",
			     OCTEON_DMA_MODE_STRING(dma_mode), inbuf_cnt,
			     inbuf_size);
			return -EINVAL;
		}

	} else {
		if ((inbuf_cnt * inbuf_size) > OCT_MAX_GATHER_DATA_SIZE) {
			cavium_error
			    ("%s DMA: Invalid {inbuf_cnt (%d), inbuf_size (%d)}\n",
			     OCTEON_DMA_MODE_STRING(dma_mode), inbuf_cnt,
			     inbuf_size);
			return -EINVAL;
		}

	}

	if ((dma_mode == OCTEON_DMA_DIRECT) || (dma_mode == OCTEON_DMA_GATHER)) {

		if (outbuf_cnt > 1) {
			cavium_error
			    ("outbuf_cnt (%d) > 1 not allowed for %s DMA \n",
			     outbuf_cnt, OCTEON_DMA_MODE_STRING(dma_mode));
			return -EINVAL;
		}

		if ((outbuf_cnt * outbuf_size) > OCT_MAX_DIRECT_DMA_SIZE) {
			cavium_error
			    ("%s DMA:Invalid {outbuf_cnt (%d),outbuf_size (%d)}\n",
			     OCTEON_DMA_MODE_STRING(dma_mode), outbuf_cnt,
			     outbuf_size);
			return -EINVAL;
		}

	}

	if ((dma_mode == OCTEON_DMA_SCATTER)
	    || (dma_mode == OCTEON_DMA_SCATTER_GATHER)) {
		if (outbuf_cnt > 13) {
			cavium_error
			    ("%s DMA:Invalid {outbuf_cnt (%d),MAX SUPPORTED IS 13}\n",
			     OCTEON_DMA_MODE_STRING(dma_mode), outbuf_cnt);
			return -EINVAL;
		}

		if ((outbuf_cnt * outbuf_size) > OCT_MAX_SCATTER_DMA_SIZE) {
			cavium_error
			    ("%s DMA:Invalid {outbuf_cnt (%d),outbuf_size (%d)}\n",
			     OCTEON_DMA_MODE_STRING(dma_mode), outbuf_cnt,
			     outbuf_size);
			return -EINVAL;
		}

	}

	memset(tstats, 0, sizeof(struct test_stats) * num_threads);

	for (i = 0; i < num_threads; i++) {
		tstats[i].pid = -1;
	}

	test_ok_to_run = 1;
	atomic_set(&test_exit, 0);
	for (i = 0; i < num_threads; i++) {
		tstats[i].idx = i;
		tstats[i].pid =
		    (unsigned long)kthread_run(oct_test_thread, &tstats[i],
					       "Oct Reqresp Test");
		if (((cavium_ostask_t *) tstats[i].pid) == NULL) {
			cavium_error("Failed to create test thread\n");
			retval = -ENOMEM;
			goto req_resp_fail;
		}
	}

	proc1 = proc_create("reqrespstats", 0644, NULL, &reqresp_proc_ops);
	if (proc1 == NULL) {
		cavium_error
		    ("OCTEON_TEST: Failed to add proc entry for req_resp.ko module\n");
		return ENOMEM;
	}
	SET_PROC_OWNER(proc1);

	cavium_parse_cvs_string(req_resp_cvs_tag, req_resp_version, 80);
	cavium_print_msg
	    ("Octeon Request/Response test application (%s) loaded\n",
	     req_resp_version);
	return 0;

req_resp_fail:

	for (i = 0; i < num_threads; i++) {
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,18)
		if (tstats[i].pid)
			kill_proc((pid_t) tstats[i].pid, SIGTERM, 1);
#else
		if (tstats[i].pid)
			kthread_stop((cavium_ostask_t *) tstats[i].pid);
#endif
	}

	return retval;
}

void cleanup_module()
{
	int i;
#if LINUX_VERSION_CODE > KERNEL_VERSION(2,6,0)
	/* SIGINT and SIGHUP both need to be disallowed for the time when 
	   we send out delete instructions. */
	disallow_signal(SIGINT);
	disallow_signal(SIGHUP);
#endif
	for (i = 0; i < num_threads; i++) {
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,18)
		if (tstats[i].pid)
			kill_proc((pid_t) tstats[i].pid, SIGTERM, 1);
#else
		if (tstats[i].pid)
			kthread_stop((cavium_ostask_t *) tstats[i].pid);
#endif
	}
	/* Change flag to 0 after kill command. kthread_stop() has issues if the
	   thread that it tried to stop had already exited. */
	test_ok_to_run = 0;
	while (atomic_read(&test_exit) < num_threads)
		cavium_schedule();
	remove_proc_entry("reqrespstats", NULL);
}

/* $Id: octeon_req_resp.c 142567 2016-07-27 07:14:47Z mchalla $ */
