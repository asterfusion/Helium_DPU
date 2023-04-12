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

/*! \file oct_req.c  
 *  \brief Test program to test request/response for Octeon PCI.
 */

/*  This program allows testing of user-space requests to the Octeon driver
	for all supported. It supports multiple processes. All processes generate
	the same type of request (determined by command-line args or values in
	oct_req.h). The data sizes can be randomized.

	The main process allocates a shared memory are for a struct test.
	It forks child processes if TEST_THREAD_COUNT is > 1 and gives and index
	to each process.
	Each child process attached to the shared memory allocated by the main
	and uses the perthread field based on its index to store test stats.
	Each child process runs an instance of oct_request_thread().
	The main thread continues to wait till the child processes finish execution.
	The test parameters are all available from the struct test var.
	If the test is for UNORDERED NONBLOCKING requests, an array of size
	MAX_NB_REQUESTS keep track of pending requests for which queries need to be
	sent.
	For UNORDERED BLOCKING, each call to send a request returns only when the
	response has arrived.
	For NORESPONSE, each call to send a request returns as soon as the driver
	queues the request.
	The input and output buffer data size is determined by the values in
	oct_req.h.
	The input data buffers are signed with a pattern. For UNORDERED requests,
	the response is checked against this pattern if VERIFY_DATA is enabled.
	The child processes stop on receiving a signal or if the predefined number
	of requests have been sent. They wait for UNORDERED BLOCKING requests to
	complete.
	The main process detects the completion of child processes and prints the
	test results and exits.
*/

#include "cavium_sysdep.h"
#include "cavium_defs.h"
#include "octeon-opcodes.h"
#include "octeon-common.h"
#include "octeon_user.h"
#include "cavium_release.h"
#include <signal.h>

#include <sys/ipc.h>
#include <sys/shm.h>
#include <sys/sysinfo.h>
#include <sched.h>
#include <errno.h>
#include "oct_req.h"

/* Enable this definition to display debug messages. */
//#define DEBUG_MODE_ON

#define   REQ_NONE  0
#define   REQ_PEND  1
#define   REQ_DONE  2

/* size of the all inbufs, if MAX_INBUFS > 1
 *
 */
uint32_t indata_size;

/* size of the all outbufs, if MAX_OUTBUFS > 1
 *
 */
uint32_t outdata_size;

int thread_cnt = TEST_THREAD_COUNT;

int oct_id = OCTEON_ID, ok_to_print = 1, shmid = -1;
int signal_to_catch = SIGINT, non_stop = 1, num_ioqs, num_cpus;
void (*prev_sig_handler) (int);

uint32_t inbuf_size = INBUF_SIZE;
uint32_t outbuf_size = OUTBUF_SIZE;

struct request_list {
	octeon_soft_request_t *sr;
	int status;
	uint32_t outsize;
	uint32_t verify_size;
};

struct test_stats {
	void *sh_mem;
	struct request_list *nbreqs;
	pid_t pid;
	volatile int running;
	volatile int reqs_pending;
	unsigned long incntfreq[MAX_INBUFS + 1];
	unsigned long outcntfreq[MAX_OUTBUFS + 1];
	unsigned long maxdatasent;
	unsigned long maxdatareceived;
	unsigned long request_count;
	unsigned long verify_failed;
	unsigned long verify_passed;
};

struct test {
	volatile int ok_to_send;

	pid_t main_pid;

	OCTEON_RESPONSE_ORDER resp_order;
	OCTEON_RESPONSE_MODE resp_mode;
	OCTEON_DMA_MODE dma_mode;

	struct test_stats perthread[TEST_THREAD_COUNT * OCTEON_MAX_BASE_IOQ];
	struct test_stats total;
	time_t start, end;
};

void free_soft_request(octeon_soft_request_t * soft_req);

int verify_output(struct test_stats *s, octeon_soft_request_t * soft_req,
		  int vcount, int ocount);
int check_req_status(octeon_soft_request_t * sr);

struct test *t_main = NULL;

#ifdef DEBUG_MODE_ON
#define __print(format, ...)    \
{ \
	if(ok_to_print) \
		printf(format, ## __VA_ARGS__); \
}
#else
#define __print(format, ...)    do{ } while(0)
#endif

void print_count_freq(struct test_stats *s)
{
	int i;

	printf("Tested with Input buffers [buffer count/requests sent]\n");
	for (i = 0; i <= MAX_INBUFS; i++) {
		if (s->incntfreq[i])
			printf("[ %d/%lu ] ", i, s->incntfreq[i]);
	}
	printf("\n");
	if (!s->maxdatareceived)
		return;
	printf("Tested with Output buffers [buffer count/requests sent]\n");
	for (i = 0; i <= MAX_OUTBUFS; i++) {
		if (s->outcntfreq[i])
			printf("[ %d/%lu ] ", i, s->outcntfreq[i]);
	}
	printf("\n");
}

void print_test_stats(struct test *t)
{
	printf("\nTest completed: %lu requests sent.\n",
	       t->total.request_count);
#ifdef VERIFY_DATA
	if (t->resp_order != OCTEON_RESP_NORESPONSE) {
		printf("Verification: %lu passed %lu failed \n",
		       t->total.verify_passed, t->total.verify_failed);
	}
#endif
	print_count_freq(&t->total);

	printf("Max data sent: %lu bytes\n", t->total.maxdatasent);

	if (t->resp_order != OCTEON_RESP_NORESPONSE) {
		printf("Max data received: %lu bytes\n",
		       t->total.maxdatareceived);
	}
}

void add_thread_stats(struct test *t)
{
	int i, j;

	for (i = 0; i < thread_cnt; i++) {
		for (j = 0; j <= MAX_INBUFS; j++)
			t->total.incntfreq[j] += t->perthread[i].incntfreq[j];
		for (j = 0; j <= MAX_OUTBUFS; j++)
			t->total.outcntfreq[j] += t->perthread[i].outcntfreq[j];

		t->total.request_count += t->perthread[i].request_count;
		t->total.verify_failed += t->perthread[i].verify_failed;
		t->total.verify_passed += t->perthread[i].verify_passed;

		if (t->total.maxdatasent < t->perthread[i].maxdatasent)
			t->total.maxdatasent = t->perthread[i].maxdatasent;

		if (t->total.maxdatareceived < t->perthread[i].maxdatareceived)
			t->total.maxdatareceived =
			    t->perthread[i].maxdatareceived;
	}
}

/* Call with a non-zero timeval to check the active threads for a
   fixed number of iterations (given by counter). If timeval is 0,
   the routine does not exit till there are active threads.
*/
void wait_for_thread_completion(struct test *t, int timeval)
{
	int i, t_exists, counter = 5, sleeptime = 1;

	__print("--- In wait_for_thread_completion() --\n");

	if (timeval)
		sleeptime = timeval;

	do {

		for (i = 0, t_exists = 0; i < thread_cnt; i++)
			t_exists += t->perthread[i].running;

		if (timeval && !(--counter))
			break;

		sleep(sleeptime);

		/* ok_to_send is reset only when the signal handler is called.
		   After the signal handler is called, the main thread will
		   check for active thread for only "counter" times. */
		timeval = (t_main->ok_to_send == 0);

	} while (t_exists);

	__print("quitting %s t_exists: %d counter: %d timeval: %d\n",
		__FUNCTION__, t_exists, counter, timeval);
}

void wait_for_unordered_requests(struct test_stats *s)
{
	int i, r, max_retries = 10;

	__print("\n(pid: %d) pending requests: %d\n", getpid(),
		s->reqs_pending);

	while (s->reqs_pending && max_retries--) {
		for (i = 0; i < MAX_NB_REQUESTS; i++) {

			if (s->nbreqs[i].status == REQ_NONE)
				continue;

			r = check_req_status(s->nbreqs[i].sr);

			if (r != OCTEON_REQUEST_PENDING) {
				if (r == OCTEON_REQUEST_DONE) {
					verify_output(s, s->nbreqs[i].sr,
						      s->nbreqs[i].verify_size,
						      s->nbreqs[i].outsize);
					if (s->nbreqs[i].outsize >
					    s->maxdatareceived)
						s->maxdatareceived =
						    s->nbreqs[i].outsize;
				}
				free_soft_request(s->nbreqs[i].sr);
				s->nbreqs[i].sr = NULL;
				s->nbreqs[i].status = REQ_NONE;
				s->reqs_pending--;
			}
		}
		sleep(1);
		__print("(pid: %d) %d pending requests\n", getpid(),
			s->reqs_pending);
	}

	if (s->reqs_pending) {
		printf
		    ("Quitting! There are still %d pending requests for thread %d\n",
		     s->reqs_pending, s->pid);
	} else {
		__print("(pid: %d) No more requests\n", getpid());
	}
}

void signal_handler(int x)
{
	pid_t my_pid = getpid();

	/* Just clear the ok_to_send flag. When the signal handler returns in
	   the main process, it will wait for the children to complete its
	   processing.
	 */
	if (t_main && (my_pid == t_main->main_pid)) {
		t_main->ok_to_send = 0;
		return;
	}

}

void print_usage()
{
	printf
	    ("Usage: oct_req <oct_id> [-b] [-u] [-s] [-h] [-y] [-d dma_mode] [-I size] [-O size] [-q iq_num] [count]\n");
	printf
	    ("Usage: oct_req <oct_id> [-b] [-u] [-s] [-h] [-y] [-d dma_mode] [-I size] [-O size] [count]\n");
	printf("  Sends requests of the type specified to the Octeon driver\n");
	printf("  By default requests are sent with\n");
	printf("        dma mode       = DIRECT\n");
	printf("        response order = NO RESPONSE\n");
	printf("        response mode  = NON-BLOCKING\n");
	printf("        to Octeon device 0\n\n");

	printf(" Mandatory arguments\n");
	printf
	    ("    oct_id - Octeon device id (0 for 1st device, 1 for 2nd..)\n");
	printf(" Optional arguments\n");
	printf
	    ("   -d <dma_mode>: where dma mode can be \"direct\", \"gather\", \"scatter\" or \"scatter_gather\" \n");
	printf("   -b: changes response mode to BLOCKING\n");
	printf("   -u: changes response order to UNORDERED\n");
	printf("   -I: Input buffer size in bytes\n");
	printf("   -O: Output buffer size in bytes\n");
	printf("   -s: turns off flow related prints. Errors are printed\n");
	printf("   -y: turns off all user prompts\n");
	printf
	    ("   -q: <input queue> : prints all the queues for a wrong value\n");
	printf("  count: The program stops after sending \"count\" requests\n");
}

void printstring(int type, int value)
{
	switch (type) {
	case 0:
		switch (value) {
		case OCTEON_RESP_NORESPONSE:
			printf(" NORESPONSE (%d)\n", value);
			break;
		case OCTEON_RESP_UNORDERED:
			printf(" UNORDERED (%d)\n", value);
			break;
		default:
			printf(" UNKNOWN ");
			break;
		}
		break;
	case 1:
		switch (value) {
		case OCTEON_RESP_BLOCKING:
			printf(" BLOCKING (%d)\n", value);
			break;
		case OCTEON_RESP_NON_BLOCKING:
			printf(" NON-BLOCKING (%d)\n", value);
			break;
		default:
			printf(" UNKNOWN ");
			break;
		}
		break;
	case 2:
		switch (value) {
		case OCTEON_DMA_DIRECT:
			printf(" DIRECT (%d)\n", value);
			break;
		case OCTEON_DMA_GATHER:
			printf(" GATHER (%d)\n", value);
			break;
		case OCTEON_DMA_SCATTER:
			printf(" SCATTER (%d)\n", value);
			break;
		case OCTEON_DMA_SCATTER_GATHER:
			printf(" SCATTER/GATHER (%d)\n", value);
			break;
		}
		break;
	default:
		break;
	}

}

void print_data(uint8_t * data, uint32_t size)
{
	int i;

	printf("Printing %d bytes @ %p\n", size, data);
	for (i = 0; i < size; i++) {
		printf(" %02x", data[i]);
		if ((i & 0x7) == 0x7)
			printf("\n");
	}
	printf("\n");
}

void
print_test_setup(OCTEON_DMA_MODE dma_mode,
		 OCTEON_RESPONSE_ORDER resp_order,
		 OCTEON_RESPONSE_MODE resp_mode)
{
	printf("  response order = ");
	printstring(0, resp_order);
	printf("  response mode  = ");
	printstring(1, resp_mode);
	printf("  dma mode       = ");
	printstring(2, dma_mode);
	printf("  Max in bufs  = %d\n", MAX_INBUFS);
	printf("  Max out bufs  = %d\n", MAX_OUTBUFS);
	printf("  Inbuf size: %d  Outbuf size: %d\n", inbuf_size, outbuf_size);
}

int set_buffers(octeon_soft_request_t * soft_req, int incnt, int outcnt)
{
	int i, j;

	__print("incnt: %d outcnt: %d\n", incnt, outcnt);

	if ((incnt > MAX_INBUFS) || (outcnt > MAX_OUTBUFS))
		return 1;

	memset(&soft_req->inbuf, 0, sizeof(octeon_buffer_t));
	memset(&soft_req->outbuf, 0, sizeof(octeon_buffer_t));

	soft_req->inbuf.cnt = 0;
	for (i = 0; i < incnt; i++) {
		soft_req->inbuf.cnt++;
		SOFT_REQ_INBUF(soft_req, i) = malloc(inbuf_size);
		if (SOFT_REQ_INBUF(soft_req, i) == NULL)
			goto free_inbufs;
		__print("inbuf.ptr[%d] = %p\n", i, SOFT_REQ_INBUF(soft_req, i));
		soft_req->inbuf.size[i] = inbuf_size;
#ifdef VERIFY_DATA
		for (j = 0; j < inbuf_size; j++)
			SOFT_REQ_INBUF(soft_req, i)[j] =
			    ((j & 0xff) == 0) ? 1 : j;
#endif
	}

	soft_req->outbuf.cnt = 0;
	for (i = 0; i < outcnt; i++) {
		soft_req->outbuf.cnt++;
		SOFT_REQ_OUTBUF(soft_req, i) = malloc(outbuf_size);
		if (SOFT_REQ_OUTBUF(soft_req, i) == NULL)
			goto free_outbufs;
		__print("outbuf.ptr[%d] = %p\n", i,
			SOFT_REQ_OUTBUF(soft_req, i));
		soft_req->outbuf.size[i] = outbuf_size;
#ifdef VERIFY_DATA
		memset(SOFT_REQ_OUTBUF(soft_req, i), i + 1, outbuf_size);
#endif
	}
	return 0;

free_outbufs:
	for (i = 0; i < outcnt; i++) {
		if (SOFT_REQ_OUTBUF(soft_req, i))
			free(SOFT_REQ_OUTBUF(soft_req, i));
	}
free_inbufs:
	for (i = 0; i < incnt; i++) {
		if (SOFT_REQ_INBUF(soft_req, i))
			free(SOFT_REQ_INBUF(soft_req, i));
	}
	return 1;
}

int send_request(int oct_id, struct test_stats *s, octeon_soft_request_t * sr)
{
	int status = -1, retval, i;
	octeon_request_info_t *req_info;

	req_info = SOFT_REQ_INFO(sr);

	__print("BEFORE oct_id: %d soft_req->status: %d req_id: %d\n",
		SOFT_REQ_INFO(sr)->octeon_id, SOFT_REQ_INFO(sr)->status,
		SOFT_REQ_INFO(sr)->request_id);

	retval = octeon_send_request(oct_id, sr);
	__print("test_input: retval is %d\n", retval);

	if (!retval) {

		s->request_count++;
		s->incntfreq[sr->inbuf.cnt]++;
		if (sr->outbuf.cnt)
			s->outcntfreq[sr->outbuf.cnt]++;

		__print("req_id: %d status: %d\n", req_info->request_id,
			req_info->status);
		if (req_info->req_mask.resp_mode == OCTEON_RESP_NON_BLOCKING)
			status = retval;
		else
			status = req_info->status;

	} else {

		printf("\n----Request (req_id: %d) FAILED; retval: %d----\n",
		       SOFT_REQ_INFO(sr)->request_id, retval);

	}

	if (ok_to_print
	    && (req_info->req_mask.resp_order == OCTEON_RESP_UNORDERED)) {
		__print("Buffer contents after ioctl\n");
		for (i = 0; i < sr->outbuf.cnt; i++) {
			print_data(SOFT_REQ_OUTBUF(sr, i), sr->outbuf.size[i]);
		}
	}

	return status;
}

octeon_soft_request_t *create_soft_request(OCTEON_DMA_MODE dma_mode,
					   OCTEON_RESPONSE_ORDER resp_order,
					   OCTEON_RESPONSE_MODE resp_mode,
					   uint32_t inbuf_cnt,
					   uint32_t outbuf_cnt,
					   uint32_t tag, uint32_t q_no)
{
	octeon_soft_request_t *soft_req = NULL;
	octeon_request_info_t *req_info = NULL;

	soft_req = malloc(sizeof(octeon_soft_request_t));
	if (soft_req == NULL)
		return NULL;

	req_info = malloc(sizeof(octeon_request_info_t));
	if (req_info == NULL) {
		free(soft_req);
		return NULL;
	}

	memset(soft_req, 0, sizeof(octeon_soft_request_t));
	memset(req_info, 0, sizeof(octeon_request_info_t));

	SOFT_REQ_INFO(soft_req) = req_info;

	/* Fill up IH */
	soft_req->ih.raw = 1;
	soft_req->ih.qos = 0;
	soft_req->ih.grp = 0;
	soft_req->ih.rs = 0;
	soft_req->ih.tagtype = 1;
	soft_req->ih.tag = tag;
	if ((dma_mode == OCTEON_DMA_GATHER)
	    || (dma_mode == OCTEON_DMA_SCATTER_GATHER))
		soft_req->ih.gather = 1;

	/* Fill up IRH */
	soft_req->irh.opcode = CVMCS_REQRESP_OP;
	soft_req->irh.param = 0x10;
	soft_req->irh.dport = 32;

	if ((dma_mode == OCTEON_DMA_SCATTER)
	    || (dma_mode == OCTEON_DMA_SCATTER_GATHER))
		soft_req->irh.scatter = 1;

	req_info->octeon_id = 0;
	req_info->request_id = 0xff;
	req_info->req_mask.dma_mode = dma_mode;
	req_info->req_mask.resp_mode = resp_mode;
	req_info->req_mask.resp_order = resp_order;
	req_info->req_mask.iq_no = q_no;
	req_info->timeout = REQUEST_TIMEOUT;

	if (set_buffers(soft_req, inbuf_cnt, outbuf_cnt)) {
		free(req_info);
		free(soft_req);
		return NULL;
	}
	SOFT_REQ_INFO(soft_req)->status = 3;

	return soft_req;
}

void free_soft_request(octeon_soft_request_t * soft_req)
{
	int i;
	for (i = 0; i < soft_req->outbuf.cnt; i++) {
		if (SOFT_REQ_OUTBUF(soft_req, i))
			free(SOFT_REQ_OUTBUF(soft_req, i));
	}
	for (i = 0; i < soft_req->inbuf.cnt; i++) {
		if (SOFT_REQ_INBUF(soft_req, i))
			free(SOFT_REQ_INBUF(soft_req, i));
	}
	free(SOFT_REQ_INFO(soft_req));
	free(soft_req);
}

/* The core application copies input bytes into the output buffers. If the
 * input buffer is smaller than output, the rest of the output buffer is
 * filled with 0xFA.
 * The verify_output() sets the check_sign when it knows that all copied
 * bytes have been compared and that the rest of the output buffer(s) are
 * filled with 0xFA.
 */
int compare_bytes(uint8_t * in, uint8_t * out, int bytes, int check_sign)
{
	int i, j;

	if (check_sign) {
		for (i = 0; i < bytes; i++) {
			if (0xFA != out[i]) {
				printf("Data sign mismatch at byte %d\n", i);
				j = (i > 8) ? i - 8 : 0;
				goto compare_bytes_error;
			}
		}
	} else {
		for (i = 0; i < bytes; i++) {
			if (in[i] != out[i])
				return -1;
		}
	}
	return 0;

compare_bytes_error:
	printf("Printing output bytes from byte %d\n", j);
	for (i = j; (i < (j + 32)) && (i < bytes); i++)
		printf(" %02x ", out[i]);
	printf("\n");
	return -1;
}

/* soft_req - Request structure with input and output buffers.
   vcount   - number of bytes to verify.
   ocount   - Total number of output bytes.
*/
int
verify_output(struct test_stats *s,
	      octeon_soft_request_t * soft_req, int vcount, int ocount)
{
	int total_bytes = 0, in_idx = 0, out_idx = 0, check_sign = 0;
	int check_bytes = 0, in_bytes = 0, out_bytes = 0;
	uint8_t *inptr = SOFT_REQ_INBUF(soft_req, 0);
	uint8_t *outptr = SOFT_REQ_OUTBUF(soft_req, 0);

	__print("Verifying %d bytes\n", vcount);
resume_verification:
	while (total_bytes < vcount) {
		if (out_bytes == 0) {
			if (out_idx < soft_req->outbuf.cnt) {
				out_bytes = soft_req->outbuf.size[out_idx];
				outptr = SOFT_REQ_OUTBUF(soft_req, out_idx);
				out_idx++;
			} else {
				printf("Verify ran out of output buffers\n");
				goto verify_error;
			}
		}

		/* For each input buffer. */
		if (!check_sign && (in_bytes == 0)) {
			if (in_idx < soft_req->inbuf.cnt) {
				in_bytes = soft_req->inbuf.size[in_idx];
				inptr = SOFT_REQ_INBUF(soft_req, in_idx);
				in_idx++;
			} else {
				printf("Verify ran out of input buffers\n");
				goto verify_error;
			}
		}
		if (check_sign)
			check_bytes = out_bytes;
		else
			check_bytes =
			    (in_bytes < out_bytes) ? in_bytes : out_bytes;

		__print("Compare %d bytes with%s sign\n", check_bytes,
			(check_sign) ? "" : "out");
		if (compare_bytes(inptr, outptr, check_bytes, check_sign))
			goto verify_error;
		if (!check_sign) {
			in_bytes -= check_bytes;
			inptr += check_bytes;
		}
		out_bytes -= check_bytes;
		outptr += check_bytes;
		total_bytes += check_bytes;
	}

	/* If there are more output bytes than input, the rest of output 
	 * should have all 0xFA in them. Verify that this is the case.
	 */
	if (ocount > vcount) {
		vcount = ocount;
		check_sign = 1;
		goto resume_verification;
	}

	__print("Verified %d bytes\n", total_bytes);
	s->verify_passed++;
	return 0;

verify_error:
	printf("Verification mismatch at inbuf[%d], outbuf[%d]\n",
	       in_idx - 1, out_idx - 1);
#ifdef DEBUG_MODE_ON
	printf("%d bytes of Input buffer no. %d starting at %p\n",
	       in_bytes, in_idx, inptr);
	print_data(inptr, in_bytes);
	printf("%d bytes of Output buffer no. %d starting at %p\n",
	       out_bytes, out_idx, outptr);
	print_data(outptr, out_bytes);
#endif
	s->verify_failed++;
	return 1;
}

OCTEON_DMA_MODE get_dma_mode(char *dma_string)
{
	if (!strncasecmp(dma_string, "direct", 6))
		return OCTEON_DMA_DIRECT;
	if (!strncasecmp(dma_string, "gather", 6))
		return OCTEON_DMA_GATHER;
	if (!strncasecmp(dma_string, "scatter_gather", 14))
		return OCTEON_DMA_SCATTER_GATHER;
	if (!strncasecmp(dma_string, "scatter", 7))
		return OCTEON_DMA_SCATTER;
	return TEST_DMA_MODE;
}

void
generate_data_sizes(struct test_stats *s,
		    uint32_t * incnt,
		    uint32_t * outcnt,
		    uint32_t * insize,
		    uint32_t * outsize, uint32_t * verify_size)
{

	*incnt = MAX_INBUFS;
	if (outcnt)
		*outcnt = MAX_OUTBUFS;

	*insize = (*incnt * inbuf_size);
	if (*insize > s->maxdatasent)
		s->maxdatasent = *insize;

	if (outcnt) {
		*outsize = (*outcnt * outbuf_size);
		*verify_size = (*insize > *outsize) ? *outsize : *insize;
	}
}

int
unordered_blocking_request(int q_no,
			   uint32_t tag,
			   struct test_stats *s, OCTEON_DMA_MODE dma_mode)
{
	octeon_soft_request_t *soft_req = NULL;
	int req_status = 0, retval = 0;
	uint32_t incnt, outcnt;
	uint32_t insize = 0, outsize = 0, verify_size = 0;

	generate_data_sizes(s, &incnt, &outcnt, &insize, &outsize,
			    &verify_size);
	soft_req =
	    create_soft_request(dma_mode, OCTEON_RESP_UNORDERED,
				OCTEON_RESP_BLOCKING, incnt, outcnt, tag, q_no);
	__print("soft_req: %p  incnt: %d  outcnt: %d\n", soft_req, incnt,
		outcnt);

	if (soft_req == NULL) {
		printf("Soft request alloc failed\n");
		return 1;
	}
	__print("\n Created Request with incnt: %d outcnt: %d\n", incnt,
		outcnt);

	req_status = send_request(oct_id, s, soft_req);
	if (!req_status) {
		if (outsize > s->maxdatareceived)
			s->maxdatareceived = outsize;
		retval = verify_output(s, soft_req, verify_size, outsize);
	} else {
		printf("Request Failed with status %d\n", req_status);
		retval = 1;
	}
	free_soft_request(soft_req);

	return retval;
}

int validate_test_params(OCTEON_DMA_MODE dma_mode)
{

	if (outdata_size < 16) {
		printf(" \n Invalid output size for Response Order (%d)\n",
		       TEST_RESP_ORDER);
		return 1;
	}

	if (indata_size != outdata_size) {
		printf
		    ("\n     Alert::: Test Parameters Are Not Appropriate          \n");
		printf
		    (" (MAX_INBUFS * INBUF_SIZE) != (MAX_OUTBUFS * OUTBUF_SIZE)    \n");
		printf
		    ("\n ======================================================    \n");
		printf
		    ("\n Please Set The Test Parameters Appropriately Such That    \n");
		printf
		    (" (MAX_INBUFS * INBUF_SIZE) = (MAX_OUTBUFS * OUTBUF_SIZE)   \n\n");
		return 1;
	}

	if (dma_mode == OCTEON_DMA_DIRECT) {
		if (indata_size > OCT_MAX_DIRECT_INPUT_DATA_SIZE) {
			printf
			    ("\n Input size ( %d ) exeeds for max Direct dma size ( %d ) \n",
			     indata_size, OCT_MAX_DIRECT_INPUT_DATA_SIZE);
			return 1;
		}
		if (outdata_size > OCT_MAX_DIRECT_OUTPUT_DATA_SIZE) {
			printf
			    ("\n Output size ( %d ) exeeds for max Direct dma size ( %d ) \n",
			     outdata_size, OCT_MAX_DIRECT_OUTPUT_DATA_SIZE);
			return 1;
		}

	}

	if (dma_mode == OCTEON_DMA_GATHER) {
		if (indata_size > OCT_MAX_GATHER_DATA_SIZE) {
			printf
			    ("\n Input size ( %d ) exeeds for max Gather dma size ( %d ) \n",
			     indata_size, OCT_MAX_GATHER_DATA_SIZE);
			return 1;
		}
		if (outdata_size > OCT_MAX_DIRECT_OUTPUT_DATA_SIZE) {
			printf
			    ("\n Output size ( %d ) exeeds for max Gather dma size ( %d ) \n",
			     outdata_size, OCT_MAX_DIRECT_OUTPUT_DATA_SIZE);
			return 1;
		}

	}

	if (dma_mode == OCTEON_DMA_SCATTER) {
		/*if(MAX_OUTBUFS > 13)
		   {
		   printf("\n Scatter requests don't support Max Outbuf count ( %d ) more than 13 \n", MAX_OUTBUFS);
		   //return 1;          
		   } */

		if (indata_size > OCT_MAX_DIRECT_INPUT_DATA_SIZE) {
			printf
			    ("\n Input size ( %d ) exeeds for max Scatter dma size ( %d ) \n",
			     indata_size, OCT_MAX_DIRECT_INPUT_DATA_SIZE);
			return 1;
		}
		if (outdata_size > OCT_MAX_SCATTER_DATA_SIZE) {
			printf
			    ("\n Output size ( %d ) exeeds for max Scatter dma size ( %d ) \n",
			     outdata_size, OCT_MAX_SCATTER_DATA_SIZE);
			return 1;
		}

	}

	if (dma_mode == OCTEON_DMA_SCATTER_GATHER) {
		/*if(MAX_INBUFS != MAX_OUTBUFS)
		   {
		   printf("\n Max Inbuf count ( %d ) and Max Outbuf count ( %d ) is not same \n", MAX_INBUFS, MAX_OUTBUFS );
		   printf(" For Scatter_Gather requests Max Inbuf cnt and Max Outbuf cnt must be same. \n");
		   //return 1;

		   } */

		if (indata_size > OCT_MAX_GATHER_DATA_SIZE) {
			printf
			    ("\n Input size ( %d ) exeeds for max Gather dma size ( %d ) \n",
			     indata_size, OCT_MAX_GATHER_DATA_SIZE);
			return 1;
		}
		if (outdata_size > OCT_MAX_SCATTER_DATA_SIZE) {
			printf
			    ("\n Output size ( %d ) exeeds for max Scatter dma size ( %d ) \n",
			     outdata_size, OCT_MAX_SCATTER_DATA_SIZE);
			return 1;
		}

	}

	return 0;
}

int
unordered_nonblocking_request(int q_no,
			      uint32_t tag,
			      struct test_stats *s,
			      struct request_list *nb, OCTEON_DMA_MODE dma_mode)
{
	octeon_soft_request_t *soft_req;
	int req_status = 0;
	uint32_t incnt, outcnt;
	uint32_t insize = 0, outsize = 0, verify_size = 0;

	generate_data_sizes(s, &incnt, &outcnt, &insize, &outsize,
			    &verify_size);

	soft_req = create_soft_request(dma_mode, OCTEON_RESP_UNORDERED,
				       OCTEON_RESP_NON_BLOCKING,
				       incnt, outcnt, tag, q_no);
	if (soft_req == NULL) {
		printf("Soft request alloc failed\n");
		return -1;
	}
	__print("\n Created Request with incnt: %d outcnt: %d\n", incnt,
		outcnt);

	req_status = send_request(oct_id, s, soft_req);
	if (req_status) {
		printf("Request Failed with status %d\n", req_status);
		free_soft_request(soft_req);
		return 1;
	}

	nb->status = REQ_PEND;
	nb->outsize = outsize;
	nb->verify_size = verify_size;
	nb->sr = soft_req;
	return 0;
}

int
noresponse_request(int q_no,
		   uint32_t tag, struct test_stats *s, OCTEON_DMA_MODE dma_mode)
{
	octeon_soft_request_t *soft_req;
	int req_status = 0;
	uint32_t incnt, insize = 0;

	generate_data_sizes(s, &incnt, NULL, &insize, NULL, NULL);

	soft_req = create_soft_request(dma_mode, OCTEON_RESP_NORESPONSE,
				       OCTEON_RESP_NON_BLOCKING,
				       incnt, 0, tag, q_no);
	if (soft_req == NULL) {
		printf("Soft request alloc failed\n");
		return 1;
	}
	__print("\n Created Request with incnt: %d\n", incnt);

	req_status = send_request(oct_id, s, soft_req);
	if (req_status) {
		printf("Request Failed with status %d\n", req_status);
		free_soft_request(soft_req);
		return 1;
	}
	free_soft_request(soft_req);

	return 0;
}

int check_req_status(octeon_soft_request_t * sr)
{
	octeon_query_request_t query;

	query.octeon_id = SOFT_REQ_INFO(sr)->octeon_id;
	query.request_id = SOFT_REQ_INFO(sr)->request_id;

	if (octeon_query_request(oct_id, &query)) {
		perror("ioctl failed for query request\n");
		return -1;
	}

	return query.status;
}

void oct_request_thread(int q_no, int count, int tidx)
{
	struct test *t;
	struct test_stats *s;
	time_t t1;
	uint32_t tag = 0x101011;
	int i, req_status = 0, nbidx = 0;
	struct request_list *nbreqs;

	t = (struct test *)shmat(shmid, NULL, 0);
	if ((unsigned long)t == -1) {
		printf("Failed to attach shared memory in thread (index: %d)\n",
		       tidx);
		shmctl(shmid, IPC_RMID, NULL);
		return;
	}
	__print("Attached shared memory at %p in thread index %d\n", t, tidx);

	s = (struct test_stats *)&(t->perthread[tidx]);
	s->sh_mem = t;

	s->nbreqs = malloc(sizeof(struct request_list) * MAX_NB_REQUESTS);
	if (s->nbreqs == NULL) {
		printf("Failed to allocate memory for nbreqs list\n");
		shmdt(t);
		return;
	}
	nbreqs = s->nbreqs;

	s->pid = getpid();
	s->running = 1;

	/* Spin till ok_to_send is not set */
	do {
		sleep(1);
	} while (!t->ok_to_send);

	printf("Thread (index: %d pid: %d) starting execution\n",
	       tidx, getpid());

	for (i = 0; i <= MAX_INBUFS; i++)
		s->incntfreq[i] = 0;
	for (i = 0; i <= MAX_OUTBUFS; i++)
		s->outcntfreq[i] = 0;

	memset(nbreqs, 0, sizeof(struct request_list) * MAX_NB_REQUESTS);

	time(&t1);
	srandom(t1);

	do {

		if (thread_cnt == 1) {
			printf("--Sending request[%lu] tag: 0x%x--%s",
			       s->request_count, tag,
			       (ok_to_print) ? "\n" : "\r");
		}

		if (t->resp_order == OCTEON_RESP_NORESPONSE) {

			req_status =
			    noresponse_request(q_no, tag, s, t->dma_mode);
			if (count)
				count--;
			tag++;
			continue;
		}

		if ((t->resp_order == OCTEON_RESP_UNORDERED) &&
		    (t->resp_mode == OCTEON_RESP_BLOCKING)) {

			req_status =
			    unordered_blocking_request(q_no, tag, s,
						       t->dma_mode);
			if (count)
				count--;
			tag++;
			continue;
		}

		if ((t->resp_order == OCTEON_RESP_UNORDERED) &&
		    (t->resp_mode == OCTEON_RESP_NON_BLOCKING)) {

			switch (nbreqs[nbidx].status) {

			case REQ_PEND:
				{
					int r;

					r = check_req_status(nbreqs[nbidx].sr);
					if (r != OCTEON_REQUEST_PENDING) {
						req_status = r;

						if (r == OCTEON_REQUEST_DONE) {
							if (nbreqs
							    [nbidx].outsize >
							    s->maxdatareceived)
								s->maxdatareceived = nbreqs[nbidx].outsize;
// *INDENT-OFF*
						req_status = verify_output(s,nbreqs[nbidx].sr,
							               nbreqs[nbidx].verify_size,
							               nbreqs[nbidx].outsize);
// *INDENT-ON*
						}
						//printf("\r Req %d DONE\n", nbidx);
						free_soft_request(nbreqs
								  [nbidx].sr);
						nbreqs[nbidx].sr = NULL;
						nbreqs[nbidx].status = REQ_NONE;
						s->reqs_pending--;
					}
				}
				break;

			case REQ_NONE:
				req_status =
				    unordered_nonblocking_request(q_no, tag, s,
								  &nbreqs
								  [nbidx],
								  t->dma_mode);
				if (req_status == 0) {
					if (count)
						count--;
					tag++;
					s->reqs_pending++;
				}
				break;

			}

			if (nbreqs[nbidx].status == REQ_PEND)
				nbidx =
				    ((nbidx + 1) ==
				     MAX_NB_REQUESTS ? 0 : (nbidx + 1));

		}

	} while (!req_status && t->ok_to_send && (non_stop || count));

	if (s->reqs_pending) {
		wait_for_unordered_requests(s);
		free(s->nbreqs);
	}

	printf("\nTest Thread %d (pid: %d)stopping now....\n", tidx, getpid());

	s->running = 0;
	shmdt(t);
}

/* find out number of threads based on "num_ioqs" and "num_cpus" */
int get_thread_cnt()
{
	int num_threads;

	printf("Host CPUs = %d , OCTEON IOQs = %d \n", num_cpus, num_ioqs);

#ifdef SEND_TO_ALL_QUEUES
	if ((num_cpus <= 8) && (num_ioqs > 8)) {
		printf
		    ("WARNING: It is not recommended to run the test on all the Qs as No. of CPUs is < 8 \n");
		exit(-EINVAL);
	} else {
		return num_ioqs;
	}
#endif

#if 0
	switch (num_cpus) {
	case 1:
	case 2:
	case 3:
	case 4:
		num_threads = (num_ioqs < 4) ? num_ioqs : 4;
		break;
	case 6:
	case 8:
		num_threads = (num_ioqs < num_cpus) ? num_ioqs : num_cpus;
		break;

	default:
		num_threads = 8;
	}
#else
	/** Limit the num_threads created to
 	 *  4 if num_cpus <= 4  OR
 	 *  8 if num_cpus >  4 
 	 *
 	 *  "num_ioqs" used will be equal to "num_threads"
 	 */
	if (num_cpus <= 4)
		num_threads = (num_ioqs < num_cpus) ? num_ioqs : num_cpus;
	else			/* (num_cpus > 4 ) */
		num_threads = (num_ioqs < num_cpus) ? num_ioqs : 8;
#endif

	return num_threads;

}

int main(int argc, char **argv)
{
	uint32_t q_no = REQ_IQ_NO, count = 0;
	int i, arg_idx = 1, prompt_user = 1;
	char ans = 'y', arg2[8], version[80];
	const char *cvs_tag = "$Name$";
	cpu_set_t cpu_set;	/* cpu_set bit mask. */

	OCTEON_RESPONSE_ORDER resp_order = TEST_RESP_ORDER;
	OCTEON_RESPONSE_MODE resp_mode = TEST_RESP_MODE;
	OCTEON_DMA_MODE dma_mode = TEST_DMA_MODE;

	cavium_parse_cvs_string(cvs_tag, version, sizeof(version));
	printf("Octeon Test utility version: %s\n", version);

	if (argc > 1) {
		char *endptr;
		oct_id = (int)(long int)strtol(argv[arg_idx], &endptr, 10);
		if (strlen(endptr)) {
			printf("Invalid octeon_id: %s\n", argv[arg_idx]);
			print_usage();
			return -EINVAL;
		}
		arg_idx++;
	}

	if (octeon_initialize()) {
		printf("oct_req: Could not find octeon device\n");
		return -ENODEV;
	}

	while (arg_idx < argc) {
		if (strlen(argv[arg_idx]) > 7) {
			printf("Badly formed options: %s\n", argv[arg_idx]);
			print_usage();
			return -EINVAL;
		}

		memset(arg2, 0, 8);
		strncpy(arg2, argv[arg_idx++], 7);
		if (arg2[0] == '-') {
			i = 1;
			while (i < strlen(arg2)) {
				switch (arg2[i]) {
				case 'b':
					resp_mode = OCTEON_RESP_BLOCKING;
					break;
				case 'u':
					resp_order = OCTEON_RESP_UNORDERED;
					break;
				case 'd':
					dma_mode =
					    get_dma_mode(argv[arg_idx++]);
				case 's':
					ok_to_print = 0;
					break;
				case 'I':
					inbuf_size = atoi(argv[arg_idx++]);
					break;
				case 'O':
					outbuf_size = atoi(argv[arg_idx++]);
					break;
				case 'y':
					prompt_user = 0;
					break;
				case 'q':
					q_no = atoi(argv[arg_idx++]);
					break;
				case 'h':
					print_usage();
					return 0;
				default:
					printf("Unknown option: %c\n", arg2[i]);
					return -EINVAL;
				}
				i++;
			}
		} else {
			i = 0;
			while (isxdigit((int)arg2[i]) && (i++ < strlen(arg2))) ;
			if (i == strlen(arg2)) {
				sscanf(arg2, "%d", &count);
				if (arg_idx < argc) {
					printf("Invalid arguments found\n");
					print_usage();
					return -EINVAL;
				}
				break;
			} else {
				printf("Badly formed option list : %s\n", arg2);
				print_usage();
				return -EINVAL;
			}
		}
	}

	if (argc == 1) {
		print_usage();
		return 0;
	}

	printf("\n\nStarting operation %s with\n",
	       (ok_to_print) ? "" : "in silent mode");
	printf("Octeon id: %d\n", oct_id);
	print_test_setup(dma_mode, resp_order, resp_mode);
	if (count)
		printf("  for %d requests\n", count);

	if (prompt_user) {
		printf("\n Continue (Y/N): ");
		ans = getchar();
	}

	if (ans != 'y' && ans != 'Y') {
		printf("\nQuitting!!\n");
		return 0;
	}

	indata_size = (inbuf_size * MAX_INBUFS);
	outdata_size = (outbuf_size * MAX_OUTBUFS);

	/* on cn73xx/cn78xx, DLENGSZ=1 is invalid for Scatter-Gather/Gather mode */
#ifdef ENABLE_OCTEON_III
	if ((dma_mode == OCTEON_DMA_GATHER ||
	     dma_mode == OCTEON_DMA_SCATTER_GATHER) && (MAX_INBUFS < 2)) {
		printf
		    ("For Scatter-Gather / Gather, the min input buffers should be 2 for CN73XX / CN78XX \n\n");
		return -EINVAL;
	}
#endif

	if (resp_order != OCTEON_RESP_NORESPONSE) {
		/* for un ordered requests */
		if (validate_test_params(dma_mode)) {
			exit(-EINVAL);
		}
	} else {
		if (resp_mode == OCTEON_RESP_BLOCKING) {
			printf
			    ("\nNORESPONSE requests don't support blocking mode\n");
			exit(-EINVAL);
		}
		/* for NORESPONSE requests */
		if (dma_mode == OCTEON_DMA_SCATTER
		    || dma_mode == OCTEON_DMA_SCATTER_GATHER) {
			printf
			    (" \n NORESPONSE requests don't support Scatter / Scatter_Gather dma mode \n");
			exit(-EINVAL);
		}

		if ((dma_mode == OCTEON_DMA_DIRECT)
		    && (indata_size > OCT_MAX_DIRECT_INPUT_DATA_SIZE)) {
			printf
			    ("\n Input size ( %d ) exeeds the max Direct dma size ( %d ) \n",
			     indata_size, OCT_MAX_DIRECT_INPUT_DATA_SIZE);
			exit(-EINVAL);

		}

		if ((dma_mode == OCTEON_DMA_GATHER)
		    && (indata_size > OCT_MAX_GATHER_DATA_SIZE)) {
			printf
			    ("\n Input size ( %d ) exeeds the max Gather dma size ( %d ) \n",
			     indata_size, OCT_MAX_GATHER_DATA_SIZE);
			exit(-EINVAL);
		}

	}

	if (count)
		non_stop = 0;

	shmid = shmget(0, sizeof(struct test), IPC_CREAT | IPC_EXCL);
	if (shmid == -1) {
		printf("Failed to allocate shared memory\n");
		exit(-ENOMEM);
	}
	printf("Shared memory id is %d\n", shmid);

	t_main = (struct test *)shmat(shmid, NULL, 0);
	if ((unsigned long)t_main == -1) {
		printf("Failed to attach shared memory\n");
		shmctl(shmid, IPC_RMID, NULL);
		return -ENOMEM;
	}
	__print("Attached shared memory at %p in main thread\n", t_main);

	memset(t_main, 0, sizeof(struct test));

	prev_sig_handler = signal(signal_to_catch, signal_handler);

	t_main->resp_order = resp_order;
	t_main->resp_mode = resp_mode;
	t_main->dma_mode = dma_mode;

	/* get the total initilized queues from the kernel driver */
	num_ioqs = octeon_get_num_ioqs(oct_id);

	/* get the available Host CPU cores */
	num_cpus = get_nprocs();

	/* find out number of threads based on "num_ioqs" and "num_cpus" */
	thread_cnt = get_thread_cnt();

#ifndef SEND_TO_ALL_QUEUES
	if (q_no < num_ioqs)
		thread_cnt = 1;
#endif

#if 0
#ifdef SEND_TO_ALL_QUEUES
	thread_cnt = get_thread_cnt();
	printf("Sending to all the enabled queues..\n");
#else
	if (q_no > num_ioqs)
		thread_cnt = get_thread_cnt();
	else
		thread_cnt = 1;
#endif
#endif

	for (i = 0; i < thread_cnt; i++) {
		pid_t pid = fork();

		switch (pid) {
		case 0:
			/* Start executing thread in child. */
			__print("In Child: Calling oct_request_thread()\n");

			/* binding each thread to a different CPU core */
			/* Initialize it all to 0, i.e. no CPUs selected. */
			CPU_ZERO(&cpu_set);
			/* set the bit that represents the core. */
			CPU_SET(i % num_cpus, &cpu_set);
			sched_setaffinity(0, sizeof(cpu_set_t), &cpu_set);

			if (thread_cnt == 1) {
				if (num_ioqs == 1)	/* Adjusting the queue no.when only 1 IOQ is enabled. */
					q_no = 0;
				oct_request_thread(q_no, count, i);
			} else {
				oct_request_thread(i, count, i);
			}
			exit(0);

		case -1:
			printf("Fork failed. Killing all processes\n");
			while (i--)
				kill(t_main->perthread[i].pid, signal_to_catch);
			octeon_shutdown();
			exit(-ENOMEM);

		default:
			t_main->perthread[i].pid = pid;
		}
	}

	t_main->ok_to_send = 1;
	printf(" --- Press Ctrl-C to stop the test ---\n\n");

	t_main->main_pid = getpid();
	printf("Main thread pid: %d\n", t_main->main_pid);

	sleep(2);
	wait_for_thread_completion(t_main, 0);

	printf("\nMain thread stopping... \n");

	add_thread_stats(t_main);
	print_test_stats(t_main);

	shmdt(t_main);
	/* mark the shared memory segment for deletion during the exit */
	shmctl(shmid, IPC_RMID, NULL);

	signal(signal_to_catch, prev_sig_handler);

	return 0;
}

/* $Id: oct_req.c 141410 2016-06-30 14:37:41Z mchalla $ */
