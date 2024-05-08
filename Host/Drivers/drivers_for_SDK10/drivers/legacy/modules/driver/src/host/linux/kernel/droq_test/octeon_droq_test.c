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
#include "cavium_kernel_defs.h"
#include "cavium_release.h"
#include "octeon-opcodes.h"

MODULE_AUTHOR("Cavium Networks");
MODULE_LICENSE("Cavium Networks");

/* Enable this to print additional information about each received packet. */
/* #define DEBUG_MODE_ON */

/* Enable this to register dispatch function for both DROQ test opcodes. */
//#define DROQ_TEST_SEC_OPCODE

#define OCTEON_ID      0

/* The test application does not expect a buffer count greater than 64. */
#define MAX_BUFCOUNT   64

/* Count of DROQ packets received */
unsigned long droq_pkts_recvd = 0;

uint64_t total_data = 0;

/* Max data received */
unsigned long droq_min_data = -1;

/* Max data received */
unsigned long droq_max_data = 0;

/* Count of buffers received */
unsigned long droq_bufcount_freq[MAX_BUFCOUNT + 2];

unsigned long droq_print_jiffies = 0;

/* Store the pid's here. cleanup_module needs them */
/* For KERNEL_VERSION < 2,6,18, we store the pid here and the kthread task ptr
for later releases. */
unsigned long droq_test_pid[1];
int droq_test_ok_to_run, droq_test_exit = 0;

int droq_test_dispatch(octeon_recv_info_t * recv_info, void *arg)
{

#ifndef DROQ_TEST_REUSE_BUFS
	int cnt;
#endif

	octeon_recv_pkt_t *recv_pkt = recv_info->recv_pkt;

	total_data += recv_pkt->length;

	if (recv_pkt->length < droq_min_data)
		droq_min_data = recv_pkt->length;

	if (recv_pkt->length > droq_max_data)
		droq_max_data = recv_pkt->length;

	if (recv_pkt->buffer_count > MAX_BUFCOUNT)
		droq_bufcount_freq[MAX_BUFCOUNT + 1]++;
	else
		droq_bufcount_freq[recv_pkt->buffer_count]++;

	/* Limit the prints to 1 per second */
	if (jiffies <= (droq_print_jiffies + HZ))
		goto end_dispatch;

	droq_print_jiffies = jiffies;

#ifdef   DEBUG_MODE_ON
	printk("\n--- droq_dispatch pkt #%lu---\n", droq_pkts_recvd);
	printk("opcode: %x ", recv_pkt->resp_hdr.opcode);
	printk("request_id: %x ", recv_pkt->resp_hdr.request_id);
	printk("octeon_id: %d ", recv_pkt->octeon_id);
	printk("length: %d ", recv_pkt->length);
	printk("buf_count: %d\n", recv_pkt->buffer_count);
#endif

// *INDENT-OFF*
#define VERIFY_DATA //Depends on CVMCS_SIGN_DATA flag in base fw cvmcs-test.h
#ifdef VERIFY_DATA
    {  
        int i = 0, j =0, size =0;
        uint8_t *data = NULL;
        uint32_t pkt_val = 0;
        int len = 0;
        for(i = 0; i < recv_pkt->buffer_count; i++) {
            data = (uint8_t *)(((struct sk_buff*)recv_pkt->buffer_ptr[i])->data);
            size = recv_pkt->buffer_size[i];
#ifdef BUFPTR_ONLY_MODE
		/* In BUF ptr mode, Data starts at recv_pkt->offset for the first buffer
		 * If the buffer data has to be accessed in sk_buff format, it's data & tail 
		 * pointers need to be adjusted by recv_pkt->offset value as below..
		 *
		 * struct sk_buff *nicbuf = (struct sk_buff*)recv_pkt->buffer_ptr[0];
		 * nicbuf->data += recv_pkt->offset; 
		 * nicbuf->tail += recv_pkt->offset;
		 */
			if(!i)
				data += recv_pkt->offset;
#endif
			for(j = 0; j < size; j++) {
				if( pkt_val !=  *(data + j)) 
				{
					printk("MISMATCH for len: %d @ buffer: %d, offset: %d, expected: %d present: %d\n", 
						recv_pkt->length, i, j, pkt_val, *(data + j));
					goto PKT_DUMP;
				}
				pkt_val = (pkt_val + 1) & 0xff;
				len++;
				if(len == recv_pkt->length) {
					cavium_print(PRINT_DEBUG, "Data Matches for len: %d\n", recv_pkt->length);
					goto end_dispatch;
				}
			}
		}
	}


PKT_DUMP:
   {
      int        i;
      uint8_t    *data;
      uint32_t    size;
      /* Enable this section if you want to print the buffer 
         contents. Note that for big packets and for tests with a high
         packet frequency, enabling this section will cause the kernel
         to get busy printing all the time. 
      */
      for(i = 0 ; i < recv_pkt->buffer_count; i++) {
	      data = (uint8_t *)(((struct sk_buff*)recv_pkt->buffer_ptr[i])->data);
	      size = recv_pkt->buffer_size[i];
#ifdef BUFPTR_ONLY_MODE
	      if(!i) { /* For the first buffer, skip droq_info meta data */
		      data += recv_pkt->offset;
	      }
#endif
	      printk("Data buffer #%d\n", i);
	      cavium_error_print(data, size);
      }
   }
#endif
// *INDENT-ON*

end_dispatch:
/* Done for IOMMU: the buffers are re-used, so don't free them */
#ifndef DROQ_TEST_REUSE_BUFS
	for (cnt = 0; cnt < recv_pkt->buffer_count; cnt++) {
		free_recv_buffer(recv_pkt->buffer_ptr[cnt]);
	}
#endif

	octeon_free_recv_info(recv_info);
	droq_pkts_recvd++;

	return 0;
}

void print_bufcount_freq(void)
{
	int i;

	printk("Buffer count received [ bufcount/times recvd] \n");
	for (i = 0; i <= MAX_BUFCOUNT; i++) {
		if (droq_bufcount_freq[i])
			printk(" [ %d/%lu ] ", i, droq_bufcount_freq[i]);
	}
	if (droq_bufcount_freq[i])
		printk(" [ others/%lu ] ", droq_bufcount_freq[i]);
	printk("\n");
}

static uint32_t BIG_DIV(uint64_t total, uint64_t val)
{
	uint32_t result = 0;

	while ((val * result) < total)
		result++;
	return result;
}

static int droq_test_thread(void *arg)
{
	int i;
	unsigned long my_thread_id = *((unsigned long *)arg);
	int display_ticks = 0;

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,0)
	daemonize();
	reparent_to_init();
#endif

	printk("DROQ_TEST: Octeon DROQ test thread start OK\n");
	for (i = 0; i <= (MAX_BUFCOUNT + 1); i++) {
		droq_bufcount_freq[i] = 0;
	}
	if (octeon_register_dispatch_fn
	    (OCTEON_ID, DROQ_PKT_OP1, droq_test_dispatch, NULL)) {
		printk("DROQ_TEST: Registration failed for opcode: %x\n",
		       DROQ_PKT_OP1);
		goto end_droq_test;
	}
	printk("DROQ_TEST: Registered dispatch for opcode %x\n", DROQ_PKT_OP1);

#ifdef DROQ_TEST_SEC_OPCODE
	if (octeon_register_dispatch_fn
	    (OCTEON_ID, DROQ_PKT_OP2, droq_test_dispatch, NULL)) {
		printk("DROQ_TEST: Registration failed for opcode: %x\n",
		       DROQ_PKT_OP2);
		octeon_unregister_dispatch_fn(OCTEON_ID, DROQ_PKT_OP1);
		goto end_droq_test;
	}
	printk("DROQ_TEST: Registered dispatch for opcode %x\n", DROQ_PKT_OP2);
#endif
	do {

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,18)
		if (signal_pending(current)) {
			printk("OCTEON_TEST: Thread[%lu] stopping now\n",
			       my_thread_id);
			break;
		}
#else
		if (kthread_should_stop()) {
			printk("OCTEON_TEST: Thread[%lx] stopping now\n",
			       my_thread_id);
			break;
		}
#endif
		cavium_sleep_timeout(CAVIUM_TICKS_PER_SEC);
		display_ticks++;
		if (display_ticks >= 20) {
			printk("Packets Recvd: %lu maxdata: %lu mindata: %lu\n",
			       droq_pkts_recvd, droq_max_data, droq_min_data);
			display_ticks = 0;
		}
	} while (droq_test_ok_to_run);

	octeon_unregister_dispatch_fn(OCTEON_ID, DROQ_PKT_OP1);
	octeon_unregister_dispatch_fn(OCTEON_ID, DROQ_PKT_OP2);

end_droq_test:
	printk("DROQ TEST: Received %lu packets\n", droq_pkts_recvd);
	printk("Total Data Bytes: %llu  (Max : %lu, Min: %lu Avg: %u)\n",
	       CVM_CAST64(total_data), droq_max_data, droq_min_data,
	       BIG_DIV(total_data, droq_pkts_recvd));
	print_bufcount_freq();
	printk("DROQ TEST:  thread stopped!!!\n");
	droq_test_exit = 1;
	return 0;
}

int init_module()
{
	const char *droq_test_cvs_tag = "$Name$";
	char droq_test_version[80];

	droq_test_ok_to_run = 1;

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,18)
	droq_test_pid[0] = (unsigned long)
	    kernel_thread(droq_test_thread, &droq_test_pid[0],
			  CLONE_FS | CLONE_FILES | CLONE_SIGHAND);
	if (droq_test_pid[0] < 0)
#else
	droq_test_pid[0] = (unsigned long)
	    kthread_run(droq_test_thread, &droq_test_pid[0], "Oct DROQ Test");
	if (((cavium_ostask_t *) droq_test_pid[0]) == NULL)
#endif
	{
		printk("Failed to create test thread\n");
		return -ENOMEM;
	}
	cavium_parse_cvs_string(droq_test_cvs_tag, droq_test_version, 80);
	cavium_print_msg("Octeon Output Queue test application (%s) loaded\n",
			 droq_test_version);
	return 0;
}

void cleanup_module()
{
#if LINUX_VERSION_CODE > KERNEL_VERSION(2,6,0)
	/* SIGINT and SIGHUP both need to be disallowed for the time when 
	   we send out delete instructions. */
	disallow_signal(SIGINT);
	disallow_signal(SIGHUP);
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,18)
	if (droq_test_pid[0] >= 0) {
		kill_proc((pid_t) droq_test_pid[0], SIGTERM, 1);
	}
#else
	if (droq_test_pid[0]) {
		kthread_stop((cavium_ostask_t *) droq_test_pid[0]);
	}
#endif

	droq_test_ok_to_run = 0;

	while (!droq_test_exit)
		cavium_schedule();
}

/* $Id: octeon_droq_test.c 170605 2018-03-20 15:19:22Z vvelumuri $ */
