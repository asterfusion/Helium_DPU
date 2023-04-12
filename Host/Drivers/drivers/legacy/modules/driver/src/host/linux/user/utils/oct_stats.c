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

#include <ctype.h>
#include <cavium_sysdep.h>
#include <cavium_release.h>
#include <octeon_stats.h>
#include <octeon_user.h>

#ifdef USE_CURSES
#include "curses.h"
#define  oct_print   printw
#else
#define  oct_print   printf
#endif

#define DISPLAY_IQ_INFO        0x0001
#define DISPLAY_DROQ_INFO      0x0002

/* USE_BUFPOOL is not supported */
#ifdef USE_BUFPOOL
#define DISPLAY_BUFPOOL_INFO   0x0010
#endif

#define DISPLAY_ALL_INFO       0x001f
#define DISPLAY_RECURSIVE      0x1000
#define DISPLAY_DEFAULT     (DISPLAY_ALL_INFO | DISPLAY_RECURSIVE)

#define  MAX_DMAQS  2

#define  AVG_INTERVAL  10

uint32_t oct_id = 0, verbose = 0, running_only = 0;
/*Globals used to store IOQ range values*/
uint32_t imin = 0, imax = 0, omin = 0, omax = 0;
uint32_t iq_range_specified = 0, oq_range_specified = 0;

uint64_t last_input_pkts[MAX_IQS] = {
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
};

uint64_t last_input_bytes[MAX_IQS] = {
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
};

uint64_t last_output_pkts[MAX_OQS] = {
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
};

uint64_t last_output_bytes[MAX_OQS] = {
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
};

/* Average over the last AVG_INTERVAL seconds */
uint64_t avg_op_bytes[AVG_INTERVAL] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };

int avg_op_idx = 0, avg_op_crossover = 0;

int first_loop = 1;

void get_octeon_stats(int, int, int);
void print_octeon_stats(int oct_id, oct_stats_t * buf, int disp_flag);

/* Print help information. */
void print_usage()
{
	const char *oct_stats_cvs_tag = "$Name$";
	char oct_stats_version[80];

	cavium_parse_cvs_string(oct_stats_cvs_tag, oct_stats_version, 80);
	oct_print("\nOcteon Statistics Utility [Cavium Networks] %s\n\n",
		  oct_stats_version);
#ifdef USE_BUFPOOL
	oct_print
	    ("\n  Usage: oct_stat <oct_id> [ -h | [ -iocdb | -a | -r ]] [-I start end] [-O start end][display_interval]\n");
#endif
	oct_print
	    ("\n  Usage: oct_stat <oct_id> [ -h | [ -iocd | -a | -r ]] [-I start end] [-O start end][display_interval]\n");
	oct_print("         where oct_id is 0 for first Octeon device\n");
	oct_print
	    ("  If no options are given, all statistics are displayed at 1 second interval\n");
	oct_print("  -i : display input  queue (IQ) statistics\n");
	oct_print("  -o : display output queue (DROQ) statistics\n");
#ifdef USE_BUFPOOL
	oct_print("  -b : display buffer pool statistics\n");
#endif
	oct_print("  -a : display statistics for all queues\n");
	oct_print("  -r : refresh statistics at regular intervals\n");
	oct_print("  -I : range of the input queues to be displayed\n");
	oct_print("  -O : range of the output queues to be displayed\n");
	oct_print("       Maximum 12 input and 12 output queues are allowed\n");
	oct_print("       To view from 1 to 12 ex.-I/-O 1 12\n");
	oct_print("  -v : verbose output\n");
	oct_print("  -h : print this menu\n");
}

/* Pause for key stroke before termination. */
void oct_stats_terminate(void)
{

#ifdef USE_CURSES
	oct_print("Press any key to exit...\n");
	refresh();
	getchar();
	endwin();
#else
	printf("Press RETURN to exit ..\n");
	getchar();
#endif
	exit(0);
}

void print_usage_and_terminate()
{
	print_usage();
	oct_stats_terminate();
}

int
parse_ioq_range_args(const char *argv[], int *arg_idx, uint32_t * min,
		     uint32_t * max)
{
	/*This if() rejects arguments with out space and 
	   with wrong character after -I/-O. Ex:-I12,-O15,-Ia etc,. */
	if (argv[*arg_idx][0] == '-'
	    && (argv[*arg_idx][1] == 'I' || argv[*arg_idx][1] == 'O')
	    && (strlen(argv[*arg_idx]) > 2)) {
		oct_print("Error while parsing I/O queue range parameters\n");
		print_usage_and_terminate();
	}

	if (argv[*arg_idx + 1] != NULL
	    && (argv[*arg_idx + 1][0] >= '0' && argv[*arg_idx + 1][0] <= '9')) {
		*min = (uint32_t) atoi(argv[*arg_idx + 1]);
		if (*min < 0 || *min > 63) {
			oct_print("Invalid start argument for queue range\n");
			print_usage_and_terminate();
		}
		(*arg_idx)++;
	} else {
		oct_print("Invalid range for queue statistics\n");
		print_usage_and_terminate();
	}
	if (argv[*arg_idx + 1] != NULL
	    && (argv[*arg_idx + 1][0] >= '0' && argv[*arg_idx + 1][0] <= '9')) {
		*max = (uint32_t) atoi(argv[*arg_idx + 1]);
		if (*max < 0 || *max > 63) {
			oct_print("Invalid end argument for queue range\n");
			print_usage_and_terminate();
		}
		(*arg_idx)++;
	} else
		/*-1 is to know that start value is provided and not end*/
		*max = -1;

	if (*max - *min >= 12 && *max != -1) {
		oct_print("Invalid range for queue\n");
		print_usage_and_terminate();
	}

	/*start range is provide but not end. This case start and end should be same */
	if (*max == -1)
		*max = *min;

	(*arg_idx)++;

	/*return sucess to indicate range arguments are found */
	return 0;
}

int main(int argc, const char *argv[])
{
	int arg_idx, disp_flag = 0, i, sleep_time = 1;
	char arg2[8];

#ifdef USE_CURSES
	initscr();
#endif

	/* Make sure the arguments are in order and are valid. */
	if (argc == 1)
		print_usage_and_terminate();

	if (!strncmp(argv[1], "-h", 2))
		print_usage_and_terminate();

	arg_idx = 1;
	if (argc > 1) {
		char *endptr;
		oct_id = (int)(long int)strtol(argv[arg_idx], &endptr, 10);
		if (strlen(endptr)) {
			oct_print("Invalid octeon_id: %s\n", argv[arg_idx]);
			print_usage_and_terminate();
		}
		arg_idx++;
	} else {
		print_usage_and_terminate();
	}

	/* Parse the arguments and select the type of stats to display. */
	while (arg_idx < argc) {

		if (argv[arg_idx][0] == '-' && argv[arg_idx][1] == 'I') {
			if (parse_ioq_range_args
			    (&argv[0], &arg_idx, &imin, &imax) == 0)
				iq_range_specified = 1;
			continue;
		}
		if (argv[arg_idx][0] == '-' && argv[arg_idx][1] == 'O') {
			if (parse_ioq_range_args
			    (&argv[0], &arg_idx, &omin, &omax) == 0)
				oq_range_specified = 1;
			continue;
		}

		if (strlen(argv[arg_idx]) > 7) {
			oct_print("Badly formed option list: %s\n",
				  argv[arg_idx]);
			print_usage_and_terminate();
		}
		strncpy(arg2, argv[arg_idx++], 7);
		if (arg2[0] == '-') {
			i = 1;
			while (i < strlen(arg2)) {
				switch (arg2[i]) {
				case 'i':
					disp_flag |= DISPLAY_IQ_INFO;
					break;
				case 'o':
					disp_flag |= DISPLAY_DROQ_INFO;
					break;
#ifdef USE_BUFPOOL
				case 'b':
					disp_flag |= DISPLAY_BUFPOOL_INFO;
					break;
#endif
				case 'a':
					disp_flag |= DISPLAY_ALL_INFO;
					running_only = 1;
					break;
				case 'r':
					disp_flag |= DISPLAY_RECURSIVE;
					break;
				case 'v':
					verbose = 1;
					break;
				case 'h':
					print_usage_and_terminate();
					break;
				default:
					oct_print("Unknown option: %c\n",
						  arg2[i]);
					print_usage_and_terminate();
					break;
				}
				i++;
			}
		} else {
			i = 0;
			while (isxdigit((int)arg2[i]) && (i++ < strlen(arg2))) ;
			if (i == strlen(arg2)) {
				sscanf(arg2, "%d", &sleep_time);
				break;
			} else {
				oct_print("Badly formed option list : %s\n",
					  arg2);
				print_usage_and_terminate();
			}
		}
	}

	if (argc == 2) {
		disp_flag = DISPLAY_DEFAULT;
		running_only = 1;
	}

	if (!disp_flag || disp_flag == DISPLAY_RECURSIVE) {
		disp_flag = DISPLAY_DEFAULT;
		running_only = 1;
	}
#ifdef USE_CURSES
	/* If recursive mode stats display is used with curses, getch() should
	   not wait for keystroke. */
	if (disp_flag & DISPLAY_RECURSIVE)
		nodelay(stdscr, TRUE);
#endif

	/* Loop to get stats from Octeon driver and print on screen. */
	get_octeon_stats(oct_id, disp_flag, sleep_time);

#ifdef USE_CURSES
	if (disp_flag & DISPLAY_RECURSIVE)
		nodelay(stdscr, FALSE);
	endwin();
#endif

	return 0;
}

/* Loop to get stats from Octeon driver and print on screen. */
void get_octeon_stats(int oct_id, int disp_flag, int sleep_time)
{
	oct_stats_t *stats;

	if (octeon_initialize()) {
		oct_print("%s: FAILED to open octeon device file\n",
			  __FUNCTION__);
		oct_stats_terminate();
	}

	/* Allocate a buffer to collect stats from the driver. */
	stats = malloc(OCT_STATS_SIZE);
	if (!stats) {
		oct_print("Cannot allocate memory to read Octeon stats\n");
		octeon_shutdown();
		oct_stats_terminate();
	}

	/* Now the loop begins. */
	do {
#ifdef USE_CURSES
		int ch;
		clear();
#endif
		if (octeon_get_stats(oct_id, stats))
			break;

		/* Verify that we have the correct magic value. */
		if (stats->magic != CAVIUM_STATS_MAGIC) {
			oct_print("Incorrect magic from octeon: 0x%llx\n",
				  CVM_CAST64(stats->magic));
			oct_stats_terminate();
		}

		/* Print the stats. */
		print_octeon_stats(oct_id, stats, disp_flag);

		/* User can quit now by hitting a key. */
#ifdef USE_CURSES
		oct_print("Press any key to exit....");
		refresh();
		ch = getch();
		if (ch != ERR) {
			break;
		}
#else
		if (disp_flag & DISPLAY_RECURSIVE)
			printf("Press CTRL-C to exit....\n");
#endif

	} while ((disp_flag & DISPLAY_RECURSIVE) && (!sleep(sleep_time)));

}

#ifdef USE_BUFPOOL
void print_octeon_bufpool_stats(oct_stats_t * buf)
{
	int i;

	oct_print("\n--Buffer Pool----   ");
	for (i = 0; i < BUF_POOLS; i++)
		oct_print(" Pool %d ", i);
	oct_print("\n  Max  buffers   :  ");
	for (i = 0; i < BUF_POOLS; i++)
		oct_print(" %5d  ", buf->bufpool[i].max_count);
	oct_print("\n  allocated bufs :  ");
	for (i = 0; i < BUF_POOLS; i++)
		oct_print(" %5d  ", buf->bufpool[i].alloc_count);
	oct_print("\n  fragmented bufs:  ");
	for (i = 0; i < BUF_POOLS; i++)
		oct_print(" %5d  ", buf->bufpool[i].frag_count);
	oct_print("\n  other pools    :  ");
	for (i = 0; i < BUF_POOLS; i++)
		oct_print(" %5d  ", buf->bufpool[i].other_pool_count);
	oct_print("\n");
}
#endif

void print_octeon_iq_stats(oct_stats_t * buf)
{
	int i;
	static int j = 0;
	uint64_t total_bytes = 0ull, total_pkts = 0ull, diff_bytes =
	    0ull, diff_pkts = 0ull;

	oct_print("\n IQ ");
	oct_print(" \tTotal Pkts \tDropped Pkts \tLast Received Pkts");
	oct_print(" \tTotal Bytes \tLast Received Bytes");
	oct_print(" \tGather entries\n");

	for (i = 0; i < MAX_IQS; i++) {
		/* Always print stats for the first queue. 
		   Rest are printed only if any packets were sent on them. */
		if (buf->iq[i].instr_posted == 0 && i)
			continue;

		diff_bytes = 0ull;
		diff_pkts = 0ull;
		diff_pkts = buf->iq[i].instr_processed - last_input_pkts[i];
		last_input_pkts[i] = buf->iq[i].instr_processed;

		diff_bytes = buf->iq[i].bytes_sent - last_input_bytes[i];
		last_input_bytes[i] = buf->iq[i].bytes_sent;
		total_pkts += diff_pkts;
		total_bytes += diff_bytes;

		if (iq_range_specified && (!(imin <= i) || !(i <= imax))
		    && (i != 0)) {
			continue;
		}
		oct_print(" %2d ", i);
		oct_print(" \t%8llu \t%8llu \t%8llu",
			  CVM_CAST64(buf->iq[i].instr_posted),
			  CVM_CAST64(buf->iq[i].instr_dropped),
			  CVM_CAST64(diff_pkts));

		oct_print(" \t\t%8llu \t\t%8llu",
			  CVM_CAST64(buf->iq[i].bytes_sent),
			  CVM_CAST64(diff_bytes));

		oct_print("\t%8llu", CVM_CAST64(buf->iq[i].sgentry_sent));

		oct_print("\n");
	}
	oct_print("\n");

	if (!verbose)
		return;

	if (total_pkts && j) {
		oct_print
		    ("\n(Last all q's) Mbits: %llu Pkts: %llu Avg. Payload: %llu",
		     (CVM_CAST64(total_bytes) * 8 / 1000000),
		     CVM_CAST64(total_pkts),
		     CVM_CAST64(total_bytes / total_pkts));
	} else {
		j++;
	}
	oct_print
	    ("\n__________________________________________________________________________\n");

}

void print_octeon_droq_stats(oct_stats_t * buf)
{
	int i;
	static int j = 0;
	uint64_t total_bytes = 0ull, total_pkts = 0ull, diff_bytes =
	    0ull, diff_pkts = 0ull, pkts_dropped = 0ull;

	oct_print(" \n DROQ ");
	oct_print(" \tTotal Pkts \tLast Received Pkts");
	oct_print(" \tTotal Bytes \tLast Received Bytes\n");

	for (i = 0; i < MAX_OQS; i++) {
		/* Always print stats for the first queue. 
		   Rest are printed only if any packets were received on them. */
		if (buf->droq[i].pkts_received == 0 && i)
			continue;

		diff_bytes = 0ull;
		diff_pkts = 0ull;
		pkts_dropped = 0ull;

		diff_pkts = buf->droq[i].pkts_received - last_output_pkts[i];
		last_output_pkts[i] = buf->droq[i].pkts_received;

		diff_bytes = buf->droq[i].bytes_received - last_output_bytes[i];
		last_output_bytes[i] = buf->droq[i].bytes_received;

		/* Used in calculation below. */
		total_bytes += diff_bytes;
		total_pkts += diff_pkts;

		pkts_dropped += buf->droq[i].dropped_nodispatch;
		pkts_dropped += buf->droq[i].dropped_nomem;
		pkts_dropped += buf->droq[i].dropped_toomany;

		if (oq_range_specified && (!(omin <= i) || !(i <= omax))
		    && i != 0) {
			continue;
		}
		oct_print(" %2d ", i);
		oct_print(" \t%8llu \t%8llu",
			  CVM_CAST64(buf->droq[i].pkts_received),
			  CVM_CAST64(diff_pkts));
		oct_print(" \t\t%8llu \t%8llu\n",
			  CVM_CAST64(buf->droq[i].bytes_received),
			  CVM_CAST64(diff_bytes));

		if (pkts_dropped) {
			oct_print("Pkts dropped:  ");
			oct_print
			    ("(No dispatch: %llu | No memory: %llu | Too many: %llu\n",
			     CVM_CAST64(buf->droq[i].dropped_nodispatch),
			     CVM_CAST64(buf->droq[i].dropped_nomem),
			     CVM_CAST64(buf->droq[i].dropped_toomany));
		}
	}

	if (!verbose)
		goto droq_print_end;

	if (total_pkts && j) {
		oct_print
		    ("\n(Last all q's) Mbits: %llu Pkts: %llu Avg. Payload: %llu",
		     (CVM_CAST64(total_bytes) * 8 / 1000000),
		     CVM_CAST64(total_pkts),
		     CVM_CAST64(total_bytes / total_pkts));
	} else {
		j++;
	}

	avg_op_bytes[avg_op_idx] = total_bytes;
	if (++avg_op_idx == AVG_INTERVAL) {
		avg_op_crossover = 1;
		avg_op_idx = 0;
	}

	/* Ignore the first reading for calculating the extended average. */
#if 0
	if (first_loop) {
		avg_op_bytes[0] = 0;
		avg_op_idx = 0;
		first_loop = 0;
	} else {
		for (i = 0, total_bytes = 0; i < AVG_INTERVAL; i++)
			total_bytes += avg_op_bytes[i];
		total_bytes =
		    total_bytes /
		    ((avg_op_crossover) ? AVG_INTERVAL : avg_op_idx);
		oct_print("(%d-Second Average: %llu bytes)", AVG_INTERVAL,
			  CVM_CAST64(total_bytes));
	}
#endif

droq_print_end:
	oct_print("\n");
}

void print_octeon_stats(int oct_id, oct_stats_t * buf, int disp_flag)
{
	time_t stats_time = time(NULL);
	char time_string[40];

	strcpy(time_string, ctime(&stats_time));
	oct_print("Octeon %d statistics\t\t\t\t%s\n", oct_id, time_string);

	oct_print("Device state: %s\n", buf->dev_state);

#ifdef USE_BUFPOOL
	if (disp_flag & DISPLAY_BUFPOOL_INFO) {
		if (buf->components & OCTEON_BUFFER_POOL_STATS_ON)
			print_octeon_bufpool_stats(buf);
		else if (!(running_only || verbose))
			oct_print
			    ("\nDRIVER NOT COMPILED WITH BUFPOOL OPTION\n");
	}
#endif

	if (disp_flag & DISPLAY_IQ_INFO) {
		print_octeon_iq_stats(buf);
	}

	if (disp_flag & DISPLAY_DROQ_INFO) {
		print_octeon_droq_stats(buf);
	}

	oct_print
	    ("__________________________________________________________________________\n");
}

/* $Id: oct_stats.c 141712 2016-07-08 06:55:10Z mchalla $ */
