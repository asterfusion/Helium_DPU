/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2021, Marvell
 */

#include <stdio.h>
#include <pcap.h>
#include <stdlib.h>

int main(int argc, char **argv)
{
	unsigned int packet_count = 0;
	char errbuf[PCAP_ERRBUF_SIZE];
	struct pcap_pkthdr header;
	const u_char *packet;
	pcap_t *handle;

	if (argc < 2)
		return -1;

	handle = pcap_open_offline(argv[1], errbuf);

	if (handle == NULL)
		return -2;

	while ((packet = pcap_next(handle, &header)))
		packet_count++;

	pcap_close(handle);

	printf("%u\n", packet_count);
	return 0;
}
