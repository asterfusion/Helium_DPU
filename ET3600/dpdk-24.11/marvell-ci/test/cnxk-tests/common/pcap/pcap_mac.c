/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2021, Marvell
 */

#include <stdio.h>
#include <pcap.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/if_ether.h>

int main(int argc, char **argv)
{
	const struct ether_header *eth_hdr;
	char errbuf[PCAP_ERRBUF_SIZE];
	struct pcap_pkthdr header;
	const u_char *packet;
	const u_char *ptr;
	int i, smac = 0;
	pcap_t *handle;

	if (argc < 2)
		return -1;

	if (argc == 3) {
		if (strncmp(argv[2], "src", strlen("src")) == 0)
			smac = 1;
	}

	handle = pcap_open_offline(argv[1], errbuf);

	if (handle == NULL)
		return -2;

	while ((packet = pcap_next(handle, &header))) {
		eth_hdr = (const struct ether_header *) packet;
		if (smac)
			ptr = eth_hdr->ether_shost;
		else
			ptr = eth_hdr->ether_dhost;

		i = ETHER_ADDR_LEN;
		do {
			printf("%s%02x", (i == ETHER_ADDR_LEN) ? " " : ":",
				*ptr++);
		} while (--i > 0);
		printf("\n");
	}

	pcap_close(handle);

	return 0;
}
