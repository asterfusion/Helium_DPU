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

#include <octeon_user.h>

/* mapping info */
unsigned long maddr[3];
uint32_t msize[3];

uint32_t oct_id = 0;

void get_mapping_info();
void display_mapping_info();

void print_as_binary_32(uint32_t data)
{
	int i = 0;
	uint32_t mask = 0x80000000;
	printf("(");
	for (i = 0; i < 32; i++) {
		if (!(i & 0x3))
			printf(" ");
		printf("%u", (data & mask) ? 1 : 0);
		mask >>= 1;
	}
	printf(")\n");
}

void print_as_binary(uint64_t data)
{
	int i = 0;
	uint64_t mask = 0x8000000000000000ULL;
	printf("(");
	for (i = 0; i < 64; i++) {
		if (!(i & 0x3))
			printf(" ");
		printf("%u", (data & mask) ? 1 : 0);
		mask >>= 1;
	}
	printf(")\n");
}

int main(int argc, const char *argv[])
{
	char s[80];
	char c;
	uint32_t data;
	unsigned long address;
	uint32_t ldata;
	uint16_t wdata;
	uint8_t bdata;
	uint32_t val;
	uint32_t oct_dev_count;
	int expected_no_of_args, ret;

	if ((val = octeon_initialize())) {
		printf("octeon_initialize: FAILED; error code 0x%x\n", val);
		return 0;
	}

	printf("\nOcteon Register Dump Utility.\n Cavium Networks.\n\n");

	oct_dev_count = octeon_get_dev_count();
	if (!oct_dev_count) {
		printf("No Octeon found in the system. It shouldn't happen!\n");
		goto cleanup;
	}

	expected_no_of_args = (oct_dev_count > 1) ? 2 : 1;

	if (argc < expected_no_of_args) {
		printf
		    ("\nUsage: oct_dbg [oct_id]\nwhere oct_id is 0 for first Octeon device\n");
		octeon_shutdown();
		return 1;
	}

	oct_id = ((oct_dev_count > 1) ? (strtoul(argv[1], NULL, 10)) : 0);

	if (oct_id >= oct_dev_count) {
		printf
		    ("Illegal oct_id (%u) passed. It should be >= 0 and < %u\n",
		     oct_id, oct_dev_count);
		goto cleanup;
	}

	get_mapping_info();
	display_mapping_info();

	while (1) {
print_menu:
		fflush(stdin);
		printf("\n");
		printf("Enter 't' to reset Octeon.\n");
		printf("Enter 'r' to read Octeon BAR0.\n");
		printf("Enter 'w' to write Octeon BAR0.\n");
		printf("Enter 'i' to read Windowed reg.\n");
		printf("Enter 'o' to write Windowed reg.\n");
		printf("Enter 'R' to read PCI config register.\n");
		printf("Enter 'W' to write PCI config register\n");
		printf("Enter 'l' to read from Octeon DRAM\n");
		printf("Enter 's' to write to Octeon DRAM\n");
		printf("Enter 'd' to display mapping info.\n");
		if (oct_dev_count > 1)
			printf("Enter 'n' to change Octeon Id.\n");
		printf("Enter 'x' to quit.\n");

		printf("\nEnter the required operation: ");

skip_print_menu:
		data = 0;
		address = 0;
		ret = 0;

		scanf("%s", s);
		c = s[0];
		switch (c) {
		case 't':
			printf("Sending Hot Reset command to Octeon driver\n");
			octeon_hot_reset(oct_id);
			break;

		case 'r':
			printf("\n Please enter offset into BAR0 (hex): ");
			scanf("%s", s);
			address = maddr[0] + strtoul(s, NULL, 16);

			printf
			    ("\n Enter 'l','w' or 'b' for 32b,16b or 8b respectively:\n");
start_1:
			c = getchar();

			switch (c) {
			case 'l':
				ret = octeon_read32(oct_id, address, &ldata);
				data = ldata;
				break;

			case 'w':
				ret = octeon_read16(oct_id, address, &wdata);
				data = wdata;
				break;

			case 'b':
				ret = octeon_read8(oct_id, address, &bdata);
				data = bdata;
				break;

			case 'x':
				continue;

			default:
				goto start_1;
			}

			if (ret) {
				printf("read register failed 0x%x\n", ret);
				break;
			}

			printf("\nValue is 0x%x ", data);
			print_as_binary_32(data);

			break;

		case 'w':
			printf("\n Please enter offset into BAR0 (hex): ");
			scanf("%s", s);
			address = maddr[0] + strtoul(s, NULL, 16);

			printf("\n Please enter data (hex): ");
			scanf("%s", s);
			data = strtoul(s, NULL, 16);

			printf
			    ("\n Please enter 'l','w' or 'b' for 32b,16b or 8b respectively:\n");
start_2:
			c = getchar();
			switch (c) {
			case 'l':
				ret = octeon_write32(oct_id, address, data);
				break;

			case 'w':
				ret =
				    octeon_write16(oct_id, address,
						   (uint16_t) data);
				data = wdata;
				break;

			case 'b':
				ret =
				    octeon_write8(oct_id, address,
						  (uint8_t) data);
				data = bdata;
				break;

			case 'x':
				continue;

			default:
				goto start_2;
			}

			if (ret) {
				printf("octeon_write_register failed\n");
				break;
			}

			break;

		case 'i':
			{
				uint64_t ll_address, ll_data;

				printf("\n Please enter address (hex): ");
				scanf("%s", s);
				ll_address = strtoull(s, NULL, 16);
				printf
				    ("\nReading Windowed register at addr 0x%llx\n",
				     CVM_CAST64(ll_address));

				ll_data = 0;
				if (!octeon_win_read
				    (oct_id, ll_address, &ll_data)) {
					printf("\nValue is 0x%llx ",
					       CVM_CAST64(ll_data));
					print_as_binary((uint64_t) ll_data);
				} else {
					printf("octeon_win_read failed.\n");
				}
			}
			break;

		case 'o':
			{
				uint64_t ll_address, ll_data;

				printf("\n Please enter address (hex): ");
				scanf("%s", s);
				ll_address = strtoull(s, NULL, 16);

				printf("\n Please enter data (hex): ");
				scanf("%s", s);
				ll_data = strtoull(s, NULL, 16);

				printf
				    ("\nWriting Windowed register at addr 0x%llx val=0x%llx\n",
				     CVM_CAST64(ll_address),
				     CVM_CAST64(ll_data));

				if (octeon_win_write
				    (oct_id, ll_address, ll_data)) {
					printf("octeon_win_write failed.\n");
				}
			}
			break;

		case 'R':
			printf("\n Please enter offset (hex): ");
			scanf("%s", s);
			address = strtoul(s, NULL, 16);
			printf("\nReading register at offset 0x%lx\n", address);

			data = 0;
			if (octeon_read_pcicfg_register(oct_id, address, &data)) {
				printf("octeon_read_pcicfg_register failed.\n");
				break;
			}
			printf("\nValue is 0x%x ", data);
			print_as_binary_32(data);
			break;

		case 'W':
			printf("\n Please enter offset (hex): ");
			scanf("%s", s);
			address = strtoul(s, NULL, 16);
			printf("\n Please enter data (hex): ");
			scanf("%s", s);
			data = strtoul(s, NULL, 16);

			printf
			    ("\nWriting PCI config register at offset 0x%lx with 0x%x\n",
			     address, data);
			if (octeon_write_pcicfg_register(oct_id, address, data)) {
				printf("octeon_write_pcicfg_register failed\n");
				break;
			}
			break;

		case 'l':
			printf
			    ("\n Please enter offset into Octeon DRAM (hex): ");
			scanf("%s", s);
			address = strtoul(s, NULL, 16);

			data = 0;
			printf
			    ("\n Please enter 'l','w' or 'b' for 32b,16b or 8b respectively:\n");
start_core_read:
			scanf("%c", &c);
			switch (c) {
			case 'l':
				ret =
				    octeon_read_core(oct_id, DATA32, address,
						     &data);
				break;
			case 'w':
				ret =
				    octeon_read_core(oct_id, DATA16, address,
						     &data);
				break;
			case 'b':
				ret =
				    octeon_read_core(oct_id, DATA8, address,
						     &data);
				break;
			default:
				goto start_core_read;
			}
			if (!ret)
				printf("Value read from core at %llx: %x\n",
				       CVM_CAST64(address), data);
			else
				printf("octeon_read_core failed\n");

			break;

		case 's':
			printf
			    ("\n Please enter offset into Octeon DRAM (hex): ");
			scanf("%s", s);
			address = strtoul(s, NULL, 16);

			printf("\n Please enter data (hex): ");
			scanf("%s", s);
			data = strtoul(s, NULL, 16);

			printf
			    ("\n Please enter 'l','w' or 'b' for 32b,16b or 8b respectively:\n");
start_core_write:
			c = getchar();
			switch (c) {
			case 'l':
				ret =
				    octeon_write_core(oct_id, DATA32, address,
						      &data);
				break;
			case 'w':
				ret =
				    octeon_write_core(oct_id, DATA16, address,
						      &data);
				break;
			case 'b':
				ret =
				    octeon_write_core(oct_id, DATA8, address,
						      &data);
				break;
			default:
				goto start_core_write;
			}

			if (ret)
				printf("octeon_write_core failed\n");

			break;

		case 'd':
			get_mapping_info();
			display_mapping_info();
			break;

		case 'n':
			if (oct_dev_count < 2)
				break;
			printf("\n Please enter Octeon Id (currently %d): ",
			       oct_id);
			scanf("%s", s);
			data = strtoul(s, NULL, 16);
			if (data >= oct_dev_count) {
				printf
				    ("\nInvalid Octeon Id, valid values are between 0 and %d\n",
				     oct_dev_count - 1);
				break;
			}

			oct_id = data;
			get_mapping_info();
			display_mapping_info();

			break;

		case 'x':
		case 'X':
			goto cleanup;

		case 10:
			goto skip_print_menu;

		default:
			goto print_menu;
		}
	}

cleanup:
	if ((val = octeon_shutdown())) {
		printf("octeon_shutdown: FAILED; error code 0x%x\n", val);
	}
	return 0;
}

void get_mapping_info()
{
	if (octeon_get_mapping_info
	    (oct_id, PCI_BAR0_MAPPED, &maddr[0], &msize[0])) {
		printf("%s:%d get_mapping_info failed for PCI_BAR0_MAPPED\n",
		       __FILE__, __LINE__);
		goto cleanup;
	}

	if (octeon_get_mapping_info
	    (oct_id, PCI_BAR2_MAPPED, &maddr[1], &msize[1])) {
		printf("%s:%d get_mapping_info failed for PCI_BAR2_MAPPED\n",
		       __FILE__, __LINE__);
		goto cleanup;
	}

	if (octeon_get_mapping_info
	    (oct_id, PCI_BAR4_MAPPED, &maddr[2], &msize[2])) {
		if (msize[2] == 0)
			printf("PCI_BAR4 is not mapped \n");
		else
			printf
			    ("%s:%d get_mapping_info failed for PCI_BAR4_MAPPED\n",
			     __FILE__, __LINE__);
		goto cleanup;
	}
cleanup:
	return;
}

void display_mapping_info()
{
	int i;
	for (i = 0; i < 3; i++) {
		if (msize[i] != 0)
			printf
			    ("%02d: mapped memory address = 0x%lx, mapped_size = %d\n",
			     i, maddr[i], msize[i]);
	}
}

/*
 * $Id: oct_dbg.c 141410 2016-06-30 14:37:41Z mchalla $
 */
