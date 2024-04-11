/*
 *
 *   Copyright (c) 2020 Intel.
 *   Copyright (c) 2022 Marvell.
 *
 *   Licensed under the Apache License, Version 2.0 (the "License");
 *   you may not use this file except in compliance with the License.
 *   You may obtain a copy of the License at
 *
 *       http://www.apache.org/licenses/LICENSE-2.0
 *
 *   Unless required by applicable law or agreed to in writing, software
 *   distributed under the License is distributed on an "AS IS" BASIS,
 *   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *   See the License for the specific language governing permissions and
 *   limitations under the License.
 *
 */

#include <stdlib.h>
#include <stdint.h>
#include <dirent.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <strings.h>
#include <unistd.h>
#include <stdbool.h>
#include <limits.h>
#include <linux/vfio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <errno.h>
#include <libgen.h>

#define PCI_STR_SIZE 256
#define VFIO_VF_TOKEN_STR_LEN 36
#define VFIO_PCI_CONFIG_REGION_SIZE 256
#define VFIO_VF_TOKEN_LEN 16
#define PCI_VENDOR_ID		0x00	/* 16 bits */
#define PCI_DEVICE_ID   0x02	/* 16 bits */
#define PCI_COMMAND     0x04	/* 16 bits */
#define PCI_COMMAND_MEMORY 0x2	/* Enable response in Memory space */
#define PCI_COMMAND_MASTER 0x4	/* Enable bus mastering */
#define PCI_REVISION_ID		0x08	/* Revision ID */
#define SYS_DIR "/sys/bus/pci/devices"
#define NULL_PAD     2

static char pci_address[PCI_STR_SIZE];
static unsigned char vfio_vf_token[VFIO_VF_TOKEN_STR_LEN];
static int vfio_dev_fd = -1U;

static int vfio_read(int fd, void *buf, size_t len, off_t off)
{
	if (pread(fd, buf, len, off) != len) {
		printf("pread(off=%#lx len=%lu)", off, len);
		return -1;
	}

	return 0;
}

static int vfio_write(int fd, void *buf, size_t len, off_t off)
{
	if (pwrite(fd, buf, len, off) != len) {
		printf("pwrite(off=%#lx len=%lu)", off, len);
		return -1;
	}

	return 0;
}

static int vfio_set_bus_master(int vfio_dev_fd, int num_regions)
{
	int i;
	uint8_t config[VFIO_PCI_CONFIG_REGION_SIZE];

	for (i = 0; i < num_regions; i++) {
		struct vfio_region_info reg = {
				.argsz = sizeof(reg), .index = i
		};

		if (ioctl(vfio_dev_fd, VFIO_DEVICE_GET_REGION_INFO, &reg))
			continue;

		if (i == VFIO_PCI_CONFIG_REGION_INDEX) {
			uint16_t *vendor;
			uint16_t *cmd;

			if (vfio_read(vfio_dev_fd, config, sizeof(config), reg.offset))
				return -1;

			vendor = (uint16_t *)(config + PCI_VENDOR_ID);
			cmd = (uint16_t *)(config + PCI_COMMAND);

			if (*vendor == 0xffff) {
				printf("device in bad state");
				return -1;
			}

			*cmd |= PCI_COMMAND_MASTER | PCI_COMMAND_MEMORY;
			if (vfio_write(vfio_dev_fd, cmd,
					sizeof(*cmd), reg.offset + PCI_COMMAND))
				return -1;

			if (vfio_read(vfio_dev_fd, cmd,
					sizeof(*cmd), reg.offset + PCI_COMMAND))
				return -1;

			printf("vendor=%#x cmd=%#x device=%#x rev=%d",
					*vendor, *cmd,
					(uint32_t)*((uint16_t *)(config + PCI_DEVICE_ID)),
					(uint32_t)config[PCI_REVISION_ID]);

			break;
		}
	} /* loop on all regions */

	return 0;
}

static int vfio_get_device_groupid(const char *pci_addr)
{
	char device_iommu_group[PATH_MAX];
	char group_path[PATH_MAX];
	char *group_name;
	int groupid = -1;
	int len;

	snprintf(device_iommu_group, sizeof(device_iommu_group),
			"%s/%s/iommu_group", SYS_DIR, pci_addr);
	len = readlink(device_iommu_group, group_path, sizeof(group_path));
	if (len < 0) {
		printf("VFIO: iommu_group error for %s", pci_addr);
		return -1;
	}
	group_path[len] = 0;

	group_name = basename(group_path);
	groupid = strtol(group_name, NULL, 10);
	if (groupid == 0) {
		printf("VFIO: Failed to read %s", group_path);
		return -1;
	}

	return groupid;
}

static int vfio_uuid_parse(char *uuid_str, unsigned char *uuid)
{
	int i, inx;
	int high_n = 1;
	unsigned char tmp;

	if (strlen(uuid_str) != VFIO_VF_TOKEN_STR_LEN) {
		printf("uuid string len is wrong: %d", (int)strlen(uuid_str));
		return -1;
	}
	for (i = 0, inx = 0;
			((i < VFIO_VF_TOKEN_STR_LEN) && (inx < VFIO_VF_TOKEN_LEN));
			i++) {
		if (uuid_str[i] == '-') {
			if ((i ==  8) || (i == 13) || (i == 18) || (i == 23))
				continue;
		}
		if (!isxdigit(uuid_str[i])) {
			printf("Unknown char in uuid string");
			return -1;
		}
		tmp = isdigit(uuid_str[i]) ? uuid_str[i] - '0' :
				tolower(uuid_str[i]) - 'a' + 0xA;

		if (high_n) {
			uuid[inx] = (tmp & 0xF) << 4;
			high_n = 0;
		} else {
			uuid[inx++] |= (tmp & 0xF);
			high_n = 1;
		}
	}

	return 0;
}

static void uuid_unparse(unsigned char *uuid, char *uuid_str)
{
	char *ptr = uuid_str;
	int temp;
	int i;

	for (i = 0; i < VFIO_VF_TOKEN_LEN; i++) {
		if (i == 4 || i == 6 || i == 8 || i == 10)
			*ptr++ = '-';

		temp = (uuid[i] >> 4) & 0xF;
		*ptr++ = (temp < 10) ? temp + '0' : 'a' + (temp - 10);
		temp = (uuid[i] & 0xF);
		*ptr++ = (temp < 10) ? temp + '0' : 'a' + (temp - 10);
	}
	*ptr = '\0';
}

static int vfio_set_token(unsigned char *vfio_vf_token, int vfio_dev_fd)
{
	int ret;
	char uuid_string[VFIO_VF_TOKEN_STR_LEN+1];
	struct vfio_device_feature *device_feature;

	device_feature = (struct vfio_device_feature *)
			malloc(sizeof(struct vfio_device_feature) + VFIO_VF_TOKEN_LEN);
	if (device_feature == NULL) {
		printf("memory allocation failed");
		return -1;
	}

	/* Set the secret token shared between PF and VF */
	printf("Setting VFIO_DEVICE_FEATURE with UUID token");

	device_feature->argsz = sizeof(device_feature) + VFIO_VF_TOKEN_LEN;
	device_feature->flags = VFIO_DEVICE_FEATURE_SET |
			VFIO_DEVICE_FEATURE_PCI_VF_TOKEN;
	memcpy(device_feature->data, vfio_vf_token, VFIO_VF_TOKEN_LEN);
	uuid_unparse(device_feature->data, uuid_string);
	printf("[%s]", uuid_string);

	ret = ioctl(vfio_dev_fd, VFIO_DEVICE_FEATURE, device_feature);
	free(device_feature);
	if (ret) {
		printf("Fail to set VFIO_DEVICE_FEATURE with UUID token");
		return -1;
	}
	printf("Done");
	return 0;
}

static int vfio_device_open(char *pci_addr, int *vfio_dev_fd)
{
	int   ret, groupid;
	int   vfio_container_fd, vfio_group_fd;
	char  path[PATH_MAX];

	struct vfio_group_status group_status = {
		.argsz = sizeof(group_status)
	};

	struct vfio_device_info device_info = {
		.argsz = sizeof(device_info)
	};

	struct vfio_iommu_type1_dma_map dma_map = {
		.argsz = sizeof(dma_map)
	};

	printf("PCI device: %s", pci_addr);


	vfio_container_fd = open("/dev/vfio/vfio", O_RDWR);
	if (vfio_container_fd < 0) {
		printf("Failed to open /dev/vfio/vfio, %d (%s)",
				vfio_container_fd, strerror(errno));
		goto error0;
	}

	groupid = vfio_get_device_groupid(pci_addr);
	if (groupid == -1) {
		printf("Failed to get groupid");
		goto error1;
	}
	printf("VFIO: Using PCI device [%s] in group %d",
			pci_addr, groupid);

	snprintf(path, sizeof(path), "/dev/vfio/%d", groupid);
	vfio_group_fd = open(path, O_RDWR);
	if (vfio_group_fd < 0) {
		printf("Failed to open %s, %d (%s)",
				path, vfio_group_fd, strerror(errno));
		printf("Device [%s] not bind to vfio-pci driver",
				pci_addr);
		goto error1;
	}

	ret = ioctl(vfio_group_fd, VFIO_GROUP_GET_STATUS, &group_status);
	if (ret) {
		printf("ioctl(VFIO_GROUP_GET_STATUS) failed");
		goto error2;
	}

	if (!(group_status.flags & VFIO_GROUP_FLAGS_VIABLE)) {
		printf("Group not viable, are all devices attached to vfio?");
		goto error2;
	}

	/*
	 * NOTE: set container ioctl will attach the vfio_group_fd
	 * to vfio_container_fd, will not override the vfio_conatiner_fd
	 */
	ret = ioctl(vfio_group_fd, VFIO_GROUP_SET_CONTAINER,
			&vfio_container_fd);
	if (ret) {
		printf("Failed to set group container");
		goto error2;
	}

	ret = ioctl(vfio_container_fd,
			VFIO_SET_IOMMU, VFIO_TYPE1_IOMMU);
	if (ret) {
		printf("Failed to set IOMMU");
		goto error2;
	}

	*vfio_dev_fd = ioctl(vfio_group_fd,
			VFIO_GROUP_GET_DEVICE_FD, pci_addr);
	if (*vfio_dev_fd < 0) {
		printf("Failed to get device %s", pci_addr);
		goto error2;
	}

	close(vfio_container_fd);
	close(vfio_group_fd);

	printf("Done, vfio_dev_fd: %d", *vfio_dev_fd);
	return 0;

error2:
	close(vfio_group_fd);
error1:
	close(vfio_container_fd);
error0:
	return -1;
}

static int vfio_device_setup(int vfio_dev_fd)
{
	int ret;

	struct vfio_device_info device_info = {
		.argsz = sizeof(device_info)
	};

	ret = ioctl(vfio_dev_fd, VFIO_DEVICE_GET_INFO, &device_info);
	if (ret) {
		printf("Failed to get device info, dev fd: %d",
				vfio_dev_fd);
		return ret;
	}
	printf("Device supports %d regions", device_info.num_regions);

	/* Configure VFIO token */
	ret = vfio_set_token(vfio_vf_token, vfio_dev_fd);
	if (ret < 0) {
		printf("Fail to set VFIO_DEVICE_FEATURE with UUID token");
		return ret;
	}

	/* Enable BME */
	ret = vfio_set_bus_master(vfio_dev_fd, device_info.num_regions);
	if (ret < 0) {
		printf("Fail to set bust master\n");
		return ret;
	}

	return 0;
}

static void
print_helper(const char *prgname)
{
	printf("Usage: %s [-h] -p PCI_ID -v VFIO_TOKEN\n\n"
			" -p PCI_ID \t specifies PCI ID of device to configure (0000:51:00.0)\n"
			" -v VFIO_TOKEN \t VFIO_TOKEN is UUID formatted VFIO VF token required when bound with vfio-pci\n"
			" -h \t\t prints this helper\n\n", prgname);
}

static int
bbdev_parse_args(int argc, char **argv)
{
	int opt;
	char *prgname = argv[0];
	if (argc == 1) {
		print_helper(prgname);
		return 1;
	}

	while ((opt = getopt(argc, argv, "p:v:h")) != -1) {
		switch (opt) {
		case 'p':
			strncpy(pci_address, optarg,
					sizeof(pci_address) - NULL_PAD);
			pci_address[PCI_STR_SIZE - 1] = 0;
			break;

		case 'v':
			if (vfio_uuid_parse(optarg, vfio_vf_token) < 0)
				return 1;
			break;

		case 'h':
		default:
			print_helper(prgname);
			return 1;
		}
	}
	return 0;
}

static int
configure_device(void)
{
	int ret;

	ret = vfio_device_open(pci_address, &vfio_dev_fd);
	if (ret)
		return ret;

	ret = vfio_device_setup(vfio_dev_fd);
	if (ret)
		return ret;

	return 0;
}

int
main(int argc, char *argv[])
{
	int ret = 0;

	if (bbdev_parse_args(argc, argv) > 0)
		return 0;

	ret = configure_device();

	return ret;
}
