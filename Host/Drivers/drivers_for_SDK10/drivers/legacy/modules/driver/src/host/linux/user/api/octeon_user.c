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

/* common user mode apis */

#include <cavium_sysdep.h>
#include <octeon_ioctl.h>
#include <cavium_defs.h>
#include <octeon_user.h>

int oct_dev_handle = -1;

int octeon_initialize()
{
	int ret = 0;

	if (oct_dev_handle < 0) {
#if defined(_WIN32)
		oct_dev_handle = open("\\\\.\\Octeon0", 0);
#elif defined(COMPILE_FOR_VF)
		oct_dev_handle = open("/dev/octeon_vf_device", 0);
#else
		oct_dev_handle = open("/dev/octeon_device", 0);
#endif
		if (oct_dev_handle < 0)
			ret = errno;
	}
#if 0
#ifdef CVM_SUPPORT_DEPRECATED_API
	printf("\n   liboctapi: Using Deprecated API\n");
#else
	printf("\n   liboctapi: Using New API\n");
#endif
#endif

	return ret;
}				/*octeon_initialize */

int octeon_shutdown()
{
	if (oct_dev_handle != -1) {
		close(oct_dev_handle);
		oct_dev_handle = -1;
	}
	return 0;
}				/*octeon_shutdown */

int octeon_get_dev_count()
{
	int count;
	if (ioctl(oct_dev_handle, IOCTL_OCTEON_GET_DEV_COUNT, (int *)&count))
		return 0;
	else
		return (count);
}				/*octeon_get_dev_count */

int octeon_get_num_ioqs(int oct_id)
{
	octeon_rw_reg_buf_t rw_buf;
	rw_buf.oct_id = oct_id;

	if (ioctl(oct_dev_handle, IOCTL_OCTEON_GET_NUM_IOQS, (int *)&rw_buf))
		return -errno;

	return rw_buf.val;

}

int octeon_send_request(int oct_id, octeon_soft_request_t * soft_req)
{
	OCTEON_RESPONSE_ORDER resp_order;
	OCTEON_RESPONSE_MODE resp_mode;

	resp_order = GET_SOFT_REQ_RESP_ORDER(soft_req);
	resp_mode = GET_SOFT_REQ_RESP_MODE(soft_req);

	if (SOFT_REQ_IS_RAW(soft_req)) {
		/* ORDERED mode is not supported from user space. */
		if (resp_order == OCTEON_RESP_ORDERED) {
			printf
			    ("octeon_send_request: Error! ORDERED (%d) mode not supported \n",
			     resp_order);
			return EINVAL;
		}
	} else {
		/* Non-RAW mode data (Packet mode) should not expect a RESPONSE */
		if (resp_order != OCTEON_RESP_NORESPONSE) {
			printf
			    ("octeon_send_request: Error! Unsupported Response Order (%d) in non-RAW mode\n",
			     resp_order);
			return EINVAL;
		}
	}
	if ((resp_order == OCTEON_RESP_NORESPONSE)
	    && (resp_mode == OCTEON_RESP_BLOCKING)) {
		printf
		    ("octeon_send_request: Error! Blocking Mode not supported for NoResponse Packet\n");
		return EINVAL;
	}

	SOFT_REQ_INFO(soft_req)->octeon_id = oct_id;
	if (ioctl(oct_dev_handle, IOCTL_OCTEON_SEND_REQUEST, soft_req)) {
		return errno;
	}
	return 0;
}

int octeon_query_request(int oct_id, octeon_query_request_t * query)
{
	query->octeon_id = oct_id;
	if (ioctl(oct_dev_handle, IOCTL_OCTEON_QUERY_REQUEST, query)) {
		return errno;
	}
	return 0;
}

int octeon_get_stats(int oct_id, oct_stats_t * stats)
{
	stats->oct_id = oct_id;
	if (ioctl(oct_dev_handle, IOCTL_OCTEON_STATS, stats)) {
		return errno;
	}
	return 0;
}

int octeon_hot_reset(int oct_id)
{
	octeon_rw_reg_buf_t rw_buf;

	rw_buf.oct_id = oct_id;
	if (ioctl(oct_dev_handle, IOCTL_OCTEON_HOT_RESET, &rw_buf))
		return errno;
	return 0;
}

int octeon_read_pcicfg_register(int oct_id, uint32_t offset, uint32_t * data)
{
	octeon_rw_reg_buf_t rw_buf;

	rw_buf.val = 0;
	rw_buf.addr = (uint64_t) offset;
	rw_buf.type = PCI_CFG;
	rw_buf.oct_id = oct_id;
	if (ioctl(oct_dev_handle, IOCTL_OCTEON_READ_PCI_CONFIG, &rw_buf)) {
		return errno;
	}

	*data = (uint32_t) rw_buf.val;
	return 0;
}				/*octeon_read_pci_config */

int octeon_write_pcicfg_register(int oct_id, uint32_t offset, uint32_t data)
{
	octeon_rw_reg_buf_t rw_buf;

	rw_buf.val = (uint64_t) data;
	rw_buf.addr = (uint64_t) offset;
	rw_buf.type = PCI_CFG;
	rw_buf.oct_id = oct_id;
	if (ioctl(oct_dev_handle, IOCTL_OCTEON_WRITE_PCI_CONFIG, &rw_buf)) {
		return errno;
	}
	return 0;
}				/*octeon_write_pcicfg_register */

int octeon_get_mapping_info(int oct_id, octeon_reg_type_t type,
			    unsigned long *mapped_address,
			    uint32_t * mapped_size)
{
	octeon_rw_reg_buf_t rw_buf;

	if (type != PCI_BAR0_MAPPED && type != PCI_BAR2_MAPPED
	    && type != PCI_BAR4_MAPPED) {
		printf("%s:%d Error! invalid type 0x%x\n", __FILE__, __LINE__,
		       type);
		return -1;
	}

	rw_buf.val = 0;
	rw_buf.addr = 0;
	rw_buf.type = type;
	rw_buf.oct_id = oct_id;

	if (ioctl(oct_dev_handle, IOCTL_OCTEON_GET_MAPPING_INFO, &rw_buf)) {
		return errno;
	}

	*mapped_address = (unsigned long)rw_buf.addr;
	*mapped_size = (uint32_t) rw_buf.val;
	return 0;
}				/*octeon_get_mapped_address */

/** This functions is not exported to applications but API's exported to apps
    are wrapped around this function. Use this function to read/write octeon
    memory that is known to have been mapped to PCI space.
*/
int
__octeon_rw_mapped_core_memory(int oct_id, unsigned long address,
			       void *data, int cmd)
{
	octeon_rw_reg_buf_t rw_buf;

	switch (cmd) {
	case IOCTL_OCTEON_WRITE32:
		rw_buf.val = *((uint32_t *) data);
		break;
	case IOCTL_OCTEON_WRITE16:
		rw_buf.val = *((uint16_t *) data);
		break;
	case IOCTL_OCTEON_WRITE8:
		rw_buf.val = *((uint8_t *) data);
		break;
	default:
		rw_buf.val = 0;
		break;		// Command could be a read */
	}

	rw_buf.addr = (uint64_t) address;
	rw_buf.oct_id = oct_id;
	if (ioctl(oct_dev_handle, cmd, &rw_buf))
		return errno;

	switch (cmd) {
	case IOCTL_OCTEON_READ32:
		*((uint32_t *) data) = (uint32_t) rw_buf.val;
		break;
	case IOCTL_OCTEON_READ16:
		*((uint16_t *) data) = (uint16_t) rw_buf.val;
		break;
	case IOCTL_OCTEON_READ8:
		*((uint8_t *) data) = (uint8_t) rw_buf.val;
		break;
	default:
		break;
	}

	return 0;
}

int octeon_read32(int oct_id, unsigned long address, uint32_t * data)
{
	return __octeon_rw_mapped_core_memory(oct_id, address, data,
					      IOCTL_OCTEON_READ32);
}

int octeon_read16(int oct_id, unsigned long address, uint16_t * data)
{
	return __octeon_rw_mapped_core_memory(oct_id, address, data,
					      IOCTL_OCTEON_READ16);
}

int octeon_read8(int oct_id, unsigned long address, uint8_t * data)
{
	return __octeon_rw_mapped_core_memory(oct_id, address, data,
					      IOCTL_OCTEON_READ8);
}

int octeon_write32(int oct_id, unsigned long address, uint32_t data)
{
	return __octeon_rw_mapped_core_memory(oct_id, address, &data,
					      IOCTL_OCTEON_WRITE32);
}

int octeon_write16(int oct_id, unsigned long address, uint16_t data)
{
	return __octeon_rw_mapped_core_memory(oct_id, address, &data,
					      IOCTL_OCTEON_WRITE16);
}

int octeon_write8(int oct_id, unsigned long address, uint8_t data)
{
	return __octeon_rw_mapped_core_memory(oct_id, address, &data,
					      IOCTL_OCTEON_WRITE8);
}

int octeon_read_core_direct(int oct_id, uint64_t core_addr, uint32_t len,
			    void *data, uint32_t swap_mode)
{
	octeon_core_mem_rw_t core_mem;

	core_mem.oct_id = oct_id;
	core_mem.addr = core_addr;
	core_mem.size = len;
	core_mem.data = data;
	core_mem.endian = swap_mode;
	core_mem.bar1_index = 0;
	if (ioctl(oct_dev_handle, IOCTL_OCTEON_CORE_MEM_READ, &core_mem)) {
		return errno;
	}
	return 0;
}

int octeon_read_core(int oct_id, octeon_user_datatype_t datatype,
		     uint64_t address, void *data)
{

	octeon_read_core_direct(oct_id, address, datatype, data, 1);
	switch (datatype) {
	case DATA8:
		break;
	case DATA16:
		octeon_swap_2B_data(data, 1);
		break;
	case DATA32:
		octeon_swap_4B_data(data, 1);
		break;
	}
	return 0;
}				/*octeon_write_core */

int octeon_write_core_direct(int oct_id, uint64_t core_addr, uint32_t len,
			     void *data, uint32_t swap_mode)
{
	octeon_core_mem_rw_t core_mem;

	core_mem.oct_id = oct_id;
	core_mem.addr = core_addr;
	core_mem.size = len;
	core_mem.data = data;
	core_mem.endian = swap_mode;
	core_mem.bar1_index = 0;
	if (ioctl(oct_dev_handle, IOCTL_OCTEON_CORE_MEM_WRITE, &core_mem)) {
		return errno;
	}
	return 0;
}

int octeon_write_core(int oct_id, octeon_user_datatype_t datatype,
		      uint64_t address, void *data)
{

	switch (datatype) {
	case DATA8:
		break;
	case DATA16:
		octeon_swap_2B_data(data, 1);
		break;
	case DATA32:
		octeon_swap_4B_data(data, 1);
		break;
	}
	octeon_write_core_direct(oct_id, address, datatype, data, 1);

	return 0;
}				/*octeon_write_core */

int octeon_win_write(int oct_id, uint64_t address, uint64_t data)
{
	octeon_rw_reg_buf_t rw_buf;

	rw_buf.val = data;
	rw_buf.addr = address;
	rw_buf.oct_id = oct_id;
	if (ioctl(oct_dev_handle, IOCTL_OCTEON_WIN_WRITE, &rw_buf)) {
		return errno;
	}

	return 0;
}				/*octeon_win_write */

int octeon_win_read(int oct_id, uint64_t address, uint64_t * data)
{
	octeon_rw_reg_buf_t rw_buf;

	rw_buf.val = 0;
	rw_buf.addr = address;
	rw_buf.oct_id = oct_id;
	if (ioctl(oct_dev_handle, IOCTL_OCTEON_WIN_READ, &rw_buf)) {
		return errno;
	}
	*data = rw_buf.val;
	return 0;
}				/*octeon_win_read */

#if defined(_WIN32)

int errno;

int open(const char *filename, int mode)
{
	HANDLE handle;

	if ((handle =
	     CreateFile(filename, FILE_READ_DATA | FILE_WRITE_DATA,
			FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING,
			FILE_ATTRIBUTE_NORMAL, NULL)) == INVALID_HANDLE_VALUE)
		return errno = -1;

	errno = 0;

	return (int)handle;
}

void close(int fd)
{
	CloseHandle((HANDLE) fd);
	errno = 0;
}

static __inline LONG get_cmd_size(ULONG cmd)
{
	LONG retval = -1;

	switch (cmd) {
	case IOCTL_OCTEON_SEND_REQUEST:
		retval = sizeof(octeon_soft_request_t);
		break;
	case IOCTL_OCTEON_QUERY_REQUEST:
		retval = sizeof(octeon_query_request_t);
		break;
	case IOCTL_OCTEON_READ_PCI_CONFIG:
		retval = sizeof(octeon_rw_reg_buf_t);
		break;
	case IOCTL_OCTEON_WRITE_PCI_CONFIG:
		retval = sizeof(octeon_rw_reg_buf_t);
		break;
	case IOCTL_OCTEON_GET_MAPPING_INFO:
		retval = sizeof(octeon_rw_reg_buf_t);
		break;
	case IOCTL_OCTEON_READ32:
		retval = sizeof(octeon_rw_reg_buf_t);
		break;
	case IOCTL_OCTEON_WRITE32:
		retval = sizeof(octeon_rw_reg_buf_t);
		break;
	case IOCTL_OCTEON_READ16:
		retval = sizeof(octeon_rw_reg_buf_t);
		break;
	case IOCTL_OCTEON_WRITE16:
		retval = sizeof(octeon_rw_reg_buf_t);
		break;
	case IOCTL_OCTEON_READ8:
		retval = sizeof(octeon_rw_reg_buf_t);
		break;
	case IOCTL_OCTEON_WRITE8:
		retval = sizeof(octeon_rw_reg_buf_t);
		break;
	case IOCTL_OCTEON_GET_DEV_COUNT:
		retval = sizeof(int);
		break;
	case IOCTL_OCTEON_WIN_READ:
		retval = sizeof(octeon_rw_reg_buf_t);
		break;
	case IOCTL_OCTEON_WIN_WRITE:
		retval = sizeof(octeon_rw_reg_buf_t);
		break;
	}

	return retval;
}

int ioctl(int fd, int request, void *ptr)
{
	LONG size;
	DWORD inout, ret;

	inout = (DWORD) ptr;
	size = get_cmd_size(request);

	if (size < 0)
		return -1;

	if (!DeviceIoControl
	    ((HANDLE) fd, request, (LPVOID) inout, size, (LPVOID) inout, size,
	     &ret, NULL)) {
		errno = -1;
		return -1;
	}

	errno = 0;

	return 0;
}

#endif
/* $Id: octeon_user.c 141410 2016-06-30 14:37:41Z mchalla $ */
