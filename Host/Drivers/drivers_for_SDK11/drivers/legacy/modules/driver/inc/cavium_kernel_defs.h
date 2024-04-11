/* Copyright (c) 2020 Marvell.
 * SPDX-License-Identifier: GPL-2.0
 */

/*! \file  cavium_kernel_defs.h
    \brief Host Driver: Structures & functions exported by the driver
	                    for use by kernel applications.
*/

#ifndef  __CAVIUM_KERNEL_DEFS_H__
#define  __CAVIUM_KERNEL_DEFS_H__

/* The maximum number of buffers that can be dispatched from the 
   output/dma queue. Set to 64 assuming 1K buffers in DROQ and the fact that 
   max packet size from DROQ is 64K. */
#define    MAX_RECV_BUFS    64

/* Allocated using malloc etc. */
#define    OCT_RECV_BUF_TYPE_1   OCT_BUFFER_TYPE_1

/* Is a skb or similar. */
#define    OCT_RECV_BUF_TYPE_2   OCT_BUFFER_TYPE_2

/** Receive Packet format used when dispatching output queue packets
    with non-raw opcodes.
    The received packet will be sent to the upper layers using this
    structure which is passed as a parameter to the dispatch function 
*/
typedef struct {

  /**  Number of buffers in this received packet */
	uint16_t buffer_count;

  /** Id of the device that is sending the packet up */
	uint8_t octeon_id;

  /** The type of buffer contained in the buffer ptr's for this recv pkt. */
	uint8_t buf_type;

  /** Length of data in the packet buffer */
	uint32_t length;

  /** Offset of data in the first packet buffer */
	uint32_t offset;

  /** The response header */
	octeon_resp_hdr_t resp_hdr;

  /** Pointer to the OS-specific packet buffer */
	void *buffer_ptr[MAX_RECV_BUFS];

  /** Size of the buffers pointed to by ptr's in buffer_ptr */
	uint32_t buffer_size[MAX_RECV_BUFS];

} octeon_recv_pkt_t;

#define OCT_RECV_PKT_SIZE    (sizeof(octeon_recv_pkt_t))

/** The first parameter of a dispatch function.
    For a raw mode opcode, the driver dispatches with the device 
    pointer in this structure. 
    For non-raw mode opcode, the driver dispatches the recv_pkt_t
    created to contain the buffers with data received from Octeon.
    ---------------------
    |     *recv_pkt ----|---
    |-------------------|   |
    | 0 or more bytes   |   |
    | reserved by driver|   |
    |-------------------|<-/
    | octeon_recv_pkt_t |
    |                   |
    |___________________|
*/
typedef struct {
	void *rsvd;
	octeon_recv_pkt_t *recv_pkt;
} octeon_recv_info_t;

#define  OCT_RECV_INFO_SIZE    (sizeof(octeon_recv_info_t))

typedef int (*octeon_dispatch_fn_t) (octeon_recv_info_t *, void *);

#define POLL_EVENT_INTR_ARRIVED  1
#define POLL_EVENT_PROCESS_PKTS  2
#define POLL_EVENT_ENABLE_INTR   3

/** Used by NIC module to register packet handler and to get device
  * information for each octeon device.
  */
typedef struct {
	/* This function will be called by the driver for all NAPI related
	   events. The first param is the octeon id. The second param is the
	   output queue number. The third is the NAPI event that occurred. */
	/* Should be removed after adding napi support in older octeon models */
	void (*napi_fn) (int, int, int);
	/* Added for NAPI support */
	void (*napi_fun) (void *);

	int poll_mode;

	/** Flag indicating if the DROQ handler should drop packets that
	    it cannot handle in one iteration. Set by caller. */
	int drop_on_max;

	uint16_t op_mask;

	uint16_t op_major;

} octeon_droq_ops_t;

typedef enum {
	OCTEON_MODULE_HANDLER_UNREGISTERED,
	OCTEON_MODULE_HANDLER_REGISTERED,
	OCTEON_MODULE_HANDLER_INIT_LATER,
	OCTEON_MODULE_HANDLER_INIT_DONE,
	OCTEON_MODULE_HANDLER_STOPPED
} octeon_module_handler_status_t;

/** Structure passed by kernel application when registering a module with
	the driver. */
typedef struct {

	/* Application type for which handler is being registered. */
	uint32_t app_type;

	/* Call this routine to perform add-on module related setup activities
	   when a octeon device is being initialized.
	 */
	int (*startptr) (int, void *);

	/* Call this routine to perform add-on module related reset activities
	   when a octeon device is being reset.
	 */
	int (*resetptr) (int, void *);

	/* Call this routine to perform add-on module related shutdown 
	   activities when a octeon device is being removed or the driver is 
	   being unloaded.
	 */
	int (*stopptr) (int, void *);

} octeon_module_handler_t;

/** Return value for a poll function. The driver will continue scheduling the
	poll function as long as the function returns OCT_POLL_FN_CONTINUE. */
typedef enum {
	OCT_POLL_FN_CONTINUE = 0,
	OCT_POLL_FN_FINISHED = 1,
	OCT_POLL_FN_ERROR = 2,
	OCT_POLL_FN_REGISTERED = 3,	/* Used internally by driver */
	OCT_POLL_FN_UNREGISTERED = 4	/* Used internally by driver */
} oct_poll_fn_status_t;

typedef oct_poll_fn_status_t(*octeon_poll_fn_t) (void *, unsigned long);

/** Structure passed by kernel application when registering a poll function with
	the driver. */
typedef struct {

	/** Pointer to Poll function to be called by the poll thread. */
	octeon_poll_fn_t fn;

	/** The function argument to be passed to the poll function when it
	    is scheduled by the poll thread. */
	unsigned long fn_arg;

	/** The scheduling interval in timer ticks that the poll function
	    should be scheduled by the poll thread */
	int ticks;

	/** A character string to identify this poll function. */
	char name[80];

	/** Reserved for Driver use. Do not set this field */
	uint32_t rsvd;

} octeon_poll_ops_t;

/*-----------------EXPORTED ENTRY POINTS------------------------*/

/**   Register a dispatch function for a opcode. The driver will call 
 *    this dispatch function when it receives a packet with the given
 *    opcode in its output queues along with the user specified argument.
 *    @param  octeon_id  - the octeon device to register with.
 *    @param  opcode     - the opcode for which the dispatch will be registered.
 *    @param  fn         - the dispatch function.
 *    @param  fn_arg     - user specified that will be passed along with the
 *                         dispatch function by the driver.
 *    @return Success: 0; Failure: 1
 */
uint32_t octeon_register_dispatch_fn(uint32_t octeon_id,
				     octeon_opcode_t opcode,
				     octeon_dispatch_fn_t fn, void *fn_arg);

/**  Remove registration for an opcode. This will delete the mapping for
 *   an opcode. The dispatch function will be unregistered and will no
 *   longer be called if a packet with the opcode arrives in the driver
 *   output queues.
 *   @param  octeon_id  -  the octeon device to unregister from.
 *   @param  opcode     -  the opcode to be unregistered.
 *
 *   @return Success: 0; Failure: 1
 */
uint32_t octeon_unregister_dispatch_fn(uint32_t octeon_id,
				       octeon_opcode_t opcode);

void
octeon_write_core_memory(uint32_t octeon_id,
			 uint64_t addr, void *buf, uint32_t len);

void
octeon_read_core_memory(uint32_t octeon_id,
			uint64_t addr, void *buf, uint32_t len);

/** Get the number of Octeon devices currently in the system.
 *  This function is exported to other modules.
 *  @return  Count of octeon devices.
 */
uint32_t get_octeon_count(void);

/** Get the octeon id assigned to the octeon device passed as argument.
 *  This function is exported to other modules.
 *  @param dev - octeon device pointer passed as a void *.
 *  @return octeon device id
 */
int get_octeon_device_id(void *dev);

/** Get the octeon device from the octeon id passed as argument.
 *  This function is exported to other modules.
 *  @param octeon_id - octeon device id.
 *  @return octeon device pointer as a void *.
 */
void *get_octeon_device_ptr(int octeon_id);

int octeon_get_tx_qsize(int octeon_id, int q_no);

int octeon_get_rx_qsize(int octeon_id, int q_no);

/** Wrapper function to map a buffer for PCI bus transaction. */
unsigned long
octeon_map_single_buffer(int octeon_id, void *virt_addr, uint32_t size,
			 int direction);

/** Wrapper function to unmap a buffer used for PCI bus transaction. */
void
octeon_unmap_single_buffer(int octeon_id, unsigned long dma_addr,
			   uint32_t size, int direction);

unsigned long
octeon_map_page(int octeon_id, cavium_page_t * page, unsigned long offset,
		uint32_t size, int direction);

void
octeon_unmap_page(int octeon_id, unsigned long dma_addr, uint32_t size,
		  int direction);
int
octeon_mapping_error(int octeon_id, unsigned long dma_addr);

/** Register a change in droq operations. The ops field has a pointer to a
  * function which will called by the DROQ handler for all packets arriving
  * on output queues given by q_no irrespective of the type of packet.
  * The ops field also has a flag which if set tells the DROQ handler to 
  * drop packets if it receives more than what it can process in one 
  * invocation of the handler.
  * @param octeon_id - octeon device id
  * @param q_no      - octeon output queue number (0 <= q_no <= MAX_OCTEON_DROQ-1
  * @param ops       - the droq_ops settings for this queue
  * @return          - 0 on success, -ENODEV or -EINVAL on error.
  */
int
octeon_register_droq_ops(int octeon_id, uint32_t q_no, octeon_droq_ops_t * ops);

/** Resets the function pointer and flag settings made by
  * octeon_register_droq_ops(). After this routine is called, the DROQ handler
  * will lookup dispatch function for each arriving packet on the output queue
  * given by q_no.
  * @param octeon_id - octeon device id
  * @param q_no      - octeon output queue number (0 <= q_no <= MAX_OCTEON_DROQ-1
  * @return          - 0 on success, -ENODEV or -EINVAL on error.
  */
int octeon_unregister_droq_ops(int octeon_id, uint32_t q_no);

/** Register module handler functions to be called by the octeon base driver
 * when a octeon device is being initialized. The "start" function in the
 * handler may be called in this function call's context if this function is
 * called after a octeon device was initialized. The "app_type" field 
 * is checked by the base module against the application type given by the
 * core application in its start indicator. If it matches, the base module
 * calls the start handler for that octeon device.
 * @param handler - structure with "start" and "stop" routines and app type. 
 * @return 0 on success, -EINVAL if the handler arguments are invalid or if
 *         a handler was already registered; -ENOMEM if no space is available
 *         to add this handler.
 */
int octeon_register_module_handler(octeon_module_handler_t * handler);

void octeon_probe_module_handlers(int octeon_id);

/** Called by a module when it is being unloaded to unregister start
 * and stop functions. The "stop" function will be called in this function
 * call's context. The "stop" routine will also be called if the octeon device
 * if being removed (due to a hot-swap operation).
 * @param app_type - the handler for this applicatin type should be removed.
 * @return 0 on success; -ENODEV if no handler was found for the app_type.
 */
int octeon_unregister_module_handler(uint32_t app_type);

int octeon_reset_oq_bufsize(int octeon_id, int q_no, int newsize);

/** Register a poll function with the driver. The "ops" parameter
 *  points to a octeon_poll_ops_t structure that holds a pointer to the poll
 *  function, an optional argument that the driver should call if the poll
 *  function is called and the time interval in ticks that the poll function
 *  should be called.
 *  @param oct_id - octeon device id
 *  @param ops    - pointer to a structure with the poll function details.
 *  @return 0 on success; -ENODEV, -EINVAL or -ENOMEM on failure.
 */
int octeon_register_poll_fn(int oct_id, octeon_poll_ops_t * ops);

/** Unregister a poll function. The fn and fn_arg used when
	octeon_register_poll_fn() was called is passed as arguments to
 *  uniquely identify the instance of the poll function to be unregistered.
 *  @param oct_id - octeon device id
 *  @param fn     - the poll function to be unregistered.
 *  @param fn_arg - the poll function argument.
 *  @return 0 on success; -ENODEV on failure.
 */
int
octeon_unregister_poll_fn(int oct_id, octeon_poll_fn_t fn,
			  unsigned long fn_arg);

int
octeon_register_noresp_buf_free_fn(int oct_id, int buftype,
				   void (*fn) (void *));

uint32_t octeon_active_dev_count(void);

int octeon_all_devices_active(void);
#endif

/* $Id: cavium_kernel_defs.h 170605 2018-03-20 15:19:22Z vvelumuri $ */
