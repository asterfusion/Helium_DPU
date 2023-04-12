/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2017 Marvell International Ltd.
 * Copyright(c) 2017 Semihalf.
 * All rights reserved.
 */

#ifndef _ARMADA_EP_MNG_H_
#define _ARMADA_EP_MNG_H_

#include "armada_ep_ethdev.h"
#include "armada_ep_common.h"

/* MGMT Desc defines */
#define ARMADA_EP_CMD_QUEUE_LEN 256
#define ARMADA_EP_CMD_QUEUE_MAX_COOKIE_LEN (ARMADA_EP_CMD_QUEUE_LEN << 1)
#define ARMADA_EP_NOTIF_QUEUE_LEN (ARMADA_EP_CMD_QUEUE_LEN)

#define ARMADA_EP_MGMT_CMD_IDX_FREE	(0)
#define ARMADA_EP_MGMT_CMD_IDX_OCCUPY	(1)


enum armada_ep_wait_cause_t { MGMT_BUFF_CMD_SENT, MGMT_BUFF_NOTIF_RCV };

/* Message Parameters
 * cmd_idx	- Command Identifier, this field is OUTPUT param which will be
 *		  set by the lower layer.
 * cmd_code	- Command to be executed (out of enum armada_ep_cmd_codes)
 * client_id	- Client ID - PF / VF Id
 * client_type	- Client type - PF / VF
 * msg		- Message data (command parameter)
 * msg_len	- Message data size
 * timeout	- (not supported) Timeout for receiving reply
 * resp_msg	- Message response
 * resp_msg_len - Message response size
 *     Array of bytes, holding the serialized parameters/response list for a
 *     specific command.
 */
/* Make sure structure is portable along different systems. */
//TODO: move to mng.h
struct armada_ep_msg_params {
	uint16_t cmd_idx;
	enum armada_ep_cmd_codes cmd_code;
	uint8_t client_id;
	uint8_t client_type;
	void *msg;
	uint16_t msg_len;
	uint32_t timeout;
	void *resp_msg;
	uint16_t resp_msg_len;
};

//TODO: move to mng.h
struct armada_ep_mgmt_cookie {
	enum armada_ep_wait_cause_t wait_cause;
	uint32_t result;
	void *buf;
	uint32_t buf_len;
};

/* cookie values */
#define NO_RESPONSE_IS_NEEDED 0
#define NOTIICATION_MSG -1

struct armada_ep_inband_mng_msg_params {
	uint8_t	msg_code;
	void		*msg;
	uint16_t	msg_len;
	uint32_t	timeout;	/* timeout in msec */
	uint64_t	cookie;	/* user cookie. Use '0' if no response
				 * is needed.
				 * Value '-1' should not be used as it
				 * represents 'notification' message.
				 */
	void		*resp_msg;
	uint16_t	resp_msg_len;
};

int armada_ep_init_io(struct armada_ep_priv *priv);
int armada_ep_deinit_io(struct armada_ep_priv *priv);
int armada_ep_pf_vf_enable(struct armada_ep_priv *priv, uint8_t *resp_status);
int armada_ep_pf_vf_disable(struct armada_ep_priv *priv);
int armada_ep_pf_vf_link_status(struct armada_ep_priv *priv,
				uint32_t *link_status);
int armada_ep_pf_vf_get_capabilities(struct armada_ep_priv *priv);
int armada_ep_poll_mgmt(struct armada_ep_priv *priv);
int armada_ep_mgmt_notif_process(struct armada_ep_priv *priv, uint16_t cmd_code,
				 void *msg);

#endif /* _ARMADA_EP_MNG_H_ */

