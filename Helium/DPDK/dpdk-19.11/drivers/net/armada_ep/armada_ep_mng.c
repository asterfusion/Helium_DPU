/*****************************************************************************
 *  Copyright (C) 2018 Marvell International Ltd.
 *
 *  This program is provided "as is" without any warranty of any kind, and is
 *  distributed under the applicable Marvell limited use license agreement.
 *****************************************************************************/

#include <rte_spinlock.h>
#include <rte_cycles.h>

#include "armada_ep_ethdev.h"
#include "armada_ep_hw.h"
#include "armada_ep_mng.h"
#include "armada_ep_errno.h"


/* this buffer is used for asyc notification (as no buffer was allocated for
 * them).
 * Note: we assume that these notifications are handled one by one (otherwise,
 *	 this buffer will be overridden).
 */
#define ARMADA_EP_MGMT_NOTIF_BUF_SIZE	1024
#define ARMADA_EP_MGMT_CMD_RESP_TIMEOUT	5000 /* 5 secs */

static char armada_ep_notif_buf[ARMADA_EP_MGMT_NOTIF_BUF_SIZE];

static inline void
armada_ep_queue_ptr_inc(uint32_t *idx, int num, uint32_t q_sz) {
	*idx = (*idx + num) & (q_sz - 1);
}


static inline void
armada_ep_queue_ptr_inc_16(uint16_t *idx, int num, uint32_t q_sz) {
	*idx = (*idx + num) & (q_sz - 1);
}


/* Generate cmd index for the cookie list
 *
 * Note: make sure that the input parameter (cmd_idx) is used
 *       within a LOCK so 2 different threads won't get the same id.
 *
 * @param cmd_idx
 *   Current command index.
 * @param queue_size
 *   Total queue size.
 *
 * @return
 *   The incremented command index.
 */
static uint16_t
armada_ep_mgmt_cmd_idx_gen(uint16_t cmd_idx, uint32_t queue_size)
{
	do {
		/* Increment command index by 1 */
		armada_ep_queue_ptr_inc_16(&cmd_idx, 1, queue_size);
	} while (cmd_idx == CMD_ID_ILLEGAL || cmd_idx == CMD_ID_NOTIFICATION);

	return cmd_idx;
}


static int
armada_ep_mgmt_command_send_process(struct armada_ep_priv *priv,
	struct armada_ep_msg_params *msg_params)
{
	struct armada_ep_queue *q = &priv->cmd_queue;
	struct armada_ep_cmd_desc *desc;
	struct armada_ep_mgmt_cookie *mgmt_buff;
	static uint16_t cmd_idx, desc_required, desc_free, desc_idx;
	int msg_buf_left, copy_len;
	int ret = 0, no_resp_req = msg_params->resp_msg ? 0 : 1;
	uint32_t prod_val;

	/* Check if length is set (only if message is not null) */
	if (msg_params->msg && !msg_params->msg_len) {
		ARMADA_EP_LOG(ERR, "armada ep mgmt msg length is 0\n");
		return -EINVAL;
	}

	ARMADA_EP_LOG(DEBUG, "mgmt cmd issue (%d).\n", msg_params->cmd_code);

	/* Check how many descriptors are required for sending the message */
	desc_required = ceil(msg_params->msg_len, ARMADA_EP_MGMT_DESC_DATA_LEN);
	if (!desc_required)
		/*
		 * Even if there is no buffer to copy, 1 descriptor is need for
		 * the message.
		 */
		desc_required = 1;

	/* Hold the mgmt commands spin-lock, as we have a single queue that
	 * serves all CPUs
	 */
	rte_spinlock_lock(&priv->mgmt_lock);

	prod_val = readl(q->prod_p);
	desc_free = armada_ep_q_space(prod_val, readl(q->cons_p), q->count);

	if (desc_free < desc_required) {
		ARMADA_EP_LOG(ERR, "Msg size is %d which requires %d"
			      " descriptors and only %d are available",
			      msg_params->msg_len, desc_required,
			      desc_free);
		ret = -EBUSY;
		goto cmd_send_error;
	}

	/* Generate command index (for cookie list) */
	cmd_idx = armada_ep_mgmt_cmd_idx_gen(cmd_idx, q->cookie_count);

	/* return cmd index to be used later to get the buffer */
	msg_params->cmd_idx = cmd_idx;

	mgmt_buff = &q->mgmt_cookie_list[cmd_idx];

	if (mgmt_buff->buf) {
		ARMADA_EP_LOG(WARNING, "%s - No available cookie", __func__);
		ret = -ENOBUFS;
		goto cmd_send_error;
	}

	msg_buf_left = msg_params->msg_len;
	copy_len = ARMADA_EP_MGMT_DESC_DATA_LEN;

	for (desc_idx = 0; desc_idx < desc_required; desc_idx++) {
		/* Get a pointer to the next Tx descriptor and relevant mgmt
		 *buffer info
		 */
		desc = ((struct armada_ep_cmd_desc *)q->desc) + prod_val;

		/* Identify the command once the response is received */
		desc->cmd_idx = cmd_idx;
		CMD_FLAGS_NO_RESP_SET(desc->flags, no_resp_req);

		/* Update the cmd_desc (HW descriptor) */
		desc->app_code = AC_PF_MANAGER;
		desc->cmd_code = msg_params->cmd_code;
		desc->client_id = msg_params->client_id;
		desc->client_type = msg_params->client_type;

		/* If command params exist, copy them to HW descriptor */
		if (msg_params->msg) {
			/* Adjust the copy size */
			copy_len = RTE_MIN(msg_buf_left,
				ARMADA_EP_MGMT_DESC_DATA_LEN);

			memcpy(desc->data, (char *)msg_params->msg +
			      (ARMADA_EP_MGMT_DESC_DATA_LEN * desc_idx),
			       copy_len);
			msg_buf_left -= copy_len;
		}

		/* Set the desc flag
		 * (Currently, external buffers is not supported)
		 */
		if (desc_required == 1) /* Single descriptor */
			CMD_FLAGS_BUF_POS_SET(desc->flags,
				CMD_FLAG_BUF_POS_SINGLE);
		else if (desc_idx == (desc_required - 1)) /* Last descriptor */
			CMD_FLAGS_BUF_POS_SET(desc->flags,
				CMD_FLAG_BUF_POS_LAST);
		else /* First or Mid descriptor */
			CMD_FLAGS_BUF_POS_SET(desc->flags,
				CMD_FLAG_BUF_POS_FIRST_MID);
		/* Increment producer counter
		 * (Note that it's not written to HW yet)
		 */
		armada_ep_queue_ptr_inc(&prod_val, 1, q->count);
	}
	/* Save buffer info (it will be used by notification handler
	 * to save the response data)
	 */
	mgmt_buff->buf = msg_params->resp_msg;
	mgmt_buff->buf_len = msg_params->resp_msg_len;

	/* Mark the command as sent, the condition for releasing the
	 * wait_event() below is that this field is set to != 0 by the
	 * notification handler
	 */
	mgmt_buff->wait_cause = MGMT_BUFF_CMD_SENT;

	/* Notify NIC about all written descriptors */
	writel(prod_val, q->prod_p);

cmd_send_error:
	/* spin_lock can be released, as ring manipulation is over */
	rte_spinlock_unlock(&priv->mgmt_lock);

	return ret;
}

static inline int
armada_ep_validate_s_g_msg_params(struct armada_ep_cmd_desc *desc, int buf_pos)
{
	uint16_t cmd_idx = desc->cmd_idx;
	int ret = 0;

	/* Check that the descriptor has the same cmd_idx as the
	 * first one
	 */
	if (desc->cmd_idx != cmd_idx) {
		ARMADA_EP_LOG(ERR, "desc->cmd_idx (%d) != cmd_idx (%d)",
			      desc->cmd_idx, cmd_idx);
		ret = -EINVAL;
	} else if ((buf_pos == CMD_FLAG_BUF_POS_SINGLE) ||
		(buf_pos == CMD_FLAG_BUF_POS_EXT_BUF)) {
		ARMADA_EP_LOG(ERR, "Invalid buf position (%d) during S/G "
			"message", buf_pos);
		ret = -EINVAL;
	} else if (CMD_FLAGS_NUM_EXT_DESC_GET(desc->flags) != 0) {
		ARMADA_EP_LOG(ERR, "Invalid Ext desc number during S/G "
			"message");
		ret = -EINVAL;
	}
	return ret;
}

/*
 * armada_ep_scatter_gather_msg -
 * For S/G message, need to loop the descriptors until reach buf-pos with
 * value of LAST.
 * There are several error cases:
 * 1. buff-pos is single or external
 * 2. desc->cmd_indx != cmd_idx (i.e cmd_idx should be the same for all
 *    descriptors).
 * 3. num_ext_desc != 0
 * 4. Ring is empty before we reached a descriptor with buf-pos with value LAST.
 *
 * @param[in]	notif_q
 *			A pointer to a management notification queue.
 * @param[in]	msg_buf_len
 *			buffer length of whole the message.
 * @param[in]	desc
 *			next Rx descriptor and relevant mgmt buffer info.
 * @param[out]	desc
 *			Last Rx descriptor (in case S/G.
 * @param[out]	msg_buf
 *			Allocated buffer for message data.
 * @param[out]	msg_len
 *			Copied message length to msg_buf (might be different
 *			than msg_buf_len due to errors and not enougth space in
 *			the message buffer (msg_buf).
 *
 * @retval	0 in case of succsseful, negative value otherwise.
 */
static inline int
armada_ep_scatter_gather_msg(struct armada_ep_queue *notif_q, int msg_buf_len,
				struct armada_ep_cmd_desc *desc,
				void *msg_buf, int *msg_len)
{
	int ret, msg_buf_left, copy_len, buf_pos, sg_msg_flag;
	int desc_idx = 0;

	msg_buf_left = msg_buf_len;
	copy_len = ARMADA_EP_MGMT_DESC_DATA_LEN;
	*msg_len = 0;
	uint32_t cons_val;

	/* Check if this is S/G message */
	sg_msg_flag = (CMD_FLAGS_BUF_POS_GET(desc->flags) ==
		CMD_FLAG_BUF_POS_FIRST_MID) ? 1 : 0;

	cons_val = readl(notif_q->cons_p);

	do {
		/* Check if there are not more descriptor in the queue.
		 * This is an error case as for S/G message, we expect all
		 * descriptors to be in the queue before sending the message.
		 * For single message, we already checked above that the queue
		 * is not empty so this is not a valid case.
		 */
		if (readl(notif_q->prod_p) == cons_val) {
			ARMADA_EP_LOG(ERR, "queue is empty in the middle of S/G"
				      " message");
			return -ENODATA;
		}

		/* get next descriptor */
		desc = ((struct armada_ep_cmd_desc *)notif_q->desc) + cons_val;

		/* Check that the msg buffer is enough for copying the response
		 * into it. if not, reduce the copy length to whatever space
		 * left.
		 */
		if (msg_buf_left < ARMADA_EP_MGMT_DESC_DATA_LEN) {
			ARMADA_EP_LOG(DEBUG, "space left < data size (%d < %d)."
				      " reducing to left space", msg_buf_left,
				      ARMADA_EP_MGMT_DESC_DATA_LEN);
			copy_len = msg_buf_left;
		}

		/* If no space left at all and we still have descriptors to
		 * handle we iterate all remaining descriptors and increment
		 * the consumer pointer without handing the descriptors or
		 * copying the data.
		 */
		/* TODO: Assumption is that every response requires buffer
		 * (for notifications we have static buffer)
		 */
		if (msg_buf_left == 0)
			ARMADA_EP_LOG(DEBUG, "Skipping remaining descriptors as"
				      " no space left (cmd_code %d  cmd_idx "
				      "%d)", desc->cmd_code, desc->cmd_idx);

		buf_pos = CMD_FLAGS_BUF_POS_GET(desc->flags);

		if (sg_msg_flag) {
			ret = armada_ep_validate_s_g_msg_params(desc, buf_pos);
			if (ret)
				return ret;
		}

		/* Copy the message data only if there was no error and there is
		 * space in the buffer
		 */
		if (!ret && msg_buf_left) {
			memcpy((char *)msg_buf +
			      (ARMADA_EP_MGMT_DESC_DATA_LEN * desc_idx),
			       desc->data, copy_len);
			msg_buf_left -= copy_len;
			*msg_len += copy_len;
			desc_idx++;
		}

		/* Increment consumer counter */
		armada_ep_queue_ptr_inc(&cons_val, 1, notif_q->count);
	} while ((buf_pos != CMD_FLAG_BUF_POS_SINGLE) &&
		(buf_pos != CMD_FLAG_BUF_POS_LAST));

	/* Notify NIC with new consumer counter */
	//TODO: check if this writel is required
	writel(cons_val, notif_q->cons_p);
	return 0;
}

int
armada_ep_mgmt_notif_process(struct armada_ep_priv *priv, uint16_t cmd_code,
	void *msg)
{
	struct armada_ep_mgmt_notification *resp =
		(struct armada_ep_mgmt_notification *)msg;

	if (!priv) {
		ARMADA_EP_LOG(ERR, "no priv obj!");
		return -EINVAL;
	}

	ARMADA_EP_LOG(DEBUG, "Received notification id %d", cmd_code);

	switch (cmd_code) {
	case NC_PF_LINK_CHANGE:
		priv->link = resp->link_status;
		/* TODO: what do we need to do upon 'link-down/up' ? */
		ARMADA_EP_LOG(DEBUG, "got link %s",
			      priv->link ? "up" : "down");
		break;
	case NC_PF_KEEP_ALIVE:
		/* TODO: what do we need to do upon 'KA' ? */
		ARMADA_EP_LOG(DEBUG, "got KA");
		break;
	default:
		/* Unknown command code */
		ARMADA_EP_LOG(ERR, "Unknown command code %d!! Unable to process"
			      " command.", cmd_code);
		return -EOPNOTSUPP;
	}
	return 0;
}

static int
armada_ep_mgmt_resp_process(struct armada_ep_priv *priv, uint16_t cmd_idx,
				uint8_t cmd_code __rte_unused, void *msg,
				uint16_t len __rte_unused)
{
	struct armada_ep_queue *cmd_queue = &priv->cmd_queue;
	struct armada_ep_mgmt_cookie *mgmt_buff;
	struct armada_ep_mgmt_cmd_resp *cmd_resp =
		(struct armada_ep_mgmt_cmd_resp *)msg;

	/* grab the commands buffer */
	mgmt_buff = &cmd_queue->mgmt_cookie_list[cmd_idx];

	mgmt_buff->result = cmd_resp->status;

	/* For responses there is no need to handle the mgmt_buff if there was
	 * an error. we just trigger the event to wake the caller.
	 */
	if (mgmt_buff->result != ARMADA_EP_NOTIF_STATUS_OK) {
		ARMADA_EP_LOG(ERR, "netdev Notification status is failure "
			      "(0x%x).", mgmt_buff->result);
		return -1;
	}

	/* Make sure all logic above (including buf copy in caller function),
	 * was observed before releasing the command issuer.
	 */
	rte_wmb();
	mgmt_buff->wait_cause = MGMT_BUFF_NOTIF_RCV;

	return 0;
}

/* There are 3 response/notification types:
 * 1) netdev response: this is a response to a netdev command which
 *	was sent before. in this case we trigger the event that will wake-up
 *	the thread which sent the command
 *
 * 2) netdev notification: notification which are received asynchronously.
 *
 * 3) custom notification/response: notification/response which are part of
 *	the in-band management mechanism.
 */
static int armada_ep_mgmt_notif_dispatch(struct armada_ep_priv *priv,
		uint8_t client_type, uint16_t cmd_idx,
		uint8_t cmd_code, void *msg, uint16_t len)
{
	int ret = 0;
	/* (async) notification handling */
	if (cmd_idx == CMD_ID_NOTIFICATION) {
		if (client_type == CDT_PF) {
			ret = armada_ep_mgmt_notif_process(priv, cmd_code, msg);
			if (ret)
				return ret;
		}
	}

	/* response handling */
	return armada_ep_mgmt_resp_process(priv, cmd_idx, cmd_code, msg, len);
}

/*
 * mgmt_notif_handle - Handle management notifications.
 * Called by Notification ISR or a timer callback in case working in polling
 * mode.
 *
 * TODO: Add support for multi descriptor notifications.
 * TODO: Add support for external buffer notifications.
 */
int armada_ep_poll_mgmt(struct armada_ep_priv *priv)
{
	struct armada_ep_queue *notif_q = &priv->notif_queue;
	struct armada_ep_queue *cmd_q = &priv->cmd_queue;
	struct armada_ep_cmd_desc *desc;
	struct armada_ep_mgmt_cookie *mgmt_buff = NULL;
	void *msg_buf = NULL;
	int msg_buf_len, msg_len;
	uint16_t cmd_idx;
	int ret = 0;
	uint32_t cons_val;

	cons_val = readl(notif_q->cons_p);
	/* Check if anything should be done. */
	if (readl(notif_q->prod_p) == cons_val) {
		ARMADA_EP_LOG(DEBUG, "Notification ring is empty.");
		return -ENOMSG;
	}

	/* Get a pointer to the next Rx descriptor and relevant mgmt buffer
	 * info.
	 */
	desc = ((struct armada_ep_cmd_desc *)notif_q->desc) + cons_val;

	cmd_idx = desc->cmd_idx;

	if (cmd_idx == CMD_ID_NOTIFICATION) {
		/* For async notifications, no one allocated a buffer.
		 * Therefore, we use pre-allocated buffer.
		 * Note: we assume that these notifications are handled one by
		 * one (otherwise, this buffer will be overridden).
		 */
		msg_buf = armada_ep_notif_buf;
		msg_buf_len = ARMADA_EP_MGMT_NOTIF_BUF_SIZE;
	} else {
		/* Check that the cmd_idx is a valid one */
		if (cmd_idx > cmd_q->cookie_count) {
			ARMADA_EP_LOG(ERR, "Bad value in notification cmd_idx"
				      "(0x%x).", cmd_idx);
			ret = -EOVERFLOW;
			goto notify_error;
		}

		/* Now grab the commands buffer */
		mgmt_buff = &cmd_q->mgmt_cookie_list[cmd_idx];

		/* Take allocated buffer */
		msg_buf = mgmt_buff->buf;
		msg_buf_len = mgmt_buff->buf_len;

		if (msg_buf == NULL) {
			ARMADA_EP_LOG(ERR, "cmd code %d (cmd idx %d) has NULL"
				      " buffer. Skip this notification",
				      desc->cmd_code, cmd_idx);
			/* Increment the consumer so this failed message
			 * is skipped
			 */
			armada_ep_queue_ptr_inc(&cons_val, 1, notif_q->count);

			ret = -EINVAL;
			goto notify_error;
		}
	}

	/* For S/G message, need to loop the descriptors until reach buf-pos
	 * with value of LAST.
	 */
	ret = armada_ep_scatter_gather_msg(notif_q, msg_buf_len, desc, msg_buf,
		&msg_len);
	if (ret)
		goto notify_error;

	/* Call dispatcher only if we didn't reach here due to error */
	ret = armada_ep_mgmt_notif_dispatch(priv, desc->client_type,
		desc->cmd_idx, desc->cmd_code, msg_buf, msg_len);

	/* The mgmt_buff 'buf' field should be reset to indicate that this
	 * cookie entry is free
	 */
	if (mgmt_buff)
		mgmt_buff->buf = NULL;

	return ret;

notify_error:
	/* in case of an error, the mgmt_buff 'buf' field should be reset to
	 * indicate that this cookie entry is free
	 */
	if (mgmt_buff)
		mgmt_buff->buf = NULL;

	/* Notify NIC with new consumer counter */
	writel(cons_val, notif_q->cons_p);

	return ret;
}

static int
armada_ep_mgmt_command_resp_handle(struct armada_ep_priv *priv,
	struct armada_ep_msg_params *msg_params)
{
	struct armada_ep_queue *q = &priv->cmd_queue;
	struct armada_ep_mgmt_cookie *mgmt_buff;
	uint64_t timeout;
	int result;

	/* Check if length is OK */
	if (!msg_params->resp_msg_len) {
		ARMADA_EP_LOG(ERR, "armada_ep mgmt response buf length is 0");
		result = -EINVAL;
		goto error;
	}

	/* Get a pointer to the next Tx descriptor and relevant mgmt
	 * buffer info
	 */
	mgmt_buff = &q->mgmt_cookie_list[msg_params->cmd_idx];

	timeout = ARMADA_EP_MGMT_CMD_RESP_TIMEOUT;
	while ((mgmt_buff->wait_cause == MGMT_BUFF_CMD_SENT) && --timeout) {
		rte_delay_us(1000);
		armada_ep_poll_mgmt(priv);
	}
	if (!timeout) {
		ARMADA_EP_LOG(ERR, "Timeout while waiting for command"
			      "%d completion.", msg_params->cmd_code);
		result = -ETIMEDOUT;
		goto error;
	}

	/* Get notification data */
	result = mgmt_buff->result;

	/* update response size.
	 * Note that the data was copied to the buffer by notification handler
	 * so no need to copy it again.
	 */
	msg_params->resp_msg_len = sizeof(struct armada_ep_mgmt_cmd_resp);

error:
	return result;
}



/*
 * armada_ep_mgmt_command_send - Send simple control command, and wait for it's
 * completion.
 * This function does not support multi-descriptor commands, or commands with
 * external data buffers. Such commands should be implemented by a different
 * function.
 *
 * TODO: Add support for multi descriptor commands.
 * TODO: Add support for external buffer commands.
 */
static int
armada_ep_mgmt_command_send(struct armada_ep_priv *priv,
				struct armada_ep_msg_params *msg_params)
{
	int ret;

	ret = armada_ep_mgmt_command_send_process(priv, msg_params);
	if (ret) {
		ARMADA_EP_LOG(ERR, "agnic mgmt command send failed");
		return ret;
	}

	/* Check if response is required */
	if (!msg_params->resp_msg)
		return 0;

	ret = armada_ep_mgmt_command_resp_handle(priv, msg_params);
	if (ret) {
		ARMADA_EP_LOG(ERR, "agnic mgmt command recv failed");
		return ret;
	}

	return 0;
}

/*
 * armada_ep_init_io - Send the Rx / Tx / Control queues information into
 * the HW. This will actually send the required control messages to the NMP to
 * create the required "channels".
 */
int armada_ep_init_io(struct armada_ep_priv *priv)
{
	struct armada_ep_msg_params msg_params;
	struct armada_ep_mgmt_cmd_params cmd_params;
	struct armada_ep_mgmt_cmd_resp cmd_resp;
	struct armada_ep_queue *queue, *bp_queue;
	int msg_len = sizeof(struct armada_ep_mgmt_cmd_params);
	int resp_msg_len = sizeof(struct armada_ep_mgmt_cmd_resp);
	int ret, i;

	ARMADA_EP_LOG(DEBUG, "Configure queues in GIU.");

	/* Management echo. */
	ARMADA_EP_LOG(DEBUG, "Sending mgmt-echo.");
	msg_params.cmd_code = CC_PF_MGMT_ECHO;
	msg_params.client_id = priv->id;
	msg_params.client_type = CDT_VF;
	msg_params.msg = NULL; /* No msg params */
	msg_params.msg_len = 0;
	msg_params.resp_msg = &cmd_resp;
	msg_params.resp_msg_len = resp_msg_len;

	ret = armada_ep_mgmt_command_send(priv, &msg_params);
	if (ret)
		goto error;

	/* PF_VF_INIT */
	ARMADA_EP_LOG(DEBUG, "Sending PF_VF_INIT.");

	msg_params.cmd_code = CC_PF_VF_INIT;
	msg_params.client_id = priv->id;
	msg_params.client_type = CDT_VF;

	cmd_params.pf_vf_init.num_host_egress_tc = priv->num_out_tcs;
	cmd_params.pf_vf_init.num_host_ingress_tc = priv->num_in_tcs;
	cmd_params.pf_vf_init.egress_sched = ES_STRICT_SCHED;
	msg_params.msg = &cmd_params;
	msg_params.msg_len = msg_len;
	msg_params.resp_msg = &cmd_resp;
	msg_params.resp_msg_len = resp_msg_len;

	ret = armada_ep_mgmt_command_send(priv, &msg_params);
	if (ret)
		goto error;

	/* PF_VF_INGRESS_TC_ADD */
	ARMADA_EP_LOG(DEBUG, "Set ingress TC configuration.");
	msg_params.cmd_code = CC_PF_VF_INGRESS_TC_ADD;
	msg_params.client_id = priv->id;
	msg_params.client_type = CDT_VF;
	msg_params.msg = &cmd_params;
	msg_params.msg_len = msg_len;
	msg_params.resp_msg = &cmd_resp;
	msg_params.resp_msg_len = resp_msg_len;

	for (i = 0; i < priv->num_in_tcs; i++) {
		cmd_params.pf_vf_ingress_tc_add.tc = i;
		cmd_params.pf_vf_ingress_tc_add.num_queues =
			priv->num_qs_per_tc;
		cmd_params.pf_vf_ingress_tc_add.pkt_offset =
			priv->in_tcs[i].pkt_offset;
		cmd_params.pf_vf_ingress_tc_add.hash_type = priv->hash_type;

		ret = armada_ep_mgmt_command_send(priv, &msg_params);
		if (ret)
			goto error;
	}

	/* PF_VF_INGRESS_DATA_QUEUE_ADD */
	msg_params.cmd_code = CC_PF_VF_INGRESS_DATA_Q_ADD;
	msg_params.client_id = priv->id;
	msg_params.client_type = CDT_VF;
	msg_params.msg = &cmd_params;
	msg_params.msg_len = msg_len;
	msg_params.resp_msg = &cmd_resp;
	msg_params.resp_msg_len = resp_msg_len;

	for (i = 0; i < priv->num_rx_queues; i++) {
		ARMADA_EP_LOG(DEBUG, "Add ingress queue #%d.", i);
		queue = priv->rx_queue[i];
		cmd_params.pf_vf_ingress_data_q_add.tc = queue->tc;
		cmd_params.pf_vf_ingress_data_q_add.q_phys_addr = queue->dma;
		cmd_params.pf_vf_ingress_data_q_add.q_len = queue->count;
		cmd_params.pf_vf_ingress_data_q_add.q_prod_offs =
			armada_ep_q_indx_local_phys(priv->q_indices_arr_phys,
				queue->prod_idx);
		cmd_params.pf_vf_ingress_data_q_add.q_cons_offs =
			armada_ep_q_indx_local_phys(priv->q_indices_arr_phys,
				queue->cons_idx);

		cmd_params.pf_vf_ingress_data_q_add.msix_id =
			priv->rx_queue[i]->intr_vec;

		bp_queue = &priv->bp_queue[i];
		cmd_params.pf_vf_ingress_data_q_add.bpool_q_phys_addr =
			bp_queue->dma;
		cmd_params.pf_vf_ingress_data_q_add.bpool_q_prod_offs =
			armada_ep_q_indx_local_phys(priv->q_indices_arr_phys,
				bp_queue->prod_idx);
		cmd_params.pf_vf_ingress_data_q_add.bpool_q_cons_offs =
			armada_ep_q_indx_local_phys(priv->q_indices_arr_phys,
				bp_queue->cons_idx);
		cmd_params.pf_vf_ingress_data_q_add.q_buf_size =
			bp_queue->bp_frag_size;

		ret = armada_ep_mgmt_command_send(priv, &msg_params);
		if (ret)
			goto error;
	}

	/* PF_VF_EGRESS_TC_ADD */
	ARMADA_EP_LOG(DEBUG, "Set egress TC configuration.");
	msg_params.cmd_code = CC_PF_VF_EGRESS_TC_ADD;
	msg_params.client_id = priv->id;
	msg_params.client_type = CDT_VF;
	msg_params.msg = &cmd_params;
	msg_params.msg_len = msg_len;
	msg_params.resp_msg = &cmd_resp;
	msg_params.resp_msg_len = resp_msg_len;

	for (i = 0; i < priv->num_out_tcs; i++) {
		cmd_params.pf_vf_egress_tc_add.tc = i;
		cmd_params.pf_vf_egress_tc_add.num_queues = priv->num_qs_per_tc;

		ret = armada_ep_mgmt_command_send(priv, &msg_params);

		if (ret)
			goto error;
	}

	/* PF_VF_EGRESS_DATA_QUEUE_ADD */
	msg_params.cmd_code = CC_PF_VF_EGRESS_DATA_Q_ADD;
	msg_params.client_id = priv->id;
	msg_params.client_type = CDT_VF;
	msg_params.msg = &cmd_params;
	msg_params.msg_len = msg_len;
	msg_params.resp_msg = &cmd_resp;
	msg_params.resp_msg_len = resp_msg_len;

	for (i = 0; i < priv->num_tx_queues; i++) {
		ARMADA_EP_LOG(DEBUG, "Add egress queue #%d.", i);
		queue = priv->tx_queue[i];

		cmd_params.pf_vf_egress_q_add.q_phys_addr = queue->dma;
		cmd_params.pf_vf_egress_q_add.q_len = queue->count;
		cmd_params.pf_vf_egress_q_add.q_prod_offs =
			armada_ep_q_indx_local_phys(priv->q_indices_arr_phys,
				queue->prod_idx);
		cmd_params.pf_vf_egress_q_add.q_cons_offs =
			armada_ep_q_indx_local_phys(priv->q_indices_arr_phys,
				queue->cons_idx);

		/* MSI-X are not enabled */
		cmd_params.pf_vf_egress_q_add.msix_id =
			ARMADA_EP_MGMT_MSIX_ID_INVALID;

		/* Meanwhile, we support only strict prio */
		cmd_params.pf_vf_egress_q_add.q_wrr_weight = 0;
		cmd_params.pf_vf_egress_q_add.tc = queue->tc;

		ret = armada_ep_mgmt_command_send(priv, &msg_params);
		if (ret)
			goto error;
	}

	/* PF_VF_INIT_DONE */
	ARMADA_EP_LOG(DEBUG, "Send INIT_DONE command.");
	msg_params.cmd_code = CC_PF_VF_INIT_DONE;
	msg_params.client_id = priv->id;
	msg_params.client_type = CDT_VF;
	msg_params.msg = NULL; /* No msg params */
	msg_params.msg_len = 0;
	msg_params.resp_msg = &cmd_resp;
	msg_params.resp_msg_len = sizeof(cmd_resp);

	ret = armada_ep_mgmt_command_send(priv, &msg_params);
	if (ret)
		goto error;

	return 0;
error:
	/* TODO: Define configuration rollback at NIC level, then implement
	 * here.
	 */
	ARMADA_EP_LOG(ERR, "Failed to configure network queues into "
		      "hardware.");
	return ret;
}

int armada_ep_deinit_io(struct armada_ep_priv *priv)
{
	struct armada_ep_msg_params msg_params;
	struct armada_ep_mgmt_cmd_resp cmd_resp;
	int resp_msg_len = sizeof(struct armada_ep_mgmt_cmd_resp);
	int ret;

	/* close command */
	ARMADA_EP_LOG(DEBUG, "Sending close.");
	msg_params.cmd_code = CC_PF_VF_CLOSE;
	msg_params.client_id = priv->id;
	msg_params.client_type = CDT_VF;
	msg_params.msg = NULL; /* No msg params */
	msg_params.msg_len = 0;
	msg_params.resp_msg = &cmd_resp;
	msg_params.resp_msg_len = resp_msg_len;

	ret = armada_ep_mgmt_command_send(priv, &msg_params);
	if (ret) {
		ARMADA_EP_LOG(ERR, "Failed to set %s command!", "close");
		return ret;
	}

	return 0;
}

int armada_ep_pf_vf_get_capabilities(struct armada_ep_priv *priv)
{
	int ret;
	struct armada_ep_msg_params msg_params;
	struct armada_ep_mgmt_cmd_resp cmd_resp;

	if (!priv) {
		ARMADA_EP_LOG(ERR, "no priv obj!");
		return -EINVAL;
	}

	msg_params.client_id = priv->id;
	msg_params.client_type = CDT_VF;
	msg_params.msg = NULL;    /* No msg params */
	msg_params.msg_len = 0;
	msg_params.cmd_code = CC_PF_VF_GET_CAPABILITIES;
	msg_params.resp_msg = &cmd_resp;
	msg_params.resp_msg_len = sizeof(cmd_resp);

	ret = armada_ep_mgmt_command_send(priv, &msg_params);
	if (ret) {
		ARMADA_EP_LOG(ERR, "Failed to set %s command!", "enable");
		return ret;
	}

	memcpy(&priv->pf_vf_capabilities,
	       &cmd_resp.pf_vf_capabilities,
	       sizeof(struct armada_ep_mgmt_capabilities));

	return 0;
}

int armada_ep_pf_vf_enable(struct armada_ep_priv *priv, uint8_t *resp_status)
{
	int ret;
	struct armada_ep_msg_params msg_params;
	struct armada_ep_mgmt_cmd_resp cmd_resp;

	if (!priv) {
		ARMADA_EP_LOG(ERR, "no priv obj!");
		return -EINVAL;
	}

	msg_params.client_id = priv->id;
	msg_params.client_type = CDT_VF;
	msg_params.msg = NULL;    /* No msg params */
	msg_params.msg_len = 0;
	msg_params.cmd_code = CC_PF_VF_ENABLE;
	msg_params.resp_msg = &cmd_resp;
	msg_params.resp_msg_len = sizeof(cmd_resp);

	ret = armada_ep_mgmt_command_send(priv, &msg_params);
	if (ret) {
		ARMADA_EP_LOG(ERR, "Failed to set %s command!", "enable");
		return ret;
	}

	*resp_status = cmd_resp.status;

	return 0;
}

int armada_ep_pf_vf_disable(struct armada_ep_priv *priv)
{
	int ret;
	struct armada_ep_msg_params msg_params;
	struct armada_ep_mgmt_cmd_resp cmd_resp;

	if (!priv) {
		ARMADA_EP_LOG(ERR, "no priv obj!");
		return -EINVAL;
	}

	msg_params.client_id = priv->id;
	msg_params.client_type = CDT_VF;
	msg_params.msg = NULL;    /* No msg params */
	msg_params.msg_len = 0;
	msg_params.cmd_code = CC_PF_VF_DISABLE;
	msg_params.resp_msg = &cmd_resp;
	msg_params.resp_msg_len = sizeof(cmd_resp);

	ret = armada_ep_mgmt_command_send(priv, &msg_params);
	if (ret) {
		ARMADA_EP_LOG(ERR, "Failed to set %s command!", "disable");
		return ret;
	}

	return 0;
}

int armada_ep_pf_vf_link_status(struct armada_ep_priv *priv,
				uint32_t *link_status)
{
	int ret;
	struct armada_ep_msg_params msg_params;
	struct armada_ep_mgmt_cmd_resp cmd_resp;

	if (!priv) {
		ARMADA_EP_LOG(ERR, "no priv obj!");
		return -EINVAL;
	}

	msg_params.client_id = priv->id;
	msg_params.client_type = CDT_VF;
	msg_params.msg = NULL;    /* No msg params */
	msg_params.msg_len = 0;
	msg_params.cmd_code = CC_PF_VF_LINK_STATUS;
	msg_params.resp_msg = &cmd_resp;
	msg_params.resp_msg_len = sizeof(cmd_resp);

	ret = armada_ep_mgmt_command_send(priv, &msg_params);
	if (ret) {
		ARMADA_EP_LOG(ERR, "Failed to set %s command!", "link_status");
		return ret;
	}
	*link_status = cmd_resp.link_status;

	return 0;
}


/* TODO: implement ...
 * int armada_ep_pfio_get_mac_addr(struct armada_ep_priv *priv,
 * eth_addr_t addr);
 * int armada_ep_pfio_get_mtu(struct armada_ep_priv *priv, uint16_t *mtu);
 * int armada_ep_pfio_set_mru(struct armada_ep_priv *priv, uint16_t len);
 * int armada_ep_pfio_get_mru(struct armada_ep_priv *priv, uint16_t *len);
 * int armada_ep_pfio_set_promisc(struct armada_ep_priv *priv, int en);
 * int armada_ep_pfio_get_promisc(struct armada_ep_priv *priv, int *en);
 * int armada_ep_pfio_set_mc_promisc(struct armada_ep_priv *priv, int en);
 * int armada_ep_pfio_get_mc_promisc(struct armada_ep_priv *priv, int *en);
 * int armada_ep_pfio_add_mac_addr(struct armada_ep_priv *priv,
 * const eth_addr_t addr);
 * int armada_ep_pfio_remove_mac_addr(struct armada_ep_priv *priv,
 * const eth_addr_t addr);
 * int armada_ep_pfio_flush_mac_addrs(struct armada_ep_priv *priv, int uc,
 * int mc);
 * int armada_ep_pfio_get_statistics(struct armada_ep_priv *priv,
 * struct armada_ep_pfio_statistics *stats);
 * int armada_ep_pfio_set_link_state(struct armada_ep_priv *priv, int en);
 */



