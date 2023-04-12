/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2018 Cavium, Inc
 */

#include <rte_alarm.h>
#include <rte_bus_pci.h>
#include <rte_cryptodev.h>
#include <rte_cryptodev_pmd.h>
#include <rte_errno.h>
#include <rte_malloc.h>
#include <rte_mempool.h>

#include "otx_cryptodev.h"
#include "otx_cryptodev_capabilities.h"
#include "otx_cryptodev_hw_access.h"
#include "otx_cryptodev_mbox.h"
#include "otx_cryptodev_ops.h"

#include "cpt_pmd_logs.h"
#include "cpt_pmd_ops_helper.h"
#include "cpt_ucode.h"
#include "cpt_ucode_asym.h"

static uint64_t otx_fpm_iova[CPT_EC_ID_PMAX];

/* Forward declarations */

static int
otx_cpt_que_pair_release(struct rte_cryptodev *dev, uint16_t que_pair_id);

/* Alarm routines */

static void
otx_cpt_alarm_cb(void *arg)
{
	struct cpt_vf *cptvf = arg;
	otx_cpt_poll_misc(cptvf);
	rte_eal_alarm_set(CPT_INTR_POLL_INTERVAL_MS * 1000,
			  otx_cpt_alarm_cb, cptvf);
}

static int
otx_cpt_periodic_alarm_start(void *arg)
{
	return rte_eal_alarm_set(CPT_INTR_POLL_INTERVAL_MS * 1000,
				 otx_cpt_alarm_cb, arg);
}

static int
otx_cpt_periodic_alarm_stop(void *arg)
{
	return rte_eal_alarm_cancel(otx_cpt_alarm_cb, arg);
}

/* PMD ops */

static int
otx_cpt_dev_config(struct rte_cryptodev *dev,
		   struct rte_cryptodev_config *config __rte_unused)
{
	int ret = 0;

	CPT_PMD_INIT_FUNC_TRACE();

	if (dev->feature_flags & RTE_CRYPTODEV_FF_ASYMMETRIC_CRYPTO)
		/* Initialize shared FPM table */
		ret = cpt_fpm_init(otx_fpm_iova);

	return ret;
}

static int
otx_cpt_dev_start(struct rte_cryptodev *c_dev)
{
	void *cptvf = c_dev->data->dev_private;

	CPT_PMD_INIT_FUNC_TRACE();

	return otx_cpt_start_device(cptvf);
}

static void
otx_cpt_dev_stop(struct rte_cryptodev *c_dev)
{
	void *cptvf = c_dev->data->dev_private;

	CPT_PMD_INIT_FUNC_TRACE();

	if (c_dev->feature_flags & RTE_CRYPTODEV_FF_ASYMMETRIC_CRYPTO)
		cpt_fpm_clear();

	otx_cpt_stop_device(cptvf);
}

static int
otx_cpt_dev_close(struct rte_cryptodev *c_dev)
{
	void *cptvf = c_dev->data->dev_private;
	int i, ret;

	CPT_PMD_INIT_FUNC_TRACE();

	for (i = 0; i < c_dev->data->nb_queue_pairs; i++) {
		ret = otx_cpt_que_pair_release(c_dev, i);
		if (ret)
			return ret;
	}

	otx_cpt_periodic_alarm_stop(cptvf);
	otx_cpt_deinit_device(cptvf);

	return 0;
}

static void
otx_cpt_dev_info_get(struct rte_cryptodev *dev, struct rte_cryptodev_info *info)
{
	CPT_PMD_INIT_FUNC_TRACE();
	if (info != NULL) {
		info->max_nb_queue_pairs = CPT_NUM_QS_PER_VF;
		info->feature_flags = dev->feature_flags;
		info->capabilities = otx_get_capabilities(info->feature_flags);
		info->sym.max_nb_sessions = 0;
		info->driver_id = otx_cryptodev_driver_id;
		info->min_mbuf_headroom_req = OTX_CPT_MIN_HEADROOM_REQ;
		info->min_mbuf_tailroom_req = OTX_CPT_MIN_TAILROOM_REQ;
	}
}

static void
otx_cpt_stats_get(struct rte_cryptodev *dev __rte_unused,
		  struct rte_cryptodev_stats *stats __rte_unused)
{
	CPT_PMD_INIT_FUNC_TRACE();
}

static void
otx_cpt_stats_reset(struct rte_cryptodev *dev __rte_unused)
{
	CPT_PMD_INIT_FUNC_TRACE();
}

static int
otx_cpt_que_pair_setup(struct rte_cryptodev *dev,
		       uint16_t que_pair_id,
		       const struct rte_cryptodev_qp_conf *qp_conf,
		       int socket_id __rte_unused)
{
	struct cpt_instance *instance = NULL;
	struct rte_pci_device *pci_dev;
	int ret = -1;

	CPT_PMD_INIT_FUNC_TRACE();

	if (dev->data->queue_pairs[que_pair_id] != NULL) {
		ret = otx_cpt_que_pair_release(dev, que_pair_id);
		if (ret)
			return ret;
	}

	if (qp_conf->nb_descriptors > DEFAULT_CMD_QLEN) {
		CPT_LOG_INFO("Number of descriptors too big %d, using default "
			     "queue length of %d", qp_conf->nb_descriptors,
			     DEFAULT_CMD_QLEN);
	}

	pci_dev = RTE_DEV_TO_PCI(dev->device);

	if (pci_dev->mem_resource[0].addr == NULL) {
		CPT_LOG_ERR("PCI mem address null");
		return -EIO;
	}

	ret = otx_cpt_get_resource(dev, 0, &instance, que_pair_id);
	if (ret != 0 || instance == NULL) {
		CPT_LOG_ERR("Error getting instance handle from device %s : "
			    "ret = %d", dev->data->name, ret);
		return ret;
	}

	instance->queue_id = que_pair_id;
	instance->sess_mp = qp_conf->mp_session;
	instance->sess_mp_priv = qp_conf->mp_session_private;
	dev->data->queue_pairs[que_pair_id] = instance;

	return 0;
}

static int
otx_cpt_que_pair_release(struct rte_cryptodev *dev, uint16_t que_pair_id)
{
	struct cpt_instance *instance = dev->data->queue_pairs[que_pair_id];
	int ret;

	CPT_PMD_INIT_FUNC_TRACE();

	ret = otx_cpt_put_resource(instance);
	if (ret != 0) {
		CPT_LOG_ERR("Error putting instance handle of device %s : "
			    "ret = %d", dev->data->name, ret);
		return ret;
	}

	dev->data->queue_pairs[que_pair_id] = NULL;

	return 0;
}

static unsigned int
otx_cpt_get_session_size(struct rte_cryptodev *dev __rte_unused)
{
	return cpt_get_session_size();
}

static void
otx_cpt_session_init(void *sym_sess, uint8_t driver_id)
{
	struct rte_cryptodev_sym_session *sess = sym_sess;
	struct cpt_sess_misc *cpt_sess =
	 (struct cpt_sess_misc *) get_sym_session_private_data(sess, driver_id);

	CPT_PMD_INIT_FUNC_TRACE();
	cpt_sess->ctx_dma_addr = rte_mempool_virt2iova(cpt_sess) +
			sizeof(struct cpt_sess_misc);
}

static int
otx_cpt_session_cfg(struct rte_cryptodev *dev,
		    struct rte_crypto_sym_xform *xform,
		    struct rte_cryptodev_sym_session *sess,
		    struct rte_mempool *mempool)
{
	struct rte_crypto_sym_xform *chain;
	void *sess_private_data = NULL;

	CPT_PMD_INIT_FUNC_TRACE();

	if (cpt_is_algo_supported(xform))
		goto err;

	if (unlikely(sess == NULL)) {
		CPT_LOG_ERR("invalid session struct");
		return -EINVAL;
	}

	if (rte_mempool_get(mempool, &sess_private_data)) {
		CPT_LOG_ERR("Could not allocate sess_private_data");
		return -ENOMEM;
	}

	chain = xform;
	while (chain) {
		switch (chain->type) {
		case RTE_CRYPTO_SYM_XFORM_AEAD:
			if (fill_sess_aead(chain, sess_private_data))
				goto err;
			break;
		case RTE_CRYPTO_SYM_XFORM_CIPHER:
			if (fill_sess_cipher(chain, sess_private_data))
				goto err;
			break;
		case RTE_CRYPTO_SYM_XFORM_AUTH:
			if (chain->auth.algo == RTE_CRYPTO_AUTH_AES_GMAC) {
				if (fill_sess_gmac(chain, sess_private_data))
					goto err;
			} else {
				if (fill_sess_auth(chain, sess_private_data))
					goto err;
			}
			break;
		default:
			CPT_LOG_ERR("Invalid crypto xform type");
			break;
		}
		chain = chain->next;
	}
	set_sym_session_private_data(sess, dev->driver_id, sess_private_data);
	otx_cpt_session_init(sess, dev->driver_id);
	return 0;

err:
	if (sess_private_data)
		rte_mempool_put(mempool, sess_private_data);
	return -EPERM;
}

static void
otx_cpt_session_clear(struct rte_cryptodev *dev,
		  struct rte_cryptodev_sym_session *sess)
{
	void *sess_priv = get_sym_session_private_data(sess, dev->driver_id);

	CPT_PMD_INIT_FUNC_TRACE();
	if (sess_priv) {
		memset(sess_priv, 0, otx_cpt_get_session_size(dev));
		struct rte_mempool *sess_mp = rte_mempool_from_obj(sess_priv);
		set_sym_session_private_data(sess, dev->driver_id, NULL);
		rte_mempool_put(sess_mp, sess_priv);
	}
}

static unsigned int
otx_cpt_asym_session_size_get(struct rte_cryptodev *dev __rte_unused)
{
	return sizeof(struct cpt_asym_sess_misc);
}

static int
otx_cpt_asym_session_cfg(struct rte_cryptodev *dev,
			 struct rte_crypto_asym_xform *xform __rte_unused,
			 struct rte_cryptodev_asym_session *sess,
			 struct rte_mempool *pool)
{
	struct cpt_asym_sess_misc *priv;
	int ret;

	CPT_PMD_INIT_FUNC_TRACE();

	if (rte_mempool_get(pool, (void **)&priv)) {
		CPT_LOG_ERR("Could not allocate session private data");
		return -ENOMEM;
	}

	memset(priv, 0, sizeof(struct cpt_asym_sess_misc));

	ret = cpt_fill_asym_session_parameters(priv, xform);
	if (ret) {
		CPT_LOG_ERR("Could not configure session parameters");

		/* Return session to mempool */
		rte_mempool_put(pool, priv);
		return ret;
	}

	set_asym_session_private_data(sess, dev->driver_id, priv);
	return 0;
}

static void
otx_cpt_asym_session_clear(struct rte_cryptodev *dev,
			   struct rte_cryptodev_asym_session *sess)
{
	struct cpt_asym_sess_misc *priv;
	struct rte_mempool *sess_mp;

	CPT_PMD_INIT_FUNC_TRACE();

	priv = get_asym_session_private_data(sess, dev->driver_id);

	if (priv == NULL)
		return;

	/* Free resources allocated during session configure */
	cpt_free_asym_session_parameters(priv);
	memset(priv, 0, otx_cpt_asym_session_size_get(dev));
	sess_mp = rte_mempool_from_obj(priv);
	set_asym_session_private_data(sess, dev->driver_id, NULL);
	rte_mempool_put(sess_mp, priv);
}

static __rte_always_inline int32_t __hot
otx_cpt_request_enqueue(struct cpt_instance *instance,
			struct pending_queue *pqueue,
			void *req)
{
	struct cpt_request_info *user_req = (struct cpt_request_info *)req;

	if (unlikely(pqueue->pending_count >= DEFAULT_CMD_QLEN))
		return -EAGAIN;

	fill_cpt_inst(instance, req);

	CPT_LOG_DP_DEBUG("req: %p op: %p ", req, user_req->op);

	/* Fill time_out cycles */
	user_req->time_out = rte_get_timer_cycles() +
			DEFAULT_COMMAND_TIMEOUT * rte_get_timer_hz();
	user_req->extra_time = 0;

	/* Default mode of software queue */
	mark_cpt_inst(instance);

	pqueue->rid_queue[pqueue->enq_tail].rid = (uintptr_t)user_req;

	/* We will use soft queue length here to limit requests */
	MOD_INC(pqueue->enq_tail, DEFAULT_CMD_QLEN);
	pqueue->pending_count += 1;

	CPT_LOG_DP_DEBUG("Submitted NB cmd with request: %p "
			 "op: %p", user_req, user_req->op);
	return 0;
}

static __rte_always_inline int __hot
otx_cpt_enq_single_asym(struct cpt_instance *instance,
			struct rte_crypto_op *op,
			struct pending_queue *pqueue)
{
	struct cpt_qp_meta_info *minfo = &instance->meta_info;
	struct rte_crypto_asym_op *asym_op = op->asym;
	struct asym_op_params params = {0};
	struct cpt_asym_sess_misc *sess;
	uintptr_t *cop;
	void *mdata;
	int ret;

	if (unlikely(rte_mempool_get(minfo->pool, &mdata) < 0)) {
		CPT_LOG_DP_ERR("Could not allocate meta buffer for request");
		return -ENOMEM;
	}

	sess = get_asym_session_private_data(asym_op->session,
					     otx_cryptodev_driver_id);

	/* Store phys_addr of the mdata to meta_buf */
	params.meta_buf = rte_mempool_virt2iova(mdata);

	cop = mdata;
	cop[0] = (uintptr_t)mdata;
	cop[1] = (uintptr_t)op;
	cop[2] = cop[3] = 0ULL;

	params.req = RTE_PTR_ADD(cop, 4 * sizeof(uintptr_t));
	params.req->op = cop;

	/* Adjust meta_buf by crypto_op data  and request_info struct */
	params.meta_buf += (4 * sizeof(uintptr_t)) +
			   sizeof(struct cpt_request_info);

	switch (sess->xfrm_type) {
	case RTE_CRYPTO_ASYM_XFORM_MODEX:
		ret = cpt_modex_prep(&params, &sess->mod_ctx);
		if (unlikely(ret))
			goto req_fail;
		break;
	case RTE_CRYPTO_ASYM_XFORM_RSA:
		ret = cpt_enqueue_rsa_op(op, &params, sess);
		if (unlikely(ret))
			goto req_fail;
		break;
	case RTE_CRYPTO_ASYM_XFORM_ECDSA:
		ret = cpt_enqueue_ecdsa_op(op, &params, sess, otx_fpm_iova);
		if (unlikely(ret))
			goto req_fail;
		break;
	case RTE_CRYPTO_ASYM_XFORM_ECPM:
		ret = cpt_ecpm_prep(&asym_op->ecpm, &params,
				    sess->ec_ctx.curveid);
		if (unlikely(ret))
			goto req_fail;
		break;

	default:
		op->status = RTE_CRYPTO_OP_STATUS_INVALID_ARGS;
		ret = -EINVAL;
		goto req_fail;
	}

	ret = otx_cpt_request_enqueue(instance, pqueue, params.req);

	if (unlikely(ret)) {
		CPT_LOG_DP_ERR("Could not enqueue crypto req");
		goto req_fail;
	}

	return 0;

req_fail:
	free_op_meta(mdata, minfo->pool);

	return ret;
}

static __rte_always_inline int __hot
otx_cpt_enq_single_sym(struct cpt_instance *instance,
		       struct rte_crypto_op *op,
		       struct pending_queue *pqueue)
{
	struct cpt_sess_misc *sess;
	struct rte_crypto_sym_op *sym_op = op->sym;
	void *prep_req, *mdata = NULL;
	int ret = 0;
	uint64_t cpt_op;

	sess = (struct cpt_sess_misc *)
			get_sym_session_private_data(sym_op->session,
						     otx_cryptodev_driver_id);

	cpt_op = sess->cpt_op;

	if (likely(cpt_op & CPT_OP_CIPHER_MASK))
		ret = fill_fc_params(op, sess, &instance->meta_info, &mdata,
				     &prep_req);
	else
		ret = fill_digest_params(op, sess, &instance->meta_info,
					 &mdata, &prep_req);

	if (unlikely(ret)) {
		CPT_LOG_DP_ERR("prep cryto req : op %p, cpt_op 0x%x "
			       "ret 0x%x", op, (unsigned int)cpt_op, ret);
		return ret;
	}

	/* Enqueue prepared instruction to h/w */
	ret = otx_cpt_request_enqueue(instance, pqueue, prep_req);

	if (unlikely(ret)) {
		/* Buffer allocated for request preparation need to be freed */
		free_op_meta(mdata, instance->meta_info.pool);
		return ret;
	}

	return 0;
}

static __rte_always_inline int __hot
otx_cpt_enq_single_sym_sessless(struct cpt_instance *instance,
				struct rte_crypto_op *op,
				struct pending_queue *pqueue)
{
	struct cpt_sess_misc *sess;
	struct rte_crypto_sym_op *sym_op = op->sym;
	int ret;
	void *sess_t = NULL;
	void *sess_private_data_t = NULL;

	/* Create tmp session */

	if (rte_mempool_get(instance->sess_mp, (void **)&sess_t)) {
		ret = -ENOMEM;
		goto exit;
	}

	if (rte_mempool_get(instance->sess_mp_priv,
			(void **)&sess_private_data_t)) {
		ret = -ENOMEM;
		goto free_sess;
	}

	sess = (struct cpt_sess_misc *)sess_private_data_t;

	sess->ctx_dma_addr = rte_mempool_virt2iova(sess) +
			sizeof(struct cpt_sess_misc);

	ret = instance_session_cfg(sym_op->xform, (void *)sess);
	if (unlikely(ret)) {
		ret = -EINVAL;
		goto free_sess_priv;
	}

	/* Save tmp session in op */

	sym_op->session = (struct rte_cryptodev_sym_session *)sess_t;
	set_sym_session_private_data(sym_op->session, otx_cryptodev_driver_id,
				     sess_private_data_t);

	/* Enqueue op with the tmp session set */
	ret = otx_cpt_enq_single_sym(instance, op, pqueue);

	if (unlikely(ret))
		goto free_sess_priv;

	return 0;

free_sess_priv:
	rte_mempool_put(instance->sess_mp_priv, sess_private_data_t);
free_sess:
	rte_mempool_put(instance->sess_mp, sess_t);
exit:
	return ret;
}

#define OP_TYPE_SYM		0
#define OP_TYPE_ASYM		1

static __rte_always_inline int __hot
otx_cpt_enq_single(struct cpt_instance *inst,
		   struct rte_crypto_op *op,
		   struct pending_queue *pqueue,
		   const uint8_t op_type)
{
	/* Check for the type */

	if (op_type == OP_TYPE_SYM) {
		if (op->sess_type == RTE_CRYPTO_OP_WITH_SESSION)
			return otx_cpt_enq_single_sym(inst, op, pqueue);
		else
			return otx_cpt_enq_single_sym_sessless(inst, op,
							       pqueue);
	}

	if (op_type == OP_TYPE_ASYM) {
		if (op->sess_type == RTE_CRYPTO_OP_WITH_SESSION)
			return otx_cpt_enq_single_asym(inst, op, pqueue);
	}

	/* Should not reach here */
	return -ENOTSUP;
}

static  __rte_always_inline uint16_t __hot
otx_cpt_pkt_enqueue(void *qptr, struct rte_crypto_op **ops, uint16_t nb_ops,
		    const uint8_t op_type)
{
	struct cpt_instance *instance = (struct cpt_instance *)qptr;
	uint16_t count;
	int ret;
	struct cpt_vf *cptvf = (struct cpt_vf *)instance;
	struct pending_queue *pqueue = &cptvf->pqueue;

	count = DEFAULT_CMD_QLEN - pqueue->pending_count;
	if (nb_ops > count)
		nb_ops = count;

	count = 0;
	while (likely(count < nb_ops)) {

		/* Enqueue single op */
		ret = otx_cpt_enq_single(instance, ops[count], pqueue, op_type);

		if (unlikely(ret))
			break;
		count++;
	}
	otx_cpt_ring_dbell(instance, count);
	return count;
}

static uint16_t
otx_cpt_enqueue_asym(void *qptr, struct rte_crypto_op **ops, uint16_t nb_ops)
{
	return otx_cpt_pkt_enqueue(qptr, ops, nb_ops, OP_TYPE_ASYM);
}

static uint16_t
otx_cpt_enqueue_sym(void *qptr, struct rte_crypto_op **ops, uint16_t nb_ops)
{
	return otx_cpt_pkt_enqueue(qptr, ops, nb_ops, OP_TYPE_SYM);
}

static inline void
otx_cpt_asym_rsa_op(struct rte_crypto_op *cop, struct cpt_request_info *req,
		    struct rte_crypto_rsa_xform *rsa_ctx)

{
	struct rte_crypto_rsa_op_param *rsa = &cop->asym->rsa;

	switch (rsa->op_type) {
	case RTE_CRYPTO_ASYM_OP_ENCRYPT:
		rsa->cipher.length = rsa_ctx->n.length;
		memcpy(rsa->cipher.data, req->rptr, rsa->cipher.length);
		break;
	case RTE_CRYPTO_ASYM_OP_DECRYPT:
		if (rsa->pad == RTE_CRYPTO_RSA_PADDING_NONE)
			rsa->message.length = rsa_ctx->n.length;
		else {
			/* Get length of decrypted output */
			rsa->message.length = rte_cpu_to_be_16
					(*((uint16_t *)req->rptr));

			/* Offset data pointer by length fields */
			req->rptr += 2;
		}
		memcpy(rsa->message.data, req->rptr, rsa->message.length);
		break;
	case RTE_CRYPTO_ASYM_OP_SIGN:
		rsa->sign.length = rsa_ctx->n.length;
		memcpy(rsa->sign.data, req->rptr, rsa->sign.length);
		break;
	case RTE_CRYPTO_ASYM_OP_VERIFY:
		if (rsa->pad == RTE_CRYPTO_RSA_PADDING_NONE)
			rsa->sign.length = rsa_ctx->n.length;
		else {
			/* Get length of decrypted output */
			rsa->sign.length = rte_cpu_to_be_16
					(*((uint16_t *)req->rptr));

			/* Offset data pointer by length fields */
			req->rptr += 2;
		}
		memcpy(rsa->sign.data, req->rptr, rsa->sign.length);

		if (memcmp(rsa->sign.data, rsa->message.data,
			   rsa->message.length)) {
			CPT_LOG_DP_ERR("RSA verification failed");
			cop->status = RTE_CRYPTO_OP_STATUS_ERROR;
		}
		break;
	default:
		CPT_LOG_DP_DEBUG("Invalid RSA operation type");
		cop->status = RTE_CRYPTO_OP_STATUS_INVALID_ARGS;
		break;
	}
}

static __rte_always_inline void
otx_cpt_asym_dequeue_ecdsa_op(struct rte_crypto_ecdsa_op_param *ecdsa,
			    struct cpt_request_info *req,
			    struct cpt_asym_ec_ctx *ec)

{
	int prime_len = ec_grp[ec->curveid].prime.length;

	if (ecdsa->op_type == RTE_CRYPTO_ASYM_OP_VERIFY)
		return;

	/* Separate out sign r and s components */
	memcpy(ecdsa->r.data, req->rptr, prime_len);
	memcpy(ecdsa->s.data, req->rptr + ROUNDUP8(prime_len), prime_len);
	ecdsa->r.length = prime_len;
	ecdsa->s.length = prime_len;
}

static __rte_always_inline void
otx_cpt_asym_dequeue_ecpm_op(struct rte_crypto_ecpm_op_param *ecpm,
			     struct cpt_request_info *req,
			     struct cpt_asym_ec_ctx *ec)
{
	int prime_len = ec_grp[ec->curveid].prime.length;

	memcpy(ecpm->r.x.data, req->rptr, prime_len);
	memcpy(ecpm->r.y.data, req->rptr + ROUNDUP8(prime_len), prime_len);
	ecpm->r.x.length = prime_len;
	ecpm->r.y.length = prime_len;
}

static __rte_always_inline void __hot
otx_cpt_asym_post_process(struct rte_crypto_op *cop,
			  struct cpt_request_info *req)
{
	struct rte_crypto_asym_op *op = cop->asym;
	struct cpt_asym_sess_misc *sess;

	sess = get_asym_session_private_data(op->session,
					     otx_cryptodev_driver_id);

	switch (sess->xfrm_type) {
	case RTE_CRYPTO_ASYM_XFORM_RSA:
		otx_cpt_asym_rsa_op(cop, req, &sess->rsa_ctx);
		break;
	case RTE_CRYPTO_ASYM_XFORM_MODEX:
		op->modex.result.length = sess->mod_ctx.modulus.length;
		memcpy(op->modex.result.data, req->rptr,
		       op->modex.result.length);
		break;
	case RTE_CRYPTO_ASYM_XFORM_ECDSA:
		otx_cpt_asym_dequeue_ecdsa_op(&op->ecdsa, req, &sess->ec_ctx);
		break;
	case RTE_CRYPTO_ASYM_XFORM_ECPM:
		otx_cpt_asym_dequeue_ecpm_op(&op->ecpm, req, &sess->ec_ctx);
		break;
	default:
		CPT_LOG_DP_DEBUG("Invalid crypto xform type");
		cop->status = RTE_CRYPTO_OP_STATUS_INVALID_ARGS;
		break;
	}
}

static __rte_always_inline void __hot
otx_cpt_dequeue_post_process(struct rte_crypto_op *cop, uintptr_t *rsp,
			     const uint8_t op_type)
{
	/* H/w has returned success */
	cop->status = RTE_CRYPTO_OP_STATUS_SUCCESS;

	/* Perform further post processing */

	if ((op_type == OP_TYPE_SYM) &&
	    (cop->type == RTE_CRYPTO_OP_TYPE_SYMMETRIC)) {
		/* Check if auth verify need to be completed */
		if (unlikely(rsp[2]))
			compl_auth_verify(cop, (uint8_t *)rsp[2], rsp[3]);
		return;
	}

	if ((op_type == OP_TYPE_ASYM) &&
	    (cop->type == RTE_CRYPTO_OP_TYPE_ASYMMETRIC)) {
		rsp = RTE_PTR_ADD(rsp, 4 * sizeof(uintptr_t));
		otx_cpt_asym_post_process(cop, (struct cpt_request_info *)rsp);
	}

	return;
}

static __rte_always_inline uint16_t __hot
otx_cpt_pkt_dequeue(void *qptr, struct rte_crypto_op **ops, uint16_t nb_ops,
		    const uint8_t op_type)
{
	struct cpt_instance *instance = (struct cpt_instance *)qptr;
	struct cpt_request_info *user_req;
	struct cpt_vf *cptvf = (struct cpt_vf *)instance;
	struct rid *rid_e;
	uint8_t cc[nb_ops];
	int i, count, pcount;
	uint8_t ret;
	int nb_completed;
	struct pending_queue *pqueue = &cptvf->pqueue;
	struct rte_crypto_op *cop;
	void *metabuf;
	uintptr_t *rsp;

	pcount = pqueue->pending_count;
	count = (nb_ops > pcount) ? pcount : nb_ops;

	for (i = 0; i < count; i++) {
		rid_e = &pqueue->rid_queue[pqueue->deq_head];
		user_req = (struct cpt_request_info *)(rid_e->rid);

		if (likely((i+1) < count))
			rte_prefetch_non_temporal((void *)rid_e[1].rid);

		ret = check_nb_command_id(user_req, instance);

		if (unlikely(ret == ERR_REQ_PENDING)) {
			/* Stop checking for completions */
			break;
		}

		/* Return completion code and op handle */
		cc[i] = ret;
		ops[i] = user_req->op;

		CPT_LOG_DP_DEBUG("Request %p Op %p completed with code %d",
				 user_req, user_req->op, ret);

		MOD_INC(pqueue->deq_head, DEFAULT_CMD_QLEN);
		pqueue->pending_count -= 1;
	}

	nb_completed = i;

	for (i = 0; i < nb_completed; i++) {

		rsp = (void *)ops[i];

		if (likely((i + 1) < nb_completed))
			rte_prefetch0(ops[i+1]);

		metabuf = (void *)rsp[0];
		cop = (void *)rsp[1];

		ops[i] = cop;

		/* Check completion code */

		if (likely(cc[i] == 0)) {
			/* H/w success pkt. Post process */
			otx_cpt_dequeue_post_process(cop, rsp, op_type);
		} else if (cc[i] == ERR_GC_ICV_MISCOMPARE) {
			/* auth data mismatch */
			cop->status = RTE_CRYPTO_OP_STATUS_AUTH_FAILED;
		} else {
			/* Error */
			cop->status = RTE_CRYPTO_OP_STATUS_ERROR;
		}

		if (unlikely(cop->sess_type == RTE_CRYPTO_OP_SESSIONLESS)) {
			void *sess_private_data_t =
				get_sym_session_private_data(cop->sym->session,
						otx_cryptodev_driver_id);
			memset(sess_private_data_t, 0,
					cpt_get_session_size());
			memset(cop->sym->session, 0,
			rte_cryptodev_sym_get_existing_header_session_size(
					cop->sym->session));
			rte_mempool_put(instance->sess_mp_priv,
					sess_private_data_t);
			rte_mempool_put(instance->sess_mp, cop->sym->session);
			cop->sym->session = NULL;
		}
		free_op_meta(metabuf, instance->meta_info.pool);
	}

	return nb_completed;
}

static uint16_t
otx_cpt_dequeue_asym(void *qptr, struct rte_crypto_op **ops, uint16_t nb_ops)
{
	return otx_cpt_pkt_dequeue(qptr, ops, nb_ops, OP_TYPE_ASYM);
}

static uint16_t
otx_cpt_dequeue_sym(void *qptr, struct rte_crypto_op **ops, uint16_t nb_ops)
{
	return otx_cpt_pkt_dequeue(qptr, ops, nb_ops, OP_TYPE_SYM);
}

static struct rte_cryptodev_ops cptvf_ops = {
	/* Device related operations */
	.dev_configure = otx_cpt_dev_config,
	.dev_start = otx_cpt_dev_start,
	.dev_stop = otx_cpt_dev_stop,
	.dev_close = otx_cpt_dev_close,
	.dev_infos_get = otx_cpt_dev_info_get,

	.stats_get = otx_cpt_stats_get,
	.stats_reset = otx_cpt_stats_reset,
	.queue_pair_setup = otx_cpt_que_pair_setup,
	.queue_pair_release = otx_cpt_que_pair_release,
	.queue_pair_count = NULL,

	/* Crypto related operations */
	.sym_session_get_size = otx_cpt_get_session_size,
	.sym_session_configure = otx_cpt_session_cfg,
	.sym_session_clear = otx_cpt_session_clear,

	.asym_session_get_size = otx_cpt_asym_session_size_get,
	.asym_session_configure = otx_cpt_asym_session_cfg,
	.asym_session_clear = otx_cpt_asym_session_clear,
};

int
otx_cpt_dev_create(struct rte_cryptodev *c_dev)
{
	struct rte_pci_device *pdev = RTE_DEV_TO_PCI(c_dev->device);
	struct cpt_vf *cptvf = NULL;
	void *reg_base;
	char dev_name[32];
	int ret;

	if (pdev->mem_resource[0].phys_addr == 0ULL)
		return -EIO;

	/* for secondary processes, we don't initialise any further as primary
	 * has already done this work.
	 */
	if (rte_eal_process_type() != RTE_PROC_PRIMARY)
		return 0;

	cptvf = rte_zmalloc_socket("otx_cryptodev_private_mem",
			sizeof(struct cpt_vf), RTE_CACHE_LINE_SIZE,
			rte_socket_id());

	if (cptvf == NULL) {
		CPT_LOG_ERR("Cannot allocate memory for device private data");
		return -ENOMEM;
	}

	snprintf(dev_name, 32, "%02x:%02x.%x",
			pdev->addr.bus, pdev->addr.devid, pdev->addr.function);

	reg_base = pdev->mem_resource[0].addr;
	if (!reg_base) {
		CPT_LOG_ERR("Failed to map BAR0 of %s", dev_name);
		ret = -ENODEV;
		goto fail;
	}

	ret = otx_cpt_hw_init(cptvf, pdev, reg_base, dev_name);
	if (ret) {
		CPT_LOG_ERR("Failed to init cptvf %s", dev_name);
		ret = -EIO;
		goto fail;
	}

	switch (cptvf->vftype) {
	case OTX_CPT_VF_TYPE_AE:
		/* Set asymmetric cpt feature flags */
		c_dev->feature_flags = RTE_CRYPTODEV_FF_ASYMMETRIC_CRYPTO |
				RTE_CRYPTODEV_FF_HW_ACCELERATED |
				RTE_CRYPTODEV_FF_RSA_PRIV_OP_KEY_QT;
		break;
	case OTX_CPT_VF_TYPE_SE:
		/* Set symmetric cpt feature flags */
		c_dev->feature_flags = RTE_CRYPTODEV_FF_SYMMETRIC_CRYPTO |
				RTE_CRYPTODEV_FF_HW_ACCELERATED |
				RTE_CRYPTODEV_FF_SYM_OPERATION_CHAINING |
				RTE_CRYPTODEV_FF_IN_PLACE_SGL |
				RTE_CRYPTODEV_FF_OOP_SGL_IN_LB_OUT |
				RTE_CRYPTODEV_FF_OOP_SGL_IN_SGL_OUT;
		break;
	default:
		/* Feature not supported. Abort */
		CPT_LOG_ERR("VF type not supported by %s", dev_name);
		ret = -EIO;
		goto deinit_dev;
	}

	/* Start off timer for mailbox interrupts */
	otx_cpt_periodic_alarm_start(cptvf);

	c_dev->dev_ops = &cptvf_ops;

	if (c_dev->feature_flags & RTE_CRYPTODEV_FF_SYMMETRIC_CRYPTO) {
		c_dev->enqueue_burst = otx_cpt_enqueue_sym;
		c_dev->dequeue_burst = otx_cpt_dequeue_sym;
	} else {
		c_dev->enqueue_burst = otx_cpt_enqueue_asym;
		c_dev->dequeue_burst = otx_cpt_dequeue_asym;
	}

	/* Save dev private data */
	c_dev->data->dev_private = cptvf;

	return 0;

deinit_dev:
	otx_cpt_deinit_device(cptvf);

fail:
	if (cptvf) {
		/* Free private data allocated */
		rte_free(cptvf);
	}

	return ret;
}
