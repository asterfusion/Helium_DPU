/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2025 Marvell.
 */
#include <bus_pci_driver.h>
#include <dev_driver.h>
#include <rte_common.h>
#include <rte_eal.h>
#include <rte_lcore.h>
#include <rte_pci.h>
#include <rte_rawdev.h>
#include <rte_rawdev_pmd.h>

#include <roc_api.h>

#include "cnxk_emdev_vnet.h"

extern const struct rte_rawdev_ops cnxk_emdev_vnet_ops;

static uint16_t
vnet_cq_id_get(struct cnxk_emdev_virtio_pfvf *pfvf, uint64_t feature_bits)
{
	RTE_SET_USED(pfvf);

	if (feature_bits & (1ULL << VIRTIO_NET_F_MQ))
		return pfvf->max_queues - 1;
	else
		return 2;
}

static int
vnet_link_sts_update(struct cnxk_emdev_virtio_pfvf *pfvf,
		     struct rte_pmd_cnxk_vnet_link_info *link_info)
{
	struct virtio_net_config *dev_cfg = &pfvf->net_conf.dev_cfg;

	dev_cfg->status = link_info->status;
	dev_cfg->duplex = link_info->duplex;
	dev_cfg->speed = link_info->speed;

	roc_emdev_psw_mbox_int_trigger(&pfvf->dev->roc_emdev, pfvf->vf_id);

	return 0;
}

static int
vnet_devcfg_read(struct cnxk_emdev_virtio_pfvf *pfvf, uint32_t offset, void *data, uint8_t len)
{
	struct virtio_net_config *dev_cfg = &pfvf->net_conf.dev_cfg;
	uint32_t cfg_offset;

	cfg_offset = offset - ROC_EMDEV_VIRTIO_PCI_COMMON_CFG_LEN;
	if (cfg_offset >= 64)
		return -EINVAL;

	memcpy(data, (uint8_t *)dev_cfg + cfg_offset, len);

	return 0;
}

static void
vnet_dump(struct cnxk_emdev *dev, FILE *file)
{
	struct cnxk_emdev_virtio_pfvf *pfvf = dev->pfvf;
	struct cnxk_emdev_virtio_queue_conf *conf;
	uint16_t qid;
	int i;

	/* Dump all the inbound/outbound queues for all VF's */
	for (i = 0; i < dev->nb_epfvfs; i++) {
		plt_info("Dumping inb/outb queues for epf_func 0x%x", pfvf[i].epf_func);

		for (qid = 0; qid < pfvf[i].max_queues; qid++) {
			conf = &pfvf[i].queue_conf[qid];
			/* Skip dumping queue if not enabled */

			if (!conf->queue_enable)
				continue;
			roc_emdev_psw_inb_q_dump(&conf->inbq, file);
			roc_emdev_psw_outb_q_dump(&conf->outbq, file);
		}
	}
}

static void
vnet_queue_setup(struct cnxk_emdev *dev, uint16_t queue_id)
{
	struct cnxk_emdev_virtio_pfvf *pfvfs = dev->pfvf;
	int i;

	/* Take references of vnet queues */
	for (i = 0; i < dev->nb_epfvfs; i++) {
		plt_emdev_dbg("VNET queue setup for PFVF %d %p ", i, pfvfs[i].vnet_qs);
		dev->emdev_qs[queue_id].vnet_q_base[i] = pfvfs[i].vnet_qs;
	}
}

static const struct cnxk_emdev_cls_ops vnet_ops = {
	.cls_queue_setup = vnet_queue_setup,
	.cls_dump = vnet_dump,
};

int
cnxk_emdev_vnet_init(struct cnxk_emdev_virtio_pfvf *pfvf, struct rte_pmd_cnxk_vnet_conf *conf)
{
	struct virtio_net_config *dev_cfg = &pfvf->net_conf.dev_cfg;
	uint64_t feature_bits = 0x0ULL;

	feature_bits |= RTE_BIT64(VIRTIO_NET_F_CTRL_VQ) | RTE_BIT64(VIRTIO_NET_F_MQ) |
			RTE_BIT64(VIRTIO_NET_F_CTRL_RX) | RTE_BIT64(VIRTIO_NET_F_STATUS) |
			RTE_BIT64(VIRTIO_NET_F_MAC) | RTE_BIT64(VIRTIO_NET_F_MRG_RXBUF) |
			RTE_BIT64(VIRTIO_NET_F_SPEED_DUPLEX);

	if (conf->reta_size)
		feature_bits |= RTE_BIT64(VIRTIO_NET_F_RSS);

	if (conf->mtu) {
		feature_bits |= RTE_BIT64(VIRTIO_NET_F_MTU);
		dev_cfg->mtu = conf->mtu;
	}

	/* Populate default netdev config */
	dev_cfg->status = conf->link_info.status;
	dev_cfg->duplex = conf->link_info.duplex;
	dev_cfg->speed = conf->link_info.speed;
	memcpy(dev_cfg->mac, conf->mac, sizeof(dev_cfg->mac));
	dev_cfg->max_virtqueue_pairs = pfvf->max_queues / 2;
	dev_cfg->rss_max_key_size = conf->hash_key_size;
	dev_cfg->rss_max_indirection_table_length = conf->reta_size;
	dev_cfg->supported_hash_types = VIRTIO_NET_HASH_TYPE_MASK;

	/* One time setup */
	emdev_virtio_cbs[EMDEV_TYPE_VIRTIO_NET].cq_id_get = vnet_cq_id_get;
	emdev_virtio_cbs[EMDEV_TYPE_VIRTIO_NET].dev_cfg_read = vnet_devcfg_read;

	pfvf->dev_feature_bits |= feature_bits;

	/* Update devops to point to vnet_ops */
	pfvf->dev->rawdev->dev_ops = &cnxk_emdev_vnet_ops;
	pfvf->dev->cls_ops = &vnet_ops;

	/* Updates null function pointers */
	cnxk_emdev_vnet_update_fn_ptrs();

	return 0;
}

static int
cnxk_emdev_vnet_attr_set(struct rte_rawdev *rawdev, const char *attr_name, uint64_t attr_value)
{
	struct cnxk_emdev *dev = cnxk_rawdev_priv(rawdev);

	if (attr_name == NULL)
		return -EINVAL;

	if (!strncmp(attr_name, CNXK_EMDEV_ATTR_FUNC_Q_MAP, CNXK_EMDEV_ATTR_NAME_LEN)) {
		struct rte_pmd_cnxk_func_q_map_attr *q_map =
			(struct rte_pmd_cnxk_func_q_map_attr *)attr_value;

		if (q_map == NULL) {
			plt_err("Invalid func_q_map attribute value");
			return -EINVAL;
		}
		if (q_map->func_id >= dev->roc_emdev.nb_epfvfs) {
			plt_err("Invalid func_id:%u for func_q_map", q_map->func_id);
			return -EINVAL;
		}
		dev->func_q_map[q_map->func_id][q_map->outb_qid] = q_map->qid;
		/* Reinitialize the queues since notification queue to be mapped might be
		 * different
		 */
		cnxk_emdev_virtio_queue_fini(dev, q_map->func_id, q_map->outb_qid);
		return cnxk_emdev_virtio_queue_init(dev, q_map->func_id, q_map->outb_qid);

	} else if (!strncmp(attr_name, CNXK_EMDEV_ATTR_LINK_STATUS, CNXK_EMDEV_ATTR_NAME_LEN)) {
		struct rte_pmd_cnxk_vnet_link_info *link =
			(struct rte_pmd_cnxk_vnet_link_info *)attr_value;
		struct cnxk_emdev_virtio_pfvf *pfvfs = dev->pfvf;
		struct cnxk_emdev_virtio_pfvf *pfvf;

		if (link == NULL) {
			plt_err("Invalid vnet link attribute value");
			return -EINVAL;
		}
		if (link->func_id >= dev->roc_emdev.nb_epfvfs) {
			plt_err("Invalid func_id:%u for link status update", link->func_id);
			return -EINVAL;
		}
		pfvf = &pfvfs[link->func_id];

		return vnet_link_sts_update(pfvf, link);
	}
	return -EINVAL;
}

const struct rte_rawdev_ops cnxk_emdev_vnet_ops = {
	.dev_info_get = cnxk_emdev_info_get,
	.dev_configure = cnxk_emdev_configure,
	.dev_close = cnxk_emdev_close,
	.dev_start = cnxk_emdev_start,
	.dev_stop = cnxk_emdev_stop,

	.queue_count = cnxk_emdev_queue_count,
	.queue_setup = cnxk_emdev_queue_setup,
	.queue_release = cnxk_emdev_queue_release,
	.enqueue_bufs = cnxk_emdev_vnet_enqueue,
	.dequeue_bufs = cnxk_emdev_vnet_dequeue,

	.attr_set = cnxk_emdev_vnet_attr_set,

	.dump = cnxk_emdev_dump,
};

cnxk_emdev_vnet_psw_dbl_fn_t cnxk_emdev_vnet_psw_dbl_fn[EMDEV_VNET_PSW_DBL_OFFLOAD_LAST << 1] = {
#define D(name, flags) [flags] = cnxk_emdev_vnet_psw_dbl_##name,
	EMDEV_VNET_PSW_DBL_FASTPATH_MODES
#undef D
};

cnxk_emdev_vnet_dpi_compl_fn_t
	cnxk_emdev_vnet_dpi_compl_fn[EMDEV_VNET_DPI_COMPL_OFFLOAD_LAST << 1] = {
#define C(name, flags) [flags] = cnxk_emdev_vnet_dpi_compl_##name,
		EMDEV_VNET_DPI_COMPL_FASTPATH_MODES
#undef C
};

static __rte_always_inline int
emdev_vnet_dpi_compl(struct cnxk_emdev_queue *queue, struct cnxk_emdev_vnet_queue *vnet_q,
		     uint16_t index, const uint16_t flags)
{
	if (flags & DPI_ENQ_F)
		return cnxk_emdev_vnet_enq_dpi_compl(queue, vnet_q, index, flags);

	if (flags & DPI_DEQ_F)
		return cnxk_emdev_vnet_deq_dpi_compl(queue, vnet_q, index, flags);

	return 0;
}

static __rte_always_inline int
emdev_vnet_psw_dbl(struct cnxk_emdev_queue *queue, struct cnxk_emdev_vnet_queue *vnet_q,
		   uint16_t index, const uint16_t flags)
{
	if (flags & DBL_ENQ_F)
		return cnxk_emdev_vnet_enq_psw_dbl(queue, vnet_q, index, flags);

	if (flags & DBL_CTRL_F)
		return cnxk_emdev_vnet_ctrl_deq_psw_dbl(queue, vnet_q, index, flags);

	if (flags & DBL_DEQ_F)
		return cnxk_emdev_vnet_deq_psw_dbl(queue, vnet_q, index, flags);

	return 0;
}

#define C(name, flags)                                                                             \
	int cnxk_emdev_vnet_dpi_compl_##name(void *q, void *vnet_q, uint16_t idx)                  \
	{                                                                                          \
		return emdev_vnet_dpi_compl(q, vnet_q, idx, flags);                                \
	}

EMDEV_VNET_DPI_COMPL_FASTPATH_MODES
#undef C

#define D(name, flags)                                                                             \
	int cnxk_emdev_vnet_psw_dbl_##name(void *q, void *vnet_q, uint16_t idx)                    \
	{                                                                                          \
		return emdev_vnet_psw_dbl(q, vnet_q, idx, flags);                                  \
	}

EMDEV_VNET_PSW_DBL_FASTPATH_MODES
#undef D
