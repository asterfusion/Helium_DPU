/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2025 Marvell.
 */
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <bus_pci_driver.h>
#include <roc_api.h>
#include <rte_common.h>
#include <rte_eal.h>
#include <rte_lcore.h>
#include <rte_log.h>
#include <rte_mbuf.h>
#include <rte_memcpy.h>
#include <rte_memzone.h>
#include <rte_pci.h>
#include <rte_rawdev.h>
#include <rte_rawdev_pmd.h>

#include "cnxk_emdev.h"
#include "cnxk_emdev_vnet.h"
#include "rte_pmd_cnxk_emdev.h"

#define NB_DESC_MAX 4096

static void
cnxk_emdev_get_name(char *name, struct rte_pci_device *pci_dev)
{
	snprintf(name, RTE_RAWDEV_NAME_MAX_LEN, "EMDEV:%02x:%02x.%x", pci_dev->addr.bus,
		 pci_dev->addr.devid, pci_dev->addr.function);
}

uint16_t
cnxk_emdev_queue_count(struct rte_rawdev *rawdev)
{
	struct cnxk_emdev *dev = cnxk_rawdev_priv(rawdev);

	return dev->roc_emdev.nb_notify_qs;
}

int
cnxk_emdev_queue_setup(struct rte_rawdev *rawdev, uint16_t queue_id, rte_rawdev_obj_t queue_conf,
		       size_t conf_size)
{
	struct cnxk_emdev *dev = cnxk_rawdev_priv(rawdev);
	struct rte_pmd_cnxk_emdev_q_conf *conf = queue_conf;
	struct roc_emdev_psw_nq_qp *roc_nq_qp;
	struct cnxk_emdev_queue *emdev_q;
	struct roc_dpi_lf_que *roc_dpi_q;
	struct cnxk_emdev_dpi_q *dpi_q;
	struct roc_dpi_lf *dpi_lf;
	uintptr_t rbase;
	int rc;

	if (conf_size != sizeof(*conf))
		return -EINVAL;
	if (queue_id >= dev->roc_emdev.nb_notify_qs)
		return -EINVAL;
	if (conf->nb_desc > NB_DESC_MAX)
		return -EINVAL;

	roc_nq_qp = &dev->notify_qs[queue_id];
	roc_nq_qp->nb_desc = conf->nb_desc;
	roc_nq_qp->qid = queue_id;

	/* Setup PSW Notify Queue, Ack Queue */
	rc = roc_emdev_psw_nq_qp_init(&dev->roc_emdev, roc_nq_qp);
	if (rc) {
		plt_err("Failed to init notify queue pair %u, rc=%d", queue_id, rc);
		return rc;
	}

	/* Setup EMDEV Queue object */
	emdev_q = &dev->emdev_qs[queue_id];
	emdev_q->nq.q_base = roc_nq_qp->notify_q_base;
	emdev_q->nq.q_sz = roc_nq_qp->q_sz;
	emdev_q->nq.pi_dbl = roc_nq_qp->notify_q_pi_dbell;
	emdev_q->nq.ci_dbl = roc_nq_qp->notify_q_ci_dbell;
	emdev_q->nq.ci = 0;
	emdev_q->aq.q_base = roc_nq_qp->ack_q_base;
	emdev_q->aq.q_sz = roc_nq_qp->q_sz;
	emdev_q->aq.pi_dbl = roc_nq_qp->ack_q_pi_dbell;
	emdev_q->aq.ci_dbl = roc_nq_qp->ack_q_ci_dbell;
	emdev_q->roc_nq_qp = roc_nq_qp;
	emdev_q->dev = dev;
	emdev_q->mbuf_pi = 0;
	emdev_q->mbuf_ci = 0;

	/* Associate with DPI inbound and outbound queues */
	dpi_lf = &dev->dpi_lfs[queue_id];
	rbase = (uintptr_t)dpi_lf->rbase;

	/* DPI inbound/DEV_TO_MEM queue */
	roc_dpi_q = &dpi_lf->queue[ROC_EMDEV_DPI_LF_RING_INB];
	dpi_q = &emdev_q->dpi_q_inb;
	dpi_q->inst_base = (uint64_t *)roc_dpi_q->cmd_base;
	dpi_q->qid = ROC_EMDEV_DPI_LF_RING_INB;
	dpi_q->ridx_r = (uint64_t *)(rbase + DPI_LF_RINGX_RIDX(ROC_EMDEV_DPI_LF_RING_INB));
	dpi_q->widx_r = (uint64_t *)(rbase + DPI_LF_RINGX_WIDX(ROC_EMDEV_DPI_LF_RING_INB));

	rc = -ENOMEM;
	dpi_q->compl_base =
		rte_zmalloc("cnxk_emdev_inb_compl_base", ROC_ALIGN * roc_dpi_q->qsize, 0);
	if (!dpi_q->compl_base)
		goto psw_nq_qp_fini;

	/* DPI outbound/MEM_TO_DEV queue */
	roc_dpi_q = &dpi_lf->queue[ROC_EMDEV_DPI_LF_RING_OUTB];
	dpi_q = &emdev_q->dpi_q_outb;
	dpi_q->inst_base = (uint64_t *)roc_dpi_q->cmd_base;
	dpi_q->qid = ROC_EMDEV_DPI_LF_RING_OUTB;
	dpi_q->ridx_r = (uint64_t *)(rbase + DPI_LF_RINGX_RIDX(ROC_EMDEV_DPI_LF_RING_OUTB));
	dpi_q->widx_r = (uint64_t *)(rbase + DPI_LF_RINGX_WIDX(ROC_EMDEV_DPI_LF_RING_OUTB));

	rc = -ENOMEM;
	dpi_q->compl_base =
		rte_zmalloc("cnxk_emdev_outb_compl_base", ROC_ALIGN * roc_dpi_q->qsize, 0);
	if (!dpi_q->compl_base)
		goto psw_nq_qp_fini;

	if (dev->cls_ops && dev->cls_ops->cls_queue_setup)
		dev->cls_ops->cls_queue_setup(dev, queue_id);

	return 0;
psw_nq_qp_fini:
	rte_free(emdev_q->dpi_q_inb.compl_base);
	rte_free(emdev_q->dpi_q_outb.compl_base);
	rc |= roc_emdev_psw_nq_qp_fini(roc_nq_qp);
	emdev_q->roc_nq_qp = NULL;
	return rc;
}

int
cnxk_emdev_queue_release(struct rte_rawdev *rawdev, uint16_t queue_id)
{
	struct cnxk_emdev *dev = cnxk_rawdev_priv(rawdev);
	struct roc_emdev_psw_nq_qp *roc_nq_qp;
	struct cnxk_emdev_queue *emdev_q;
	int rc;

	emdev_q = &dev->emdev_qs[queue_id];
	if (queue_id >= dev->roc_emdev.nb_notify_qs || emdev_q->roc_nq_qp == NULL)
		return -EINVAL;

	roc_nq_qp = &dev->notify_qs[queue_id];

	rc = roc_emdev_psw_nq_qp_fini(roc_nq_qp);
	if (rc) {
		plt_err("Failed to cleanup notify queue pair %u, rc=%d", queue_id, rc);
		return rc;
	}
	rte_free(emdev_q->dpi_q_inb.compl_base);
	rte_free(emdev_q->dpi_q_outb.compl_base);
	emdev_q->roc_nq_qp = NULL;

	return 0;
}

int
cnxk_emdev_info_get(struct rte_rawdev *rawdev, rte_rawdev_obj_t dev_info, size_t dev_info_size)
{
	RTE_SET_USED(rawdev);
	RTE_SET_USED(dev_info);
	RTE_SET_USED(dev_info_size);

	return 0;
}

static inline int
cnxk_emdev_class_init(const struct rte_rawdev *rawdev, struct rte_pmd_cnxk_emdev_conf *conf)
{
	struct cnxk_emdev *dev = cnxk_rawdev_priv(rawdev);
	int rc = 0;

	switch (dev->emdev_type) {
	case EMDEV_TYPE_VIRTIO_NET:
		rc = cnxk_emdev_virtio_setup(dev, conf);
		break;
	default:
		rc = -ENOTSUP;
		break;
	}
	return rc;
}

static inline int
cnxk_emdev_class_fini(struct cnxk_emdev *dev)
{
	switch (dev->emdev_type) {
	case EMDEV_TYPE_VIRTIO_NET:
		cnxk_emdev_virtio_close(dev);
		break;
	default:
		break;
	}

	return 0;
}

int
cnxk_emdev_configure(const struct rte_rawdev *rawdev, rte_rawdev_obj_t config, size_t config_size)
{
	struct cnxk_emdev *dev = cnxk_rawdev_priv(rawdev);
	struct rte_pmd_cnxk_emdev_conf *conf = config;
	struct roc_emdev *roc_emdev = &dev->roc_emdev;
	uint16_t nb_emdev_qs, first_skip;
	int rc, i, j;

	if (conf == NULL || config_size != sizeof(*conf) || conf->default_mp == NULL)
		return -EINVAL;

	if (conf->num_emdev_queues > ROC_PSW_NOTIF_QUEUES_MAX)
		return -EINVAL;

	if (conf->max_outb_queues > ROC_PSW_OUTB_QUEUES_MAX)
		return -EINVAL;

	dev->dev_id = rawdev->dev_id;
	nb_emdev_qs = conf->num_emdev_queues;
	roc_emdev->nb_notify_qs = nb_emdev_qs;
	roc_emdev->nb_outb_qs = conf->max_outb_queues;
	roc_emdev->nb_inb_qs = conf->max_outb_queues;
	roc_emdev->nb_epfvfs = conf->num_funcs;
	roc_emdev->nb_dpi_lfs = nb_emdev_qs;
	switch (conf->emdev_type) {
	case EMDEV_TYPE_VIRTIO_NET:
		roc_emdev->emul_type = ROC_EMDEV_TYPE_VIRTIO;
		break;
	default:
		plt_err("Unsupported emdev type : %d", conf->emdev_type);
		return -ENOTSUP;
	}

	dev->emdev_type = conf->emdev_type;
	dev->default_mp = conf->default_mp;
	/* For now, number of notify queues and DPI LFs are same */
	dev->nb_emdev_qs = nb_emdev_qs;
	dev->nb_notify_qs = nb_emdev_qs;
	dev->nb_dpi_lfs = nb_emdev_qs;
	dev->nb_epfvfs = roc_emdev->nb_epfvfs;

	/* Default all the queue notifications to 1 */
	for (i = 0; i < dev->nb_epfvfs; i++)
		for (j = 0; j < conf->max_outb_queues; j++)
			dev->func_q_map[i][j] = CNXK_EMDEV_DFLT_QID;

	first_skip = sizeof(struct rte_mbuf);
	first_skip += RTE_PKTMBUF_HEADROOM;
	first_skip += rte_pktmbuf_priv_size(conf->default_mp);
	first_skip /= 8;
	roc_emdev->first_skip = first_skip;
	roc_emdev->later_skip = first_skip;

	rc = -ENOMEM;
	dev->notify_qs = rte_zmalloc("cnxk_emdev_notify_queues",
				     sizeof(struct roc_emdev_psw_nq_qp) * dev->nb_notify_qs, 0);
	if (!dev->notify_qs)
		goto exit;

	/* Allocate memory for fast path queue objects */
	dev->emdev_qs = rte_zmalloc("cnxk_emdev_queue",
				    sizeof(struct cnxk_emdev_queue) * dev->nb_emdev_qs, 0);
	if (!dev->emdev_qs)
		goto exit;

	/* Setup ROC EMDEV */
	rc = roc_emdev_setup(roc_emdev);
	if (rc) {
		plt_err("Failed to setup roc_emdev, rc=%d", rc);
		return rc;
	}

	/* Register interrupts */
	rc = roc_emdev_irqs_register(roc_emdev);
	if (rc) {
		plt_err("roc_emdev_irqs_register failed");
		goto emdev_release;
	}

	/* Setup EMDEV class */
	rc = cnxk_emdev_class_init(rawdev, conf);
	if (rc) {
		plt_err("Failed to setup emdev class, rc=%d", rc);
		goto irq_unregister;
	}

	/* Get DPI LF base */
	dev->dpi_lfs = roc_emdev_dpi_lf_base_get(roc_emdev);
	if (!dev->dpi_lfs) {
		plt_err("Failed to get DPI LF base");
		rc = -ENODEV;
		goto class_fini;
	}

	plt_emdev_dbg("Configured emdev with emdev_qs: %u max_outb_queues: %d",
		      conf->num_emdev_queues, conf->max_outb_queues);

	return 0;
class_fini:
	rc |= cnxk_emdev_class_fini(dev);
irq_unregister:
	roc_emdev_irqs_unregister(roc_emdev);
emdev_release:
	rc |= roc_emdev_release(roc_emdev);
exit:
	rte_free(dev->notify_qs);
	rte_free(dev->emdev_qs);
	return rc;
}

int
cnxk_emdev_attr_get(struct rte_rawdev *rawdev, const char *attr_name, uint64_t *attr_value)
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
		if (q_map->func_id >= dev->nb_epfvfs) {
			plt_err("Invalid func_id:%u for func_q_map", q_map->func_id);
			return -EINVAL;
		}
		q_map->qid = dev->func_q_map[q_map->func_id][q_map->outb_qid];
		return 0;
	}
	return -EINVAL;
}

int
cnxk_emdev_attr_set(struct rte_rawdev *rawdev, const char *attr_name, uint64_t attr_value)
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
		if (q_map->func_id >= dev->nb_epfvfs) {
			plt_err("Invalid func_id:%u for func_q_map", q_map->func_id);
			return -EINVAL;
		}

		if (q_map->qid >= dev->nb_emdev_qs) {
			plt_err("Invalid qid:%u for func_q_map", q_map->qid);
			return -EINVAL;
		}
		dev->func_q_map[q_map->func_id][q_map->outb_qid] = q_map->qid;

		return 0;
	}
	return -EINVAL;
}

int
cnxk_emdev_close(struct rte_rawdev *rawdev)
{
	struct cnxk_emdev *dev = cnxk_rawdev_priv(rawdev);
	int i, rc;

	for (i = 0; i < dev->roc_emdev.nb_notify_qs; i++)
		cnxk_emdev_queue_release(rawdev, i);

	rc = cnxk_emdev_class_fini(dev);
	roc_emdev_irqs_unregister(&dev->roc_emdev);
	rc |= roc_emdev_release(&dev->roc_emdev);
	rte_free(dev->notify_qs);
	rte_free(dev->emdev_qs);

	return rc;
}

int
cnxk_emdev_start(struct rte_rawdev *rawdev)
{
	struct cnxk_emdev *dev = cnxk_rawdev_priv(rawdev);
	struct roc_emdev *roc_emdev = &dev->roc_emdev;
	uint16_t notify_qoff;
	int i, rc;

	for (i = 0; i < dev->nb_epfvfs; i++) {
		notify_qoff = dev->func_q_map[i][0];
		rc = roc_emdev_psw_epfvf_config(roc_emdev, i, notify_qoff, true);
		if (rc) {
			plt_err("roc_emdev_psw_epfvf_config failed");
			goto exit;
		}
	}

	rawdev->started = 1;
	return 0;

exit:
	i--;
	for (; i >= 0; i--) {
		notify_qoff = dev->func_q_map[i][0];
		roc_emdev_psw_epfvf_config(roc_emdev, i, notify_qoff, false);
	}
	return rc;
}

void
cnxk_emdev_stop(struct rte_rawdev *rawdev)
{
	struct cnxk_emdev *dev = cnxk_rawdev_priv(rawdev);
	struct roc_emdev *roc_emdev = &dev->roc_emdev;
	uint16_t notify_qoff;
	int i, rc = 0;

	for (i = 0; i < dev->nb_epfvfs; i++) {
		notify_qoff = dev->func_q_map[i][0];
		rc = roc_emdev_psw_epfvf_config(roc_emdev, i, notify_qoff, false);
		if (rc)
			plt_err("roc_emdev_psw_epfvf_config failed for func : %d", i);
	}
	rawdev->started = 0;
}

int
cnxk_emdev_dump(struct rte_rawdev *rawdev, FILE *file)
{
	struct cnxk_emdev *dev = cnxk_rawdev_priv(rawdev);
	struct cnxk_emdev_queue *emdev_q;
	struct roc_dpi_lf *dpi_lf;
	int i;

	/* Dump all the notify/ack queues a.k.a emdev queues and associated DPI LFs */
	for (i = 0; i < dev->nb_emdev_qs; i++) {

		emdev_q = &dev->emdev_qs[i];
		/* Skip dumping queue if not enabled */
		if (!emdev_q->roc_nq_qp)
			continue;

		plt_info("Dumping emdev queue %d", i);
		roc_emdev_psw_nq_qp_dump(emdev_q->roc_nq_qp, file);

		dpi_lf = &dev->dpi_lfs[i];
		roc_dpi_lf_dump(dpi_lf, file);
	}
	if (dev->cls_ops && dev->cls_ops->cls_dump)
		dev->cls_ops->cls_dump(dev, file);

	return 0;
}

static const struct rte_rawdev_ops cnxk_emdev_ops = {
	.dev_info_get = cnxk_emdev_info_get,
	.dev_configure = cnxk_emdev_configure,
	.dev_close = cnxk_emdev_close,
	.dev_start = cnxk_emdev_start,
	.dev_stop = cnxk_emdev_stop,

	.queue_count = cnxk_emdev_queue_count,
	.queue_setup = cnxk_emdev_queue_setup,
	.queue_release = cnxk_emdev_queue_release,

	.attr_set = cnxk_emdev_attr_set,
	.attr_get = cnxk_emdev_attr_get,

	.dump = cnxk_emdev_dump,
};

static int
cnxk_emdev_probe(struct rte_pci_driver *pci_drv, struct rte_pci_device *pci_dev)
{
	char name[RTE_RAWDEV_NAME_MAX_LEN];
	struct cnxk_emdev *dev = NULL;
	struct rte_rawdev *rawdev;
	int rc;

	RTE_SET_USED(pci_drv);

	if (rte_eal_process_type() != RTE_PROC_PRIMARY)
		return 0;

	if (!pci_dev->mem_resource[2].addr) {
		plt_err("BARs have invalid values: BAR2 %p", pci_dev->mem_resource[2].addr);
		return -ENODEV;
	}

	rc = roc_plt_init();
	if (rc)
		return rc;

	cnxk_emdev_get_name(name, pci_dev);
	rawdev = rte_rawdev_pmd_allocate(name, sizeof(*dev), rte_socket_id());
	if (rawdev == NULL) {
		plt_err("Failed to allocate rawdev");
		return -ENOMEM;
	}

	rawdev->dev_ops = &cnxk_emdev_ops;
	rawdev->device = &pci_dev->device;
	rawdev->driver_name = pci_dev->driver->driver.name;

	dev = cnxk_rawdev_priv(rawdev);
	dev->roc_emdev.pci_dev = pci_dev;
	dev->rawdev = rawdev;

	return roc_emdev_init(&dev->roc_emdev);
}

static int
cnxk_emdev_remove(struct rte_pci_device *pci_dev)
{
	struct cnxk_emdev *dev;
	struct rte_rawdev *rawdev;
	int rc;

	if (rte_eal_process_type() != RTE_PROC_PRIMARY)
		return 0;

	if (pci_dev == NULL) {
		plt_err("invalid pci_dev");
		return -EINVAL;
	}

	rawdev = rte_rawdev_pmd_get_named_dev(pci_dev->driver->driver.name);
	if (rawdev == NULL)
		return -EINVAL;

	dev = cnxk_rawdev_priv(rawdev);
	rc = roc_emdev_fini(&dev->roc_emdev);
	if (rc)
		plt_warn("Failure from roc_emdev_fini");

	return rte_rawdev_pmd_release(rawdev);
}

static const struct rte_pci_id pci_emdev_map[] = {
	{RTE_PCI_DEVICE(PCI_VENDOR_ID_CAVIUM, PCI_DEVID_CNXK_RVU_PSW_PF)},
	{
		.vendor_id = 0,
	},
};

static struct rte_pci_driver cnxk_emdev_raw_pmd = {
	.id_table = pci_emdev_map,
	.drv_flags = RTE_PCI_DRV_NEED_MAPPING | RTE_PCI_DRV_NEED_IOVA_AS_VA,
	.probe = cnxk_emdev_probe,
	.remove = cnxk_emdev_remove,
};

RTE_PMD_REGISTER_PCI(raw_cnxk_emdev, cnxk_emdev_raw_pmd);
RTE_PMD_REGISTER_PCI_TABLE(raw_cnxk_emdev, pci_emdev_map);
RTE_PMD_REGISTER_KMOD_DEP(raw_cnxk_emdev, "vfio-pci");
