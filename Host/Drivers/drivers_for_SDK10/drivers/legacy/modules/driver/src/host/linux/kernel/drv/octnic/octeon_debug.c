#include "cavium_sysdep.h"
#include "cavium_defs.h"
#include "octeon_network.h"
//#include "octeon_device.h"
#include "octeon_macros.h"
#include "octeon_nic.h"

MODULE_AUTHOR("Marvell Semiconductors Inc");
MODULE_DESCRIPTION("Octeon Host PCI NIC Debug Driver");
MODULE_LICENSE("Marvell Semiconductors");

static char *dif = "oct0";
module_param(dif, charp, S_IRUGO);
MODULE_PARM_DESC(dif, "Debug Interface Name");

static void octeon_debug_dump(struct net_device *dev)
{
	octnet_priv_t *priv;
	octeon_device_t *oct;
	octeon_instr_queue_t *iq;
	octeon_droq_t *oq;
	int q;
	uint64_t total_rx;

	priv = GET_NETDEV_PRIV(dev);
	oct = (octeon_device_t *)priv->oct_dev;

	netdev_info(dev, "#######  Instruction Queue Info #######");
	for (q = 0; q < oct->num_iqs; q++) {
		netdev_info(dev, "======== IQ %d ========\n", q);
		iq = oct->instr_queue[q];
		if (iq == NULL) {
			netdev_info(dev, "Queue not used\n");
			continue;
		}
		netdev_info(dev, "fill_cnt          = %u\n", iq->fill_cnt);
		netdev_info(dev, "instr_pending     = %u\n", (u32)cavium_atomic_read(&iq->instr_pending));
		netdev_info(dev, "flush_index       = %u\n", iq->flush_index);
		netdev_info(dev, "host_write_index  = %u\n", iq->host_write_index);
		netdev_info(dev, "octeon_read_index = %u\n", iq->octeon_read_index);
		netdev_info(dev, "stat.instr_posted = %llu\n", iq->stats.instr_posted);
		netdev_info(dev, "stat.instr_processed = %llu\n", iq->stats.instr_processed);
		netdev_info(dev, "stat.instr_dropped = %llu\n", iq->stats.instr_dropped);
		netdev_info(dev, "status = %u\n", iq->status);
	}

	netdev_info(dev, "#######  Output Queue Info #######");
	netdev_info(dev, "Buffer size = %u\n", oct->droq[0]->buffer_size);
	total_rx = 0;
	for (q = 0; q < oct->num_oqs; q++) {
		netdev_info(dev, "======== OQ %d ========\n", q);
		oq = oct->droq[q];
		if (oq == NULL) {
			netdev_info(dev, "Queue not used\n");
			continue;
		}
		total_rx += oq->stats.pkts_received;

		netdev_info(dev, "host_read_index    = %u\n", oq->host_read_index);
		netdev_info(dev, "octeon_write_index = %u\n", oq->octeon_write_index);
		netdev_info(dev, "host_refill_index  = %u\n", oq->host_refill_index);
		netdev_info(dev, "pkts_pending       = %u\n", cavium_atomic_read(&oq->pkts_pending));
		netdev_info(dev, "refill_count       = %u\n", oq->refill_count);
		netdev_info(dev, "max_count          = %u\n", oq->max_count);
		netdev_info(dev, "pkts_received      = %llu\n", oq->stats.pkts_received);
		netdev_info(dev, "dropped_nodispatch = %llu\n", oq->stats.dropped_nodispatch);
		netdev_info(dev, "dropped_nomem      = %llu\n", oq->stats.dropped_nomem);
		netdev_info(dev, "dropped_toomany    = %llu\n", oq->stats.dropped_toomany);
		netdev_info(dev, "dropped_zlp        = %llu\n", oq->stats.dropped_zlp);
		netdev_info(dev, "pkts_delayed_data  = %llu\n", oq->stats.pkts_delayed_data);
	}
	netdev_info(dev, "Total Rx    = %llu\n", total_rx);
}


static int __init oceton_debug_init(void)
{
	struct net_device *dev;

	dev = dev_get_by_name(&init_net, dif);
	if (dev == NULL) {
		printk(KERN_ERR "Netdev not found for interface %s\n", dif);
		return -EINVAL;
	}
	octeon_debug_dump(dev);
	dev_put(dev);

	return 0;
}

static void __exit octeon_debug_exit(void)
{
	printk("Octeon debug module unloaded\n");
}

module_init(oceton_debug_init);
module_exit(octeon_debug_exit);
