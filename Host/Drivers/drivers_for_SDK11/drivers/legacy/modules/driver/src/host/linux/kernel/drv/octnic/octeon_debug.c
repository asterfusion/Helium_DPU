/* Copyright (c) 2020 Marvell.
 * SPDX-License-Identifier: GPL-2.0
 */

#include "cavium_sysdep.h"
#include "cavium_defs.h"
#include "octeon_network.h"
//#include "octeon_device.h"
#include "octeon_macros.h"
#include "octeon_nic.h"

MODULE_AUTHOR("Marvell Semiconductors Inc");
MODULE_DESCRIPTION("Octeon Host PCI NIC Debug Driver");
MODULE_LICENSE("GPL");

static char *dif = "oct0";
module_param(dif, charp, S_IRUGO);
MODULE_PARM_DESC(dif, "Debug Interface Name");

#if !defined(HAS_SKB_FRAG_OFF) && LINUX_VERSION_CODE < KERNEL_VERSION(5,4,0)
static inline unsigned int skb_frag_off_local(const skb_frag_t *frag)
{
	return frag->page_offset;
}
#else
#define skb_frag_off_local	skb_frag_off
#endif

static void oct_skb_dump(const char *level, const struct sk_buff *skb,
			 bool full_pkt)
{
	struct skb_shared_info *sh = skb_shinfo(skb);
	struct net_device *dev = skb->dev;
	struct sock *sk = skb->sk;
	struct sk_buff *list_skb;
	bool has_mac, has_trans;
	int headroom, tailroom;
	int i, len, seg_len;

	if (full_pkt)
		len = skb->len;
	else
		len = min_t(int, skb->len, MAX_HEADER + 128);

	headroom = skb_headroom(skb);
	tailroom = skb_tailroom(skb);

	has_mac = skb_mac_header_was_set(skb);
	has_trans = skb_transport_header_was_set(skb);

	printk("%sskb len=%u data_len=%u headroom=%u headlen=%u tailroom=%u\n"
	       "mac=(%d,%d) net=(%d,%d) trans=%d\n"
	       "shinfo(txflags=%u nr_frags=%u gso(size=%hu type=%u segs=%hu))\n"
	       "csum(0x%x ip_summed=%u complete_sw=%u valid=%u level=%u)\n"
	       "hash(0x%x sw=%u l4=%u) proto=0x%04x pkttype=%u iif=%d\n",
	       level, skb->len, skb->data_len, headroom, skb_headlen(skb), tailroom,
	       has_mac ? skb->mac_header : -1,
	       has_mac ? skb_mac_header_len(skb) : -1,
	       skb->network_header,
	       has_trans ? skb_network_header_len(skb) : -1,
	       has_trans ? skb->transport_header : -1,
	       sh->tx_flags, sh->nr_frags,
	       sh->gso_size, sh->gso_type, sh->gso_segs,
	       skb->csum, skb->ip_summed, skb->csum_complete_sw,
	       skb->csum_valid, skb->csum_level,
	       skb->hash, skb->sw_hash, skb->l4_hash,
	       ntohs(skb->protocol), skb->pkt_type, skb->skb_iif);

	if (dev)
		printk("%sdev name=%s feat=0x%pNF\n",
		       level, dev->name, &dev->features);
	if (sk)
		printk("%ssk family=%hu type=%u proto=%u\n",
		       level, sk->sk_family, sk->sk_type, sk->sk_protocol);

	if (full_pkt && headroom)
		print_hex_dump(level, "skb headroom: ", DUMP_PREFIX_OFFSET,
			       16, 1, skb->head, headroom, false);

	seg_len = min_t(int, skb_headlen(skb), len);
	if (seg_len)
		print_hex_dump(level, "skb linear:   ", DUMP_PREFIX_OFFSET,
			       16, 1, skb->data, seg_len, false);
	len -= seg_len;

	if (full_pkt && tailroom)
		print_hex_dump(level, "skb tailroom: ", DUMP_PREFIX_OFFSET,
			       16, 1, skb_tail_pointer(skb), tailroom, false);

	printk("skb num_frags %d\n", skb_shinfo(skb)->nr_frags);
	for (i = 0; len && i < skb_shinfo(skb)->nr_frags; i++) {
		skb_frag_t *frag = &skb_shinfo(skb)->frags[i];
		u32 p_off, p_len, copied;
		struct page *p;
		u8 *vaddr;

		skb_frag_foreach_page(frag, skb_frag_off_local(frag),
				      skb_frag_size(frag), p, p_off, p_len,
				      copied) {
			seg_len = min_t(int, p_len, len);
			vaddr = kmap_atomic(p);
			printk("skb frag:%d size %d\n", i, skb_frag_size(frag));
			print_hex_dump(level, "frag data:     ",
				       DUMP_PREFIX_OFFSET,
				       16, 1, vaddr + p_off, seg_len, false);
			kunmap_atomic(vaddr);
			len -= seg_len;
			if (!len)
				break;
		}
	}

	if (full_pkt && skb_has_frag_list(skb)) {
		printk("skb fraglist:\n");
		skb_walk_frags(skb, list_skb)
			oct_skb_dump(level, list_skb, true);
	}
}

static void octeon_debug_dump(struct net_device *dev)
{
	octnet_priv_t *priv;
	octeon_device_t *oct;
	octeon_instr_queue_t *iq;
	octeon_droq_t *oq;
	int q;
	uint64_t total_rx;
	uint64_t *cmd_ptr;
	struct octnet_buf_free_info *finfo;
	int buftype;
	int i, frags;
	struct sk_buff *skb;
	struct octeon_gather *g;

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
		netdev_info(dev, "stat.tx_busy_retransmit = %llu\n", iq->stats.tx_busy_retransmit);
		netdev_info(dev, "status = %u\n", iq->status);
		if ((u32)cavium_atomic_read(&iq->instr_pending) > 0) {
			netdev_info(dev, "iq command at read_idx %u\n", iq->octeon_read_index);
			cmd_ptr = (uint64_t *)(iq->base_addr + (64 * iq->octeon_read_index));
			for ( i = 0; i < 8; i++)
				netdev_info(dev, "dword:%d 0x%016llx\n", i, *(cmd_ptr + i));
			finfo = (struct octnet_buf_free_info *)iq->nrlist[iq->octeon_read_index].buf;
			buftype = iq->nrlist[iq->octeon_read_index].buftype;
			skb = finfo->skb;
			if (buftype == NORESP_BUFTYPE_NET_SG) {
				g = finfo->g;
				netdev_info(dev, "g->sg[0].ptr[0] 0x%016llx size %d\n",
					    g->sg[0].ptr[0],
#if  __CAVIUM_BYTE_ORDER == __CAVIUM_BIG_ENDIAN
					     g->sg[0].u.size[0]);
#else
					     g->sg[0].u.size[3 - 0]);
#endif
				frags = skb_shinfo(skb)->nr_frags;
				i = 1;
				while (frags--) {
					netdev_info(dev,
						    "g->sg[%d].ptr[%d] 0x%016llx size %d\n",
						    i >> 2, i & 3, g->sg[i >> 2].ptr[i & 3],
#if  __CAVIUM_BYTE_ORDER == __CAVIUM_BIG_ENDIAN
						    g->sg[i >> 2].u.size[i & 3]);
#else
						    g->sg[i >> 2].u.size[(3 - i) & 3]);
#endif
					i++;
				}
			}
			oct_skb_dump(KERN_ERR, skb, true);
		}
	}
	netdev_info(dev, "#######  Output Queue Info #######");
	netdev_info(dev, "Buffer size = %u\n", oct->droq[0]->buffer_size);
	total_rx = 0;
	for (q = 0; q < oct->num_oqs; q++) {
		int idx = 0;
		octeon_droq_desc_t *desc_ring;

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
		netdev_info(dev, "pkts_pending       = %u\n", oq->pkts_pending);
		netdev_info(dev, "refill_count       = %u\n", oq->refill_count);
		netdev_info(dev, "max_count          = %u\n", oq->max_count);
		netdev_info(dev, "pkts_received      = %llu\n", oq->stats.pkts_received);
		netdev_info(dev, "dropped_nodispatch = %llu\n", oq->stats.dropped_nodispatch);
		netdev_info(dev, "dropped_nomem      = %llu\n", oq->stats.dropped_nomem);
		netdev_info(dev, "dropped_toomany    = %llu\n", oq->stats.dropped_toomany);
		netdev_info(dev, "dropped_zlp        = %llu\n", oq->stats.dropped_zlp);
		netdev_info(dev, "pkts_delayed_data  = %llu\n", oq->stats.pkts_delayed_data);

		desc_ring = oq->desc_ring;
		for (idx = 0; idx < 32; idx++) {
			netdev_info(dev, "idx-%d buf_ptr = %llx\n", idx, desc_ring[idx].buffer_ptr);
		}
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
