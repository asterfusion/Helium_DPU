/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2019 Marvell International Ltd.
 */

#include <signal.h>
#include <stdbool.h>

#include <rte_mbuf.h>
#include <rte_mempool.h>
#include <rte_rawdev.h>

#include "otx2_common.h"
#include "otx2_ep_perf.h"
#include "otx2_ep_rawdev.h"

void pci_ep_host_exit_rawdev(uint16_t dev_id)
{
	rte_rawdev_stop(dev_id);
	rte_rawdev_close(dev_id);
}

void pci_ep_host_signal_handler(int signum)
{
	if (signum == SIGINT || signum == SIGTERM) {
		pciep_info("Signal %d received", signum);
		pciep_info("Preparing to exit...\n");
		force_quit = true;
	}
}

static inline uint64_t
sf_endian_swap_8B(uint64_t _d)
{
	return ((((((uint64_t)(_d)) >>  0) & (uint64_t)0xff) << 56) |
		(((((uint64_t)(_d)) >>  8) & (uint64_t)0xff) << 48) |
		(((((uint64_t)(_d)) >> 16) & (uint64_t)0xff) << 40) |
		(((((uint64_t)(_d)) >> 24) & (uint64_t)0xff) << 32) |
		(((((uint64_t)(_d)) >> 32) & (uint64_t)0xff) << 24) |
		(((((uint64_t)(_d)) >> 40) & (uint64_t)0xff) << 16) |
		(((((uint64_t)(_d)) >> 48) & (uint64_t)0xff) <<  8) |
		(((((uint64_t)(_d)) >> 56) & (uint64_t)0xff) <<  0));
}


static inline void
pci_ep_set_default_pkg(uint8_t *dst, uint32_t dstlen)
{
    uint32_t copyLen = dstlen >= 55 ? 55 : dstlen;
    uint64_t rand = rte_rand();
	
    uint8_t df[55] = {0x20,0x6b,0xe7,0x62,0x59,0x32,0x50,0x2b,
                      0x73,0xd4,0x5e,0x7a,0x08,0x00,0x45,0x00,
                      0x00,0x29,0x1d,0xfc,0x40,0x00,0x80,0x06,
                      0xc5,0x0f,0xc0,0xa8,0x0a,0x74,0xcb,0x77,
                      0x81,0x2f,0xff,0x5f,0x01,0xbb,0xf7,0xe8,
                      0x8e,0x2e,0x97,0x17,0x44,0x69,0x50,0x10,
                      0xfd,0x20,0x38,0x3c,0x00,0x00,0x00};

    for (uint32_t ci = 0; ci < copyLen; ci++) {
        dst[ci] = (uint8_t)(df[ci] + rand & 0xff);
    }
    return;
}



int pci_ep_host_hw_config(struct pci_ep_core_info *core_info, int num_rawdev)
{
	struct rte_rawdev_info dev_info = { 0 };
	struct sdp_rawdev_info config;
	struct rte_mempool *mpool;
	uint16_t dev_id;
	int index;
	int ret;
    int queues=0;

    char pname[20] = {0};

	for (index = 0; index < num_rawdev; index++) {
		dev_id = rte_rawdev_get_dev_id(core_info[index].rawdev_name);
		if ((int16_t)dev_id < 0) {
			pciep_err("Provided BDF %s is not a rawdev",
				core_info[index].rawdev_name);
			return PCI_EP_FAILURE;
		}

        queues = rte_rawdev_otx2_get_rpvf(dev_id);
        if (0 >= queues) {
            pciep_err("Get sdp queues err");
        }

        memset(pname, 0, 20);
        sprintf(pname, "pciep_pool%d", index);    
    	mpool = rte_mempool_create(pname,
			queues*16384 /* Num elt */,
			RTE_MBUF_DEFAULT_BUF_SIZE /* Elt size */,
			0 /* Cache_size */,
			0 /* Private_data_size */,
			NULL /* MP_init */,
			NULL /* MP_init arg */,
			NULL /* Obj_init */,
			NULL /* Obj_init arg */,
			rte_socket_id() /* Socket id */,
			0 /* Flags */);

        if (!mpool) {
            pciep_err("Failed to create mempool");
            return PCI_EP_FAILURE;
	    }

	    memset(&config, 0x00, sizeof(config));

        // config sdp interfaces
	    config.enqdeq_mpool = mpool;
	    config.app_conf = NULL;


        struct sdp_config  sf_sdp_conf = {
            /* IQ attributes */
            .iq                        = {
            	.max_iqs           = SDP_VF_CFG_IO_QUEUES,
            	.instr_type        = SDP_VF_64BYTE_INSTR,
            	.pending_list_size = (SDP_VF_MAX_IQ_DESCRIPTORS *
            			      SDP_VF_CFG_IO_QUEUES),
            },
            
            /* OQ attributes */
            .oq                        = {
            	.max_oqs           = SDP_VF_CFG_IO_QUEUES,
            	.info_ptr          = SDP_VF_OQ_INFOPTR_MODE,
            	.refill_threshold  = SDP_VF_OQ_REFIL_THRESHOLD,
            },
            
            .num_iqdef_descs           = SDP_VF_MAX_IQ_DESCRIPTORS,
            .num_oqdef_descs           = SDP_VF_MAX_OQ_DESCRIPTORS,
            .oqdef_buf_size            = SDP_VF_OQ_BUF_SIZE,
        
        };

	    config.app_conf = &sf_sdp_conf;

		core_info[index].mempool = mpool;
		core_info[index].rawdev_id = dev_id;
		core_info[index].queues = queues;


		dev_info.dev_private = &config;
		ret = rte_rawdev_configure(core_info[index].rawdev_id,
					   &dev_info);
		if (ret) {
			pciep_err("Couldn't able to configure PCI_EP %s",
				core_info[index].rawdev_name);
			return PCI_EP_FAILURE;
		}

		ret = rte_rawdev_start(core_info[index].rawdev_id);
		if (ret) {
			pciep_err("Couldn't able to start PCI_EP %s",
					core_info[index].rawdev_name);
			return PCI_EP_FAILURE;
		}
	}

	return PCI_EP_SUCCESS;
}

int pci_ep_host_get_stats(struct pci_ep_core_run_info *run_info, int num_rawdev,
                      struct pci_ep_stats *delta_stats)
{
	struct pci_ep_stats ioq_tot_stats = { 0 };
	static struct pci_ep_stats ioq_last_stats;
	int core_id;

	for (core_id = 0; core_id < num_rawdev; core_id++) {
		ioq_tot_stats.tx_events +=
			run_info[core_id].stats.tx_events;
		ioq_tot_stats.tx_bytes  +=
			run_info[core_id].stats.tx_bytes;
		ioq_tot_stats.rx_events +=
			run_info[core_id].stats.rx_events;
		ioq_tot_stats.rx_bytes  +=
			run_info[core_id].stats.rx_bytes;
	}

	delta_stats->tx_events =
		ioq_tot_stats.tx_events - ioq_last_stats.tx_events;
	delta_stats->tx_bytes  =
		ioq_tot_stats.tx_bytes - ioq_last_stats.tx_bytes;
	delta_stats->rx_events =
		ioq_tot_stats.rx_events - ioq_last_stats.rx_events;
	delta_stats->rx_bytes  =
		ioq_tot_stats.rx_bytes - ioq_last_stats.rx_bytes;

	memcpy(&ioq_last_stats, &ioq_tot_stats, sizeof(ioq_last_stats));

	return PCI_EP_SUCCESS;
}



void pci_ep_tx_pkts(struct pci_ep_core_info *core_info, uint8_t q_no,
                     uint64_t pkg_num, uint8_t *mbuf, struct pci_ep_stats *stats)
{
	void *buf;
	struct sdp_soft_instr si;
    uint32_t idx = 0;
    uint32_t headlen = ( (mbuf == NULL) ? 0 : 8 );

    while ( !force_quit && idx < pkg_num) {

        memset(&si, 0x00, sizeof(si));
        si.q_no = q_no;
        si.rptr = NULL;
        si.ih.fsz = PCI_EP_HOST_PKT_FRONT_SIZE;
        si.ih.tlen = core_info->pktlen + headlen;
        si.ih.gather = 0;
        //si.irh.rid = 1;
        si.reqtype = SDP_REQTYPE_NORESP;

        if (!mbuf) {
            rte_mempool_get(core_info->mempool, &buf);
            if (!buf) {
                pciep_dbg("Buffer allocation failed");
                break;
            }

            si.dptr = (uint8_t *)buf;
		    //use default pkg
            pci_ep_set_default_pkg(si.dptr, si.ih.tlen);
        } else {
            si.dptr = mbuf;
        }

        while (!rte_rawdev_enqueue_buffers(core_info->rawdev_id, NULL, 1, &si)) {
            rte_pause();
        }

        idx ++;
        stats->tx_events++;
        stats->tx_bytes += core_info->pktlen;
        if(core_info->dump)
        {
            printf("\nsend data len %d: ...\n", core_info->pktlen+headlen);
            int i = 0;
            for (i = 0; i < core_info->pktlen+headlen; i++)
            {
                if(i && (i%16==0)) printf("\n");
                printf("%02x ", ((uint8_t*)si.dptr)[i]);
            }
            printf("\n");
        }

    }
    return;
}


void pci_ep_rx_pkts(struct pci_ep_core_info *core_info, uint8_t q_no,
                    struct rte_rawdev_buf **buffers, uint64_t pkg_num,
                    struct pci_ep_stats *stats)

{
    struct sdp_droq_pkt *oq_pkt;
    uint64_t pkt_count = 0;
    int64_t count = 0;
    int64_t idx=0;
	struct sdp_soft_instr si;

    si.q_no = q_no;
    while (!force_quit && pkt_count < pkg_num)
    {
		/* Dequeue */

        count = rte_rawdev_dequeue_buffers(core_info->rawdev_id, buffers,
                                            core_info->burst_size, &si);
        if (count <= 0) continue;

        for (idx = 0; idx < count; idx++)
        {
            oq_pkt = (struct sdp_droq_pkt *)buffers[idx];

            if(core_info->dump) {
                printf ("\n>>> recv data len %d\n", oq_pkt->len+ 8);
                uint8_t i = 0;
                uint8_t *header = (uint8_t*)(&(oq_pkt->header));
                for (i = 0; i < 8; i++) {
                    printf("%02x ", header[i]);
                }

                for (i = 0; i< oq_pkt->len; i++) {
                    if(i && ((i+8)%16==0)) printf("\n");
                    printf("%02x ", oq_pkt->data[i]);
                }

                printf("\n");
            }

            rte_mempool_put(core_info->mempool, oq_pkt->data);

            stats->rx_events++;
            stats->rx_bytes += oq_pkt->len+8;
        }
        pkt_count += count;

        //clear recv buffer records
        for (idx = 0; idx < core_info->burst_size; idx++) {
            memset((struct sdp_droq_pkt *)buffers[idx], 0x00, 
                       sizeof(struct sdp_droq_pkt));
        }
    }
    return;
}



void pci_ep_ec96_pkts(struct pci_ep_core_info *core_info, uint8_t q_no,
                     struct rte_rawdev_buf **buffers, struct pci_ep_stats *stats)
{

    struct sdp_droq_pkt *oq_pkt;
    int count = 0;
    int idx=0;
    struct sdp_soft_instr si;

    si.q_no = q_no;

	while (!force_quit) {
		/* Dequeue */
        count = rte_rawdev_dequeue_buffers(core_info->rawdev_id, buffers,
                                            core_info->burst_size, &si);
        if (count <= 0) continue;

        for (idx = 0; idx < count; idx++)
        {
            oq_pkt = (struct sdp_droq_pkt *)buffers[idx];

            if(core_info->dump) {
                printf ("\n>>> recv data len %d\n", oq_pkt->len+ 8);
                int i = 0;
                uint8_t *header = (uint8_t*)(&(oq_pkt->header));
                for (i = 0; i < 8; i++) {
                    printf("%02x ", header[i]);
                }
                for (uint32_t ilen = 0; ilen< oq_pkt->len; ilen++) {
                    if(ilen && ((ilen+8)%16==0)) printf("\n");
                    printf("%02x ", oq_pkt->data[ilen]);
                }
            }

            stats->rx_events++;
            stats->rx_bytes += oq_pkt->len+8;


            void *mbuf;
            rte_mempool_get(core_info->mempool, &mbuf);
            if (!mbuf) {
                pciep_dbg("Buffer allocation failed");
			    rte_mempool_put(core_info->mempool, oq_pkt->data);
                break;
            }

            ((uint64_t *)mbuf)[0] = oq_pkt->header;
            uint8_t *cbuf = (uint8_t*)(&(((uint64_t*)mbuf)[1]));
            memcpy(cbuf, oq_pkt->data, oq_pkt->len);
            core_info->pktlen = oq_pkt->len;

            pci_ep_tx_pkts(core_info, q_no, 1, mbuf, stats);
			rte_mempool_put(core_info->mempool, oq_pkt->data);
        }

        //clear recv buffer records
        for (idx = 0; idx < core_info->burst_size; idx++) {
            memset((struct sdp_droq_pkt *)buffers[idx], 0x00, 
                       sizeof(struct sdp_droq_pkt));
        }

	}

    return;
}



int pci_ep_host_data_loop(void *arg_ptr)
{
	struct pci_ep_core_run_info *run_info = (struct pci_ep_core_run_info *)arg_ptr;
	struct pci_ep_core_info *core_info = (struct pci_ep_core_info *)(run_info->config);
	struct sdp_droq_pkt oq_pkt_obj[core_info->burst_size];
	struct rte_rawdev_buf *d_buf[core_info->burst_size];
	int idx;
    uint64_t pm;
    uint8_t q_id = run_info->queue_id;

    for (idx = 0; idx < core_info->burst_size; idx++) {
        memset(&oq_pkt_obj[idx], 0x00, sizeof(struct sdp_droq_pkt));
        d_buf[idx] = (struct rte_rawdev_buf *)&oq_pkt_obj[idx];
    }

    printf("CONFIG: queue_id %d, pktnum %lu, pktlen %d, rawdev_id %d\n",
            q_id, core_info->pktnum, core_info->pktlen, core_info->rawdev_id);

    switch (core_info->mode) 
    {
        case conn_rx_only:
            pci_ep_rx_pkts(core_info, q_id, d_buf, core_info->pktnum,
					        &(run_info->stats));
            break;
        case conn_tx_only:
            pci_ep_tx_pkts(core_info, q_id, core_info->pktnum, 0, 
					        &(run_info->stats));
            break;
        case conn_rxtx:  
            for (pm = 0; pm < core_info->pktnum; pm ++) {
                pci_ep_tx_pkts(core_info, q_id, 1, 0, &(run_info->stats));
                pci_ep_rx_pkts(core_info, q_id, d_buf, 1, &(run_info->stats));
            }
            break;
        case conn_ec96:
            pci_ep_ec96_pkts(core_info, q_id, d_buf, &(run_info->stats));
            break;
        default :
            break;
    }

//	pci_ep_host_exit_rawdev(core_info->rawdev_id);
//	force_quit = true;

	return PCI_EP_SUCCESS;
}


