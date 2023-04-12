/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2017 Cavium, Inc
 */

#include <string.h>
#include <errno.h>
#include "octeontx_sdp.h"

/* Response messages */
enum {
	MBOX_RET_SUCCESS,
	MBOX_RET_INVALID,
	MBOX_RET_INTERNAL_ERR,
};

int
octeontx_sdp_port_open(int port, octeontx_mbox_sdp_port_conf_t *conf)
{
	struct octeontx_mbox_hdr hdr;
	octeontx_mbox_sdp_port_conf_t sdp_conf = {0};
	int len = sizeof(octeontx_mbox_sdp_port_conf_t);

	hdr.coproc = OCTEONTX_SDP_COPROC;
	hdr.msg = MBOX_SDP_PORT_OPEN;
	hdr.vfid = port;

	if (octeontx_mbox_send(&hdr, NULL, 0, &sdp_conf, len) < 0 ||
			       hdr.res_code != MBOX_RET_SUCCESS) {
		return -EACCES;
	}

	conf->enable = sdp_conf.enable;
	conf->bpen = sdp_conf.bpen;
	conf->node = sdp_conf.node;
	conf->base_chan = sdp_conf.base_chan;
	conf->num_chans = sdp_conf.num_chans;
	conf->sdp = sdp_conf.sdp;
	conf->lmac = sdp_conf.lmac;
	conf->pkind = sdp_conf.pkind;

	return 0;
}

int
octeontx_sdp_port_close(int port)
{
	struct octeontx_mbox_hdr hdr;

	hdr.coproc = OCTEONTX_SDP_COPROC;
	hdr.msg = MBOX_SDP_PORT_CLOSE;
	hdr.vfid = port;

	if (octeontx_mbox_send(&hdr, NULL, 0, NULL, 0) < 0 ||
	    hdr.res_code != MBOX_RET_SUCCESS)
		return -EACCES;

	return 0;
}

int
octeontx_sdp_port_start(int port)
{
	struct octeontx_mbox_hdr hdr;

	hdr.coproc = OCTEONTX_SDP_COPROC;
	hdr.msg = MBOX_SDP_PORT_START;
	hdr.vfid = port;

	if (octeontx_mbox_send(&hdr, NULL, 0, NULL, 0) < 0 ||
			       hdr.res_code != MBOX_RET_SUCCESS)
		return -EACCES;

	return 0;
}

int
octeontx_sdp_port_stop(int port)
{
	struct octeontx_mbox_hdr hdr;

	hdr.coproc = OCTEONTX_SDP_COPROC;
	hdr.msg = MBOX_SDP_PORT_STOP;
	hdr.vfid = port;

	if (octeontx_mbox_send(&hdr, NULL, 0, NULL, 0) < 0 ||
			       hdr.res_code != MBOX_RET_SUCCESS)
		return -EACCES;

	return 0;
}

int
octeontx_sdp_port_config(int port, octeontx_mbox_sdp_port_conf_t *conf)
{
	struct octeontx_mbox_hdr hdr;
	octeontx_mbox_sdp_port_conf_t sdp_conf = {0};
	int len = sizeof(octeontx_mbox_sdp_port_conf_t);

	hdr.coproc = OCTEONTX_SDP_COPROC;
	hdr.msg = MBOX_SDP_PORT_GET_CONFIG;
	hdr.vfid = port;

	if (octeontx_mbox_send(&hdr, NULL, 0, &sdp_conf, len) < 0 ||
			       hdr.res_code != MBOX_RET_SUCCESS)
		return -EACCES;

	conf->enable = sdp_conf.enable;
	conf->bpen = sdp_conf.bpen;
	conf->node = sdp_conf.node;
	conf->base_chan = sdp_conf.base_chan;
	conf->num_chans = sdp_conf.num_chans;
	conf->sdp = sdp_conf.sdp;
	conf->lmac = sdp_conf.lmac;
	conf->pkind = sdp_conf.pkind;

	return 0;
}

int
octeontx_sdp_port_status(int port, octeontx_mbox_sdp_port_status_t *stat)
{
	struct octeontx_mbox_hdr hdr;
	octeontx_mbox_sdp_port_status_t sdp_stat;
	int len = sizeof(octeontx_mbox_sdp_port_status_t);

	hdr.coproc = OCTEONTX_SDP_COPROC;
	hdr.msg = MBOX_SDP_PORT_GET_STATUS;
	hdr.vfid = port;

	if (octeontx_mbox_send(&hdr, NULL, 0, &sdp_stat, len) < 0 ||
			       hdr.res_code != MBOX_RET_SUCCESS)
		return -EACCES;

	stat->link_up = sdp_stat.link_up;

	return 0;
}

int
octeontx_sdp_port_stats(int port, octeontx_mbox_sdp_port_stats_t *stats)
{
	struct octeontx_mbox_hdr hdr;
	octeontx_mbox_sdp_port_stats_t sdp_stats;
	int len = sizeof(octeontx_mbox_sdp_port_stats_t);

	hdr.coproc = OCTEONTX_SDP_COPROC;
	hdr.msg = MBOX_SDP_PORT_GET_STATS;
	hdr.vfid = port;

	if (octeontx_mbox_send(&hdr, NULL, 0, &sdp_stats, len) < 0 ||
			       hdr.res_code != MBOX_RET_SUCCESS)
		return -EACCES;

	stats->rx_packets = sdp_stats.rx_packets;
	stats->rx_bytes = sdp_stats.rx_bytes;
	stats->rx_dropped = sdp_stats.rx_dropped;
	stats->rx_errors = sdp_stats.rx_errors;
	stats->tx_packets = sdp_stats.tx_packets;
	stats->tx_bytes = sdp_stats.tx_bytes;
	stats->tx_dropped = sdp_stats.tx_dropped;
	stats->tx_errors = sdp_stats.tx_errors;

	return 0;
}

int
octeontx_sdp_port_stats_clr(int port)
{
	struct octeontx_mbox_hdr hdr;

	hdr.coproc = OCTEONTX_SDP_COPROC;
	hdr.msg = MBOX_SDP_PORT_CLR_STATS;
	hdr.vfid = port;

	if (octeontx_mbox_send(&hdr, NULL, 0, NULL, 0) < 0 ||
			       hdr.res_code != MBOX_RET_SUCCESS)
		return -EACCES;

	return 0;
}

int
octeontx_sdp_port_link_status(int port)
{
	struct octeontx_mbox_hdr hdr;
	uint8_t link;
	int len = sizeof(uint8_t);

	hdr.coproc = OCTEONTX_SDP_COPROC;
	hdr.msg = MBOX_SDP_PORT_GET_LINK_STATUS;
	hdr.vfid = port;

	if (octeontx_mbox_send(&hdr, NULL, 0, &link, len) < 0 ||
			       hdr.res_code != MBOX_RET_SUCCESS)
		return -EACCES;

	return link;
}

int
octeontx_sdp_reg_read(uint64_t addr, uint64_t *val)
{
	struct octeontx_mbox_hdr hdr;
	octeontx_mbox_sdp_reg_t reg;
	int len = sizeof(octeontx_mbox_sdp_reg_t);

	/* Need to validate address range */
	hdr.coproc = OCTEONTX_SDP_COPROC;
	hdr.msg = MBOX_SDP_REG_READ;
	hdr.vfid = 0;
	reg.addr = addr;
	reg.val = 0;

	if (octeontx_mbox_send(&hdr, &reg, len, &reg, len) < 0 ||
	    hdr.res_code != MBOX_RET_SUCCESS)
		return -EACCES;

	*val = reg.val;
	return 0;
}

int
octeontx_sdp_reg_write(uint64_t addr, uint64_t val)
{
	struct octeontx_mbox_hdr hdr;
	octeontx_mbox_sdp_reg_t reg;
	int len = sizeof(octeontx_mbox_sdp_reg_t);

	/* Need to validate address range */
	hdr.coproc = OCTEONTX_SDP_COPROC;
	hdr.msg = MBOX_SDP_REG_WRITE;
	hdr.vfid = 0;
	reg.addr = addr;
	reg.val = val;

	if (octeontx_mbox_send(&hdr, &reg, len, NULL, 0) < 0 ||
	    hdr.res_code != MBOX_RET_SUCCESS)
		return -EACCES;

	return 0;
}
