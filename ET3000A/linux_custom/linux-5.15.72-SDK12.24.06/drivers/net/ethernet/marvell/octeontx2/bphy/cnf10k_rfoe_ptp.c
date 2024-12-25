// SPDX-License-Identifier: GPL-2.0
/* Marvell CNF10K BPHY RFOE Netdev Driver
 *
 * Copyright (C) 2021 Marvell.
 */

#include "cnf10k_rfoe.h"

#define EXT_PTP_CLK_RATE		(1000 * 1000000) /* Ext PTP clk rate */

enum {
	CNF10K_RFOE_HOST_OFFSET_INIT = 1,
	CNF10K_RFOE_HOST_OFFSET_ADJ,
};

static void cnf10k_rfoe_update_host_offset(struct cnf10k_rfoe_ndev_priv *priv,
					   u8 op, s64 delta)
{
	u64 nsec = 0, offset;

	if (op == CNF10K_RFOE_HOST_OFFSET_INIT) {
		/* No need to update host offset when sw timecounter is not used */
		if (!priv->use_sw_timecounter) {
			writeq(0, priv->ptp_reg_base + MIO_PTP_CKOUT_THRESH_HI);
			return;
		}
		/* We need to share an offset in ns from the PTP hardware counter
		 * and the UTC time so that the host PHC driver using the Octeon
		 * PTP counter can get the same real time as this PTP clock
		 * represents.  This is a combination of the timecounter fields
		 * nsec and cycle_last, and we can use timecounter_cyc2time() to
		 * generate this offset.
		 * We get the time in ns of the counter value of 0.  The host will
		 * then read the cycle counter, and add this value to the counter
		 * to obtain the real time as maintained by this timecounter.
		 */
		nsec = timecounter_cyc2time(&priv->time_counter, 0);
		writeq(nsec, priv->ptp_reg_base + MIO_PTP_CKOUT_THRESH_HI);
	} else if (op == CNF10K_RFOE_HOST_OFFSET_ADJ) {
		/* No need to update host offset when sw timecounter is not used */
		if (!priv->use_sw_timecounter)
			return;
		/* Adjust the offset that is shared with the host PHC driver
		 * whenever it is adjusted.  This offset is initialized
		 * when the timecounter is initialized, and updated here where an
		 * operation that adjusts the absolute value of the timecounter is
		 * performed.
		 */
		offset = readq(priv->ptp_reg_base + MIO_PTP_CKOUT_THRESH_HI);
		writeq(offset + delta, priv->ptp_reg_base + MIO_PTP_CKOUT_THRESH_HI);
	}
}

static void cnf10k_rfoe_ptp_atomic_update(struct cnf10k_rfoe_ndev_priv *priv, u64 timestamp)
{
	u64 regval, curr_rollover_set, nxt_rollover_set;

	/* update the timestamp values */
	writeq(timestamp, priv->ptp_reg_base + MIO_PTP_NANO_TIMESTAMP);
	writeq(0, priv->ptp_reg_base + MIO_PTP_FRNS_TIMESTAMP);
	writeq(timestamp / NSEC_PER_SEC,
	       priv->ptp_reg_base + MIO_PTP_SEC_TIMESTAMP);
	nxt_rollover_set = roundup(timestamp, NSEC_PER_SEC);
	curr_rollover_set = nxt_rollover_set - NSEC_PER_SEC;
	writeq(nxt_rollover_set, priv->ptp_reg_base + MIO_PTP_NXT_ROLLOVER_SET);
	writeq(curr_rollover_set, priv->ptp_reg_base + MIO_PTP_CURR_ROLLOVER_SET);

	/* initiate atomic update */
	regval = readq(priv->ptp_reg_base + MIO_PTP_CLOCK_CFG);
	regval &= ~MIO_PTP_CFG_TSTMP_SET_MASK;
	regval |= (ATOMIC_SET << 26);
	writeq(regval, priv->ptp_reg_base + MIO_PTP_CLOCK_CFG);
}

static void cnf10k_rfoe_update_ptp_clock(struct cnf10k_rfoe_ndev_priv *priv, s64 delta)
{
	bool neg_adj = false, atomic_inc_dec = false;
	u64 regval, ptp_clock_hi;

	if (delta < 0) {
		delta = -delta;
		neg_adj = true;
	}

	/* use atomic inc/dec when delta < 1 second */
	if (delta < NSEC_PER_SEC)
		atomic_inc_dec = true;

	if (!atomic_inc_dec) {
		ptp_clock_hi = readq(priv->ptp_reg_base + MIO_PTP_CLOCK_HI);
		if (neg_adj) {
			if (ptp_clock_hi > delta)
				ptp_clock_hi -= delta;
			else
				ptp_clock_hi = delta - ptp_clock_hi;
		} else {
			ptp_clock_hi += delta;
		}
		cnf10k_rfoe_ptp_atomic_update(priv, ptp_clock_hi);
	} else {
		writeq(delta, priv->ptp_reg_base + MIO_PTP_NANO_TIMESTAMP);
		writeq(0, priv->ptp_reg_base + MIO_PTP_FRNS_TIMESTAMP);
		/* initiate atomic inc/dec */
		regval = readq(priv->ptp_reg_base + MIO_PTP_CLOCK_CFG);
		regval &= ~MIO_PTP_CFG_TSTMP_SET_MASK;
		regval |= neg_adj ? (ATOMIC_DEC << 26) : (ATOMIC_INC << 26);
		writeq(regval, priv->ptp_reg_base + MIO_PTP_CLOCK_CFG);
	}
}

static int cnf10k_rfoe_ptp_adjtime(struct ptp_clock_info *ptp_info, s64 delta)
{
	struct cnf10k_rfoe_ndev_priv *priv = container_of(ptp_info,
							  struct
							  cnf10k_rfoe_ndev_priv,
							  ptp_clock_info);
	mutex_lock(&priv->ptp_lock);
	if (priv->use_sw_timecounter)
		timecounter_adjtime(&priv->time_counter, delta);
	else
		cnf10k_rfoe_update_ptp_clock(priv, delta);
	cnf10k_rfoe_update_host_offset(priv, CNF10K_RFOE_HOST_OFFSET_INIT, 0);
	mutex_unlock(&priv->ptp_lock);

	return 0;
}

static u64 ptp_calc_adjusted_comp(u64 ptp_clock_freq)
{
	u64 comp, adj = 0, cycles_per_sec, ns_drift = 0;
	u32 ptp_clock_nsec, cycle_time;
	int cycle;

	/* Errata:
	 * Issue #1: At the time of 1 sec rollover of the nano-second counter,
	 * the nano-second counter is set to 0. However, it should be set to
	 * (existing counter_value - 10^9).
	 *
	 * Issue #2: The nano-second counter rolls over at 0x3B9A_C9FF.
	 * It should roll over at 0x3B9A_CA00.
	 */

	/* calculate ptp_clock_comp value */
	comp = ((u64)1000000000ULL << 32) / ptp_clock_freq;
	/* use CYCLE_MULT to avoid accuracy loss due to integer arithmetic */
	cycle_time = NSEC_PER_SEC * CYCLE_MULT / ptp_clock_freq;
	/* cycles per sec */
	cycles_per_sec = ptp_clock_freq;

	/* check whether ptp nanosecond counter rolls over early */
	cycle = cycles_per_sec - 1;
	ptp_clock_nsec = (cycle * comp) >> 32;
	while (ptp_clock_nsec < NSEC_PER_SEC) {
		if (ptp_clock_nsec == 0x3B9AC9FF)
			goto calc_adj_comp;
		cycle++;
		ptp_clock_nsec = (cycle * comp) >> 32;
	}
	/* compute nanoseconds lost per second when nsec counter rolls over */
	ns_drift = ptp_clock_nsec - NSEC_PER_SEC;
	/* calculate ptp_clock_comp adjustment */
	if (ns_drift > 0) {
		adj = comp * ns_drift;
		adj = adj / 1000000000ULL;
	}
	/* speed up the ptp clock to account for nanoseconds lost */
	comp += adj;
	return comp;

calc_adj_comp:
	/* slow down the ptp clock to not rollover early */
	adj = comp * cycle_time;
	adj = adj / 1000000000ULL;
	adj = adj / CYCLE_MULT;
	comp -= adj;

	return comp;
}

static int cnf10k_rfoe_ptp_adjfine(struct ptp_clock_info *ptp, long scaled_ppm)
{
	struct cnf10k_rfoe_ndev_priv *priv = container_of(ptp,
							  struct
							  cnf10k_rfoe_ndev_priv,
							  ptp_clock_info);
	bool neg_adj = false;
	u32 freq, freq_adj;
	u64 comp, adj;
	s64 ppb;

	if (scaled_ppm < 0) {
		neg_adj = true;
		scaled_ppm = -scaled_ppm;
	}

	/* The hardware adds the clock compensation value to the PTP clock
	 * on every coprocessor clock cycle. Typical convention is that it
	 * represent number of nanosecond betwen each cycle. In this
	 * convention compensation value is in 64 bit fixed-point
	 * representation where upper 32 bits are number of nanoseconds
	 * and lower is fractions of nanosecond.
	 * The scaled_ppm represent the ratio in "parts per million" by which
	 * the compensation value should be corrected.
	 * To calculate new compenstation value we use 64bit fixed point
	 * arithmetic on following formula
	 * comp = tbase + tbase * scaled_ppm / (1M * 2^16)
	 * where tbase is the basic compensation value calculated
	 * initialy in the probe function.
	 */
	/* convert scaled_ppm to ppb */
	ppb = 1 + scaled_ppm;
	ppb *= 125;
	ppb >>= 13;


	if (priv->pdev->subsystem_device == PCI_SUBSYS_DEVID_CNF10K_B) {
		comp = ((u64)1000000000ull << 32) / priv->ptp_ext_clk_rate;
		adj = comp * ppb;
		adj = div_u64(adj, 1000000000ull);
		comp = neg_adj ? comp - adj : comp + adj;
	} else {
		/* calculate the new frequency based on ppb */
		freq_adj = (priv->ptp_ext_clk_rate * ppb) / 1000000000ULL;
		freq = neg_adj ? priv->ptp_ext_clk_rate + freq_adj :
				 priv->ptp_ext_clk_rate - freq_adj;
		comp = ptp_calc_adjusted_comp(freq);
	}

	writeq(comp, priv->ptp_reg_base + MIO_PTP_CLOCK_COMP);

	return 0;
}

u64 cnf10k_rfoe_read_ptp_clock(struct cnf10k_rfoe_ndev_priv *priv)
{
	u64 tstamp, sec, sec1,  nsec;

	if (priv->pdev->subsystem_device == PCI_SUBSYS_DEVID_CNF10K_B) {
		tstamp = readq(priv->ptp_reg_base + MIO_PTP_CLOCK_HI);
	} else {
		sec = readq(priv->ptp_reg_base + MIO_PTP_CLOCK_SEC) & 0xFFFFFFFFUL;
		nsec = readq(priv->ptp_reg_base + MIO_PTP_CLOCK_HI);
		sec1 = readq(priv->ptp_reg_base + MIO_PTP_CLOCK_SEC) & 0xFFFFFFFFUL;
		/* check nsec rollover */
		if (sec1 > sec) {
			nsec = readq(priv->ptp_reg_base + MIO_PTP_CLOCK_HI);
			sec = sec1;
		}
		tstamp = sec * NSEC_PER_SEC + nsec;
	}

	return tstamp;
}
EXPORT_SYMBOL_GPL(cnf10k_rfoe_read_ptp_clock);

static u64 cnf10k_rfoe_ptp_cc_read(const struct cyclecounter *cc)
{
	struct cnf10k_rfoe_ndev_priv *priv = container_of(cc,
							  struct cnf10k_rfoe_ndev_priv,
							  cycle_counter);
	return cnf10k_rfoe_read_ptp_clock(priv);
}

static int cnf10k_rfoe_ptp_gettime(struct ptp_clock_info *ptp_info,
				   struct timespec64 *ts)
{
	struct cnf10k_rfoe_ndev_priv *priv = container_of(ptp_info,
							  struct
							  cnf10k_rfoe_ndev_priv,
							  ptp_clock_info);
	u64 nsec;

	mutex_lock(&priv->ptp_lock);
	if (priv->use_sw_timecounter) {
		nsec = timecounter_read(&priv->time_counter);
	} else {
		nsec = cnf10k_rfoe_read_ptp_clock(priv);
		if (priv->ptp_cfg->use_ptp_alg)
			cnf10k_rfoe_calc_ptp_ts(priv, &nsec);
	}
	mutex_unlock(&priv->ptp_lock);

	*ts = ns_to_timespec64(nsec);

	return 0;
}

static void __cnf10k_rfoe_ptp_settime(struct cnf10k_rfoe_ndev_priv *priv,
				      const struct timespec64 *ts)
{
	u64 nsec = timespec64_to_ns(ts);

	mutex_lock(&priv->ptp_lock);
	if (priv->use_sw_timecounter)
		timecounter_init(&priv->time_counter, &priv->cycle_counter, nsec);
	else
		cnf10k_rfoe_ptp_atomic_update(priv, nsec);
	cnf10k_rfoe_update_host_offset(priv, CNF10K_RFOE_HOST_OFFSET_INIT, 0);
	mutex_unlock(&priv->ptp_lock);
}

static int cnf10k_rfoe_ptp_settime(struct ptp_clock_info *ptp_info,
				   const struct timespec64 *ts)
{
	struct cnf10k_rfoe_ndev_priv *priv = container_of(ptp_info,
							  struct
							  cnf10k_rfoe_ndev_priv,
							  ptp_clock_info);
	__cnf10k_rfoe_ptp_settime(priv, ts);

	return 0;
}

static int cnf10k_rfoe_ptp_verify_pin(struct ptp_clock_info *ptp,
				      unsigned int pin,
				      enum ptp_pin_function func,
				      unsigned int chan)
{
	switch (func) {
	case PTP_PF_NONE:
	case PTP_PF_EXTTS:
		break;
	case PTP_PF_PEROUT:
	case PTP_PF_PHYSYNC:
		return -1;
	}
	return 0;
}

static void cnf10k_rfoe_ptp_extts_check(struct work_struct *work)
{
	struct cnf10k_rfoe_ndev_priv *priv = container_of(work, struct
							  cnf10k_rfoe_ndev_priv,
							  extts_work.work);
	struct ptp_clock_event event;
	u64 tstmp, new_thresh;

	mutex_lock(&priv->ptp_lock);
	tstmp = readq(priv->ptp_reg_base + MIO_PTP_TIMESTAMP);
	mutex_unlock(&priv->ptp_lock);
	tstmp = cnf10k_ptp_convert_ext_timestamp(priv, tstmp);

	if (tstmp != priv->last_extts) {
		event.type = PTP_CLOCK_EXTTS;
		event.index = 0;
		event.timestamp = tstmp;
		if (priv->use_sw_timecounter)
			event.timestamp = timecounter_cyc2time(&priv->time_counter, tstmp);
		ptp_clock_event(priv->ptp_clock, &event);
		priv->last_extts = tstmp;
		/* Don't modify PPS threshold registers when SW timecounter is not used since
		 * PTP timestamp is entirely maintained in HW registers and the PPS threshold
		 * comparison (after adjtime) aligns the PPS output edge to master.
		 * Modifying PPS threshold registers makes the software workaround for PPS errata
		 * ineffective.
		 */
		if (priv->ptp_errata || !priv->use_sw_timecounter)
			goto resched;

		new_thresh = tstmp % 500000000;
		if (priv->thresh != new_thresh) {
			mutex_lock(&priv->ptp_lock);
			writeq(new_thresh,
			       priv->ptp_reg_base + MIO_PTP_PPS_THRESH_HI);
			mutex_unlock(&priv->ptp_lock);
			priv->thresh = new_thresh;
		}
	}
resched:
	schedule_delayed_work(&priv->extts_work, msecs_to_jiffies(200));
}

static enum hrtimer_restart ptp_reset_thresh(struct hrtimer *hrtimer)
{
	struct cnf10k_rfoe_ndev_priv *priv = container_of(hrtimer,
							  struct cnf10k_rfoe_ndev_priv, hrtimer);
	ktime_t curr_ts = ktime_get();
	ktime_t delta_ns, period_ns;
	u64 ptp_clock_hi;

	/* calculate the elapsed time since last restart */
	delta_ns = ktime_to_ns(ktime_sub(curr_ts, priv->last_ts));

	/* if the ptp clock value has crossed 0.5 seconds,
	 * its too late to update pps threshold value, so
	 * update threshold after 1 second.
	 */
	ptp_clock_hi = readq(priv->ptp_reg_base + MIO_PTP_CLOCK_HI);
	if (ptp_clock_hi > 500000000) {
		period_ns = ktime_set(0, (NSEC_PER_SEC + 100 - ptp_clock_hi));
	} else {
		writeq(500000000, priv->ptp_reg_base + MIO_PTP_PPS_THRESH_HI);
		period_ns = ktime_set(0, (NSEC_PER_SEC + 100 - delta_ns));
	}

	hrtimer_forward_now(hrtimer, period_ns);
	priv->last_ts = curr_ts;

	return HRTIMER_RESTART;
}

static void ptp_hrtimer_start(struct cnf10k_rfoe_ndev_priv *priv, ktime_t start_ns)
{
	ktime_t period_ns;

	period_ns = ktime_set(0, (NSEC_PER_SEC + 100 - start_ns));
	hrtimer_start(&priv->hrtimer, period_ns, HRTIMER_MODE_REL);
	priv->last_ts = ktime_get();
}

static int ptp_config_hrtimer(struct cnf10k_rfoe_ndev_priv *priv, int on)
{
	u64 ptp_clock_hi;

	if (on) {
		ptp_clock_hi = readq(priv->ptp_reg_base + MIO_PTP_CLOCK_HI);
		ptp_hrtimer_start(priv, (ktime_t)ptp_clock_hi);
	} else {
		if (hrtimer_active(&priv->hrtimer))
			hrtimer_cancel(&priv->hrtimer);
	}

	return 0;
}

static int ptp_pps_on(struct cnf10k_rfoe_ndev_priv *priv, int on)
{
	u64 clock_cfg;

	clock_cfg = readq(priv->ptp_reg_base + MIO_PTP_CLOCK_CFG);

	if (on) {
		clock_cfg |= PTP_CLOCK_CFG_PPS_EN | PTP_CLOCK_CFG_PPS_INV;
		writeq(clock_cfg, priv->ptp_reg_base + MIO_PTP_CLOCK_CFG);

		writeq(0, priv->ptp_reg_base + MIO_PTP_PPS_THRESH_HI);
		writeq(0, priv->ptp_reg_base + MIO_PTP_PPS_THRESH_LO);

		/* Set 50% duty cycle for 1Hz output */
		writeq(0x1dcd650000000000, priv->ptp_reg_base + MIO_PTP_PPS_HI_INCR);
		writeq(0x1dcd650000000000, priv->ptp_reg_base + MIO_PTP_PPS_LO_INCR);

	} else {
		clock_cfg &= ~(PTP_CLOCK_CFG_PPS_EN | PTP_CLOCK_CFG_PPS_INV);
		writeq(clock_cfg, priv->ptp_reg_base + MIO_PTP_CLOCK_CFG);
	}

	if (on && priv->ptp_errata) {
		/* The ptp_clock_hi rollsover to zero once clock cycle before it
		 * reaches one second boundary. so, program the pps_lo_incr in
		 * such a way that the pps threshold value comparison at one
		 * second boundary will succeed and pps edge changes. After each
		 * one second boundary, the hrtimer handler will be invoked and
		 * reprograms the pps threshold value.
		 */
		priv->clock_rate = 1000 * 1000000; //sclk to 1000
		priv->clock_period = NSEC_PER_SEC / priv->clock_rate;
		writeq((0x1dcd6500ULL - priv->clock_period) << 32,
		       priv->ptp_reg_base + MIO_PTP_PPS_LO_INCR);
	}

	if (priv->ptp_errata)
		ptp_config_hrtimer(priv, on);

	return 0;
}

static int cnf10k_rfoe_ptp_enable(struct ptp_clock_info *ptp_info,
				  struct ptp_clock_request *rq, int on)
{
	struct cnf10k_rfoe_ndev_priv *priv = container_of(ptp_info,
							  struct
							  cnf10k_rfoe_ndev_priv,
							  ptp_clock_info);
	int pin = -1;

	switch (rq->type) {
	case PTP_CLK_REQ_EXTTS:
		pin = ptp_find_pin(priv->ptp_clock, PTP_PF_EXTTS,
				   rq->extts.index);
		if (pin < 0)
			return -EBUSY;
		if (on)
			schedule_delayed_work(&priv->extts_work,
					      msecs_to_jiffies(200));
		else
			cancel_delayed_work_sync(&priv->extts_work);
		return 0;
	case PTP_CLK_REQ_PEROUT:
		if (rq->perout.flags)
			return -EOPNOTSUPP;

		if (rq->perout.index >= ptp_info->n_pins)
			return -EINVAL;
		if (on) {
			if (rq->perout.period.sec == 1 &&
			    rq->perout.period.nsec == 0) {
				ptp_pps_on(priv, on);
			} else {
				netdev_info(priv->netdev, "PTP_CLK_REQ_PEROUT error unsupported period values\n");
				return -EOPNOTSUPP;
			}

		} else {
			ptp_pps_on(priv, on);
		}

		return 0;
	default:
		break;
	}

	return -EOPNOTSUPP;
}

int cnf10k_rfoe_ptp_reset_sw_phc(struct cnf10k_rfoe_ndev_priv *priv)
{
	struct timespec64 ts;

	if (!priv->use_sw_timecounter)
		return -EINVAL;

	if (IS_ERR_OR_NULL(priv->ptp_clock))
		return -EINVAL;

	ts.tv_sec = 0;
	ts.tv_nsec = 0;
	__cnf10k_rfoe_ptp_settime(priv, &ts);

	return 0;
}

static const struct ptp_clock_info cnf10k_rfoe_ptp_clock_info = {
	.owner          = THIS_MODULE,
	.name		= "CNF10K RFOE PTP",
	.max_adj        = 1000000000ull,
	.n_ext_ts       = 1,
	.n_per_out      = 1,
	.n_pins         = 1,
	.pps            = 0,
	.adjfine	= cnf10k_rfoe_ptp_adjfine,
	.adjtime        = cnf10k_rfoe_ptp_adjtime,
	.gettime64      = cnf10k_rfoe_ptp_gettime,
	.settime64      = cnf10k_rfoe_ptp_settime,
	.enable         = cnf10k_rfoe_ptp_enable,
	.verify		= cnf10k_rfoe_ptp_verify_pin,
};

int cnf10k_rfoe_ptp_init(struct cnf10k_rfoe_ndev_priv *priv)
{
	struct cyclecounter *cc;
	u64 rx_cfg;
	int err;
	u64 tmp;

	if (priv->pdev->subsystem_device == PCI_SUBSYS_DEVID_CNF10K_B)
		priv->use_sw_timecounter = 0;
	else
		priv->use_sw_timecounter = 1;

	if (priv->use_sw_timecounter) {
		cc = &priv->cycle_counter;
		cc->read = cnf10k_rfoe_ptp_cc_read;
		cc->mask = CYCLECOUNTER_MASK(64);
		cc->mult = 1;
		cc->shift = 0;
		timecounter_init(&priv->time_counter, &priv->cycle_counter,
				 ktime_to_ns(ktime_get_real()));
	}

	snprintf(priv->extts_config.name, sizeof(priv->extts_config.name),
		 "CNF10K RFOE TSTAMP");
	priv->extts_config.index = 0;
	priv->extts_config.func = PTP_PF_NONE;
	priv->ptp_ext_clk_rate = EXT_PTP_CLK_RATE;

	priv->ptp_clock_info = cnf10k_rfoe_ptp_clock_info;
	snprintf(priv->ptp_clock_info.name, 16, "%s", priv->netdev->name);
	priv->ptp_clock_info.pin_config = &priv->extts_config;
	INIT_DELAYED_WORK(&priv->extts_work, cnf10k_rfoe_ptp_extts_check);
	priv->ptp_clock = ptp_clock_register(&priv->ptp_clock_info,
					     &priv->pdev->dev);
	if (IS_ERR_OR_NULL(priv->ptp_clock)) {
		priv->ptp_clock = NULL;
		err = PTR_ERR(priv->ptp_clock);
		return err;
	}

	/* Enable PTP CKOUT, as we use the MIO_PTP_CKOUT_THRESH_HI register
	 * to share the offset to be added to MIO_PTP_CLOCK_HI to get UTC
	 * time in nanoseconds.  The MIO_PTP_CKOUT_THRESH_HI is updated
	 * whenever any changes are made to the offset through the
	 * _settime() or _adjtime() functions.
	 *
	 */
	tmp = readq(priv->ptp_reg_base + MIO_PTP_CLOCK_CFG);
	writeq(tmp | PTP_CLOCK_CFG_CKOUT_EN,
	       priv->ptp_reg_base + MIO_PTP_CLOCK_CFG);
	cnf10k_rfoe_update_host_offset(priv, CNF10K_RFOE_HOST_OFFSET_INIT, 0);

	/* Enable FORCE_COND_CLK_EN */
	if (is_cnf10ka_a0(priv) || is_cnf10ka_a1(priv) || is_cnf10kb_a0(priv)) {
		rx_cfg = readq(priv->rfoe_reg_base + CNF10K_RFOEX_RX_CFG(priv->rfoe_num));
		rx_cfg |= FORCE_COND_CLK_EN;
		writeq(rx_cfg, priv->rfoe_reg_base + CNF10K_RFOEX_RX_CFG(priv->rfoe_num));
		mutex_init(&priv->ptp_lock);
	}

	hrtimer_init(&priv->hrtimer, CLOCK_MONOTONIC, HRTIMER_MODE_REL);
	priv->hrtimer.function = ptp_reset_thresh;

	return 0;
}

void cnf10k_rfoe_ptp_destroy(struct cnf10k_rfoe_ndev_priv *priv)
{
	cancel_delayed_work_sync(&priv->extts_work);
	ptp_clock_unregister(priv->ptp_clock);
	priv->ptp_clock = NULL;
}

int cnf10k_rfoe_ptp_tstamp2time(struct cnf10k_rfoe_ndev_priv *priv, u64 tstamp,
				u64 *tsns)
{
	if (!priv->ptp_clock)
		return -ENODEV;

	*tsns = timecounter_cyc2time(&priv->time_counter, tstamp);

	return 0;
}
EXPORT_SYMBOL_GPL(cnf10k_rfoe_ptp_tstamp2time);
