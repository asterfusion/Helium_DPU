// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2019 Marvell International Ltd.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#define pr_fmt(fmt)  "octeontx2-serdes: " fmt

#include <linux/module.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/list.h>
#include <linux/string.h>
#include <linux/time.h>
#include <linux/pci.h>
#include <linux/uaccess.h>
#include <linux/fs.h>
#include <linux/debugfs.h>
#include <linux/arm-smccc.h>
#include <soc/marvell/octeontx/octeontx_smc.h>

#define OCTEONTX_SERDES_DBG_GET_MEM	0xc2000d04
#define OCTEONTX_SERDES_DBG_GET_EYE	0xc2000d05
#define OCTEONTX_SERDES_DBG_GET_CONF	0xc2000d06
#define OCTEONTX_SERDES_DBG_PRBS	0xc2000d07
#define OCTEONTX_SERDES_DBG_SET_TUNE	0xc2000d08
#define OCTEONTX_SERDES_DBG_SET_LOOP	0xc2000d09

#define MAX_LMAC_PER_CGX		4

#define OCTEONTX_SMC_PENDING		0x1

#define SERDES_SETTINGS_SIZE		0x1000


enum qlm_type {
	QLM_GSERC_TYPE,
	QLM_GSERR_TYPE,
	QLM_GSERN_TYPE,
};


enum cgx_prbs_cmd {
	CGX_PRBS_START_CMD = 1,
	CGX_PRBS_STOP_CMD,
	CGX_PRBS_GET_DATA_CMD,
	CGX_PRBS_CLEAR_CMD
};

struct cgx_prbs_errors {
	u64 err;
	u64 phy_host;
	u64 phy_line;
};

struct cgx_prbs_data {
	u64 num_lanes;
	struct cgx_prbs_errors errors[MAX_LMAC_PER_CGX];
};

struct prbs_status {
	struct list_head list;
	int qlm;
	int qlm_lane;
	long start_time;
	struct prbs_status *next;
};

struct eye_data {
	int width;
	int height;
	u32 data[64][128];
	enum qlm_type type;
};

static struct {
	int qlm;
	int lane;
	struct eye_data *res;
} eye_cmd_data;

static struct {
	int qlm;
	int lane;
	char *res;
} serdes_cmd_data;

static struct {
	int qlm;
	int lane;
	int swing;
	int pre;
	int post;
	char *res;
} tune_serdes_cmd;

static struct {
	int qlm;
	int lane;
	int type;
	char *res;
} loop_serdes_cmd;

static struct {
	int qlm;
	int qlm_lane;
	struct prbs_status status_list;
	struct cgx_prbs_data *res;
} prbs_cmd_data;


/* Debugfs root directory for serdes */
static struct dentry *pserdes_root;


static int serdes_dbg_lane_parse(const char __user *buffer,
				 size_t count, int *qlm, int *lane)
{
	char *cmd_buf, *cmd_buf_tmp, *subtoken;
	int ec;

	cmd_buf = memdup_user(buffer, count);
	if (IS_ERR(cmd_buf))
		return -ENOMEM;

	cmd_buf[count] = '\0';

	cmd_buf_tmp = strchr(cmd_buf, '\n');
	if (cmd_buf_tmp) {
		*cmd_buf_tmp = '\0';
		count = cmd_buf_tmp - cmd_buf + 1;
	}

	cmd_buf_tmp = cmd_buf;
	subtoken = strsep(&cmd_buf, " ");
	ec = subtoken ? kstrtoint(subtoken, 10, qlm) : -EINVAL;

	if (ec < 0) {
		kfree(cmd_buf_tmp);
		return ec;
	}

	subtoken = strsep(&cmd_buf, " ");
	ec = subtoken ? kstrtoint(subtoken, 10, lane) : -EINVAL;

	kfree(cmd_buf_tmp);
	return ec;
}

static ssize_t serdes_dbg_eye_write_op(struct file *filp,
				       const char __user *buffer,
				       size_t count, loff_t *ppos)
{
	struct arm_smccc_res res;
	int ec;

	ec = serdes_dbg_lane_parse(buffer, count, &eye_cmd_data.qlm,
				   &eye_cmd_data.lane);
	if (ec < 0) {
		pr_info("Usage: echo <qlm> <lane> > eye\n");
		return ec;
	}

	do {
		arm_smccc_smc(OCTEONTX_SERDES_DBG_GET_EYE, eye_cmd_data.qlm,
			      eye_cmd_data.lane, 0, 0, 0, 0, 0, &res);
	} while (res.a0 == OCTEONTX_SMC_PENDING);
	if (res.a0 != SMCCC_RET_SUCCESS) {
		pr_info("CGX eye capture failed.\n");
		return -EIO;
	}

	return count;
}

static int serdes_dbg_eye_print_gsern(struct seq_file *s)
{
	struct eye_data *eye;
	int v, t, v_height;
	int errors_tr_ones, errors_nt_ones, errors_tr_zeros, errors_nt_zeros;

	eye = eye_cmd_data.res;

	seq_printf(s, "V  T  %-20s %-20s %-20s %-20s\n", "TRANS_ONE_ECNT",
		   "NON_TRANS_ONE_ECNT", "TRANS_ZEROS_ECNT",
		   "NON_TRANS_ZEROS_ECNT");

	v_height = (eye->height + 1) / 2;

	for (t = 0; t < eye->width; t++) {
		for (v = 0; v < v_height; v++) {
			errors_nt_ones = eye->data[v_height-v-1][t];
			errors_tr_ones = eye->data[v_height-v-1][t+64];
			errors_nt_zeros = eye->data[v_height+v-1][t];
			errors_tr_zeros = eye->data[v_height+v-1][t+64];

			seq_printf(s, "%02x %02x %020x %020x %020x %020x\n",
				   v, t, errors_tr_ones, errors_nt_ones,
				   errors_tr_zeros, errors_nt_zeros);
		}
	}

	return 0;
}

static int serdes_dbg_eye_print_gserx(struct seq_file *s)
{
	struct eye_data *eye;
	int x_min = 0;
	int x_step = 1;
	int y_min = -255;
	int y_step = 8;
	int x;
	int y;

	eye = eye_cmd_data.res;

	seq_printf(s, "%5s %5s %s\n", "V", "T", "Errors");

	for (x = 0; x < eye->width; x++) {
		for (y = 0; y < eye->height; y++) {
			seq_printf(s, "%5d %5d %u\n", y * y_step + y_min,
				   x * x_step + x_min, eye->data[y][x]);
		}
	}

	return 0;
}

/*
 * Square root by abacus algorithm, Martin Guy @ UKC, June 1985.
 * From a book on programming abaci by Mr C. Woo.
 */
static u64 isqrt(u64 num)
{
	u64 result = 0;
	/* The second-to-top bit is set: 1 << 62 for 64 bits */
	u64 bit = 1ull << 62;

	/* "bit" starts at the highest power of four <= the argument. */
	while (bit > num)
		bit >>= 2;

	while (bit != 0) {
		if (num >= result + bit) {
			num -= result + bit;
			result = (result >> 1) + bit;
		} else {
			result >>= 1;
		}
		bit >>= 2;
	}

	return result;
}

static u64 log_10(u64 num)
{
	u64 result = 0;

	while (num > 10) {
		num /= 10;
		result++;
	}
	if (num >= 5)
		result++;

	return result;
}

static int serdes_dbg_eye_read_op(struct seq_file *s, void *unused)
{
	struct eye_data *eye;
	u64 data;
	int ec, x, y, width, height, last_color, level, deltay, deltax, dy, dx;
	int dist, color;
	int eye_area = 0;
	int eye_width = 0;
	int eye_height = 0;
	char color_str[] = "\33[40m"; /* Note: This is modified, not constant */

	eye = eye_cmd_data.res;

	/* GSERN eye needs to be handled differently */
	if (eye->type == QLM_GSERN_TYPE) {
		ec = serdes_dbg_eye_print_gsern(s);
		if (ec)
			return ec;
		for (y = 0; y < eye->height; y++) {
			for (x = 0; x < eye->width; x++) {
				data = eye->data[y][x] + eye->data[y][x + 64];
				if (data > U32_MAX)
					data = U32_MAX;
				eye->data[y][x] = data;
			}
		}
	} else {
		ec = serdes_dbg_eye_print_gserx(s);
		if (ec)
			return ec;
	}

	/* Calculate the max eye width */
	for (y = 0; y < eye->height; y++) {
		width = 0;
		for (x = 0; x < eye->width; x++) {
			if (eye->data[y][x] == 0) {
				width++;
				eye_area++;
			}
		}
		if (width > eye_width)
			eye_width = width;
	}

	/* Calculate the max eye height */
	for (x = 0; x < eye->width; x++) {
		height = 0;
		for (y = 0; y < eye->height; y++) {
			if (eye->data[y][x] == 0) {
				height++;
				eye_area++;
			}
		}
		if (height > eye_height)
			eye_height = height;
	}

	seq_printf(s, "\nEye Diagram for QLM %d, Lane %d\n", eye_cmd_data.qlm,
		   eye_cmd_data.lane);

	last_color = -1;
	for (y = 0; y < eye->height; y++) {
		for (x = 0; x < eye->width; x++) {
			level = log_10(eye->data[y][x] + 1);
			if (level > 9)
				level = 9;
			#define DIFF(a, b) (((a) < (b)) ? (b)-(a) : (a)-(b))
			deltay = (y == (eye->height - 1)) ? -1 : 1;
			deltax = (x == (eye->width - 1)) ? -1 : 1;
			dy = DIFF(eye->data[y][x], eye->data[y + deltay][x]);
			dx = DIFF(eye->data[y][x], eye->data[y][x + deltax]);
			#undef DIFF
			dist = dx * dx + dy * dy;
			color = log_10(isqrt(dist) + 1);
			if (color > 6)
				color = 6;
			if (level == 0)
				color = 0;
			if (color != last_color) {
				color_str[3] = '0' + color;
				seq_printf(s, "%s", color_str);
				last_color = color;
			}
			seq_printf(s, "%c", '0' + level);
		}
		seq_puts(s, "\33[0m\n");
		last_color = -1;
	}
	seq_printf(s, "\nEye Width %d, Height %d, Area %d\n",
		   eye_width, eye_height, eye_area);

	return 0;
}

static int serdes_dbg_open_eye(struct inode *inode, struct file *file)
{
	return single_open(file, serdes_dbg_eye_read_op, inode->i_private);
}

static const struct file_operations serdes_dbg_eye_fops = {
	.owner		= THIS_MODULE,
	.open		= serdes_dbg_open_eye,
	.read		= seq_read,
	.write		= serdes_dbg_eye_write_op,
	.llseek		= seq_lseek,
	.release	= single_release,
};

static ssize_t serdes_dbg_settings_write_op(struct file *filp,
					    const char __user *buffer,
					    size_t count, loff_t *ppos)
{
	struct arm_smccc_res res;
	int ec;

	ec = serdes_dbg_lane_parse(buffer, count, &serdes_cmd_data.qlm,
				   &serdes_cmd_data.lane);
	if (ec < 0) {
		pr_info("Usage: echo <qlm> <lane> > serdes\n");
		return ec;
	}

	arm_smccc_smc(OCTEONTX_SERDES_DBG_GET_CONF, serdes_cmd_data.qlm,
		      serdes_cmd_data.lane, 0, 0, 0, 0, 0, &res);
	if (res.a0 != SMCCC_RET_SUCCESS) {
		pr_info("CGX serdes display command failed.\n");
		return -EIO;
	}

	return count;
}

static int serdes_dbg_settings_read_op(struct seq_file *s, void *unused)
{
	serdes_cmd_data.res[SERDES_SETTINGS_SIZE - 1] = '\0';

	seq_printf(s, "%s", serdes_cmd_data.res);

	return 0;
}

static int serdes_dbg_open_settings(struct inode *inode, struct file *file)
{
	return single_open(file, serdes_dbg_settings_read_op, inode->i_private);
}

static const struct file_operations serdes_dbg_settings_fops = {
	.owner		= THIS_MODULE,
	.open		= serdes_dbg_open_settings,
	.read		= seq_read,
	.write		= serdes_dbg_settings_write_op,
	.llseek		= seq_lseek,
	.release	= single_release,
};

static int tune_serdes_dbg_lane_parse(const char __user *buffer,
				 size_t count, int *qlm, int *lane,
				 int *swing, int *pre, int *post)
{
	char *cmd_buf, *cmd_buf_tmp, *subtoken;
	int ec;

	cmd_buf = memdup_user(buffer, count);
	if (IS_ERR(cmd_buf))
		return -ENOMEM;

	cmd_buf[count] = '\0';

	cmd_buf_tmp = strchr(cmd_buf, '\n');
	if (cmd_buf_tmp) {
		*cmd_buf_tmp = '\0';
		count = cmd_buf_tmp - cmd_buf + 1;
	}

	cmd_buf_tmp = cmd_buf;
	subtoken = strsep(&cmd_buf, " ");
	ec = subtoken ? kstrtoint(subtoken, 10, qlm) : -EINVAL;

	if (ec < 0) {
		kfree(cmd_buf_tmp);
		return ec;
	}

	subtoken = strsep(&cmd_buf, " ");
	ec = subtoken ? kstrtoint(subtoken, 10, lane) : -EINVAL;

	if (ec == -EINVAL) {
		kfree(cmd_buf_tmp);
		return ec;
	}

	subtoken = strsep(&cmd_buf, " ");
	ec = subtoken ? kstrtoint(subtoken, 10, swing) : -EINVAL;

	if (ec == -EINVAL) {
		kfree(cmd_buf_tmp);
		return ec;
	}

	subtoken = strsep(&cmd_buf, " ");
	ec = subtoken ? kstrtoint(subtoken, 10, pre) : -EINVAL;

	if (ec == -EINVAL) {
		kfree(cmd_buf_tmp);
		return ec;
	}

	subtoken = strsep(&cmd_buf, " ");
	ec = subtoken ? kstrtoint(subtoken, 10, post) : -EINVAL;

	kfree(cmd_buf_tmp);
	return ec;
}

static int tune_serdes_dbg_settings_read_op(struct seq_file *s, void *unused)
{
	tune_serdes_cmd.res = '\0';

	seq_printf(s, "%s", tune_serdes_cmd.res);

	return 0;
}

static ssize_t tune_serdes_dbg_settings_write_op(struct file *filp,
					    const char __user *buffer,
					    size_t count, loff_t *ppos)
{
	struct arm_smccc_res res;
	int ec;

	ec = tune_serdes_dbg_lane_parse(buffer, count, &tune_serdes_cmd.qlm,
			&tune_serdes_cmd.lane, &tune_serdes_cmd.swing,
			&tune_serdes_cmd.pre, &tune_serdes_cmd.post);
	if (ec < 0) {
		pr_info("Usage: echo <qlm> <lane> <swing> <pre> <post> > tunetx\n");
		return ec;
	}

	arm_smccc_smc(OCTEONTX_SERDES_DBG_SET_TUNE, tune_serdes_cmd.qlm,
		tune_serdes_cmd.lane, tune_serdes_cmd.swing,
		(tune_serdes_cmd.pre << 8) | (tune_serdes_cmd.post & 0xff),
		0, 0, 0, &res);

	if (res.a0 != SMCCC_RET_SUCCESS) {
		pr_info("QLM serdes TX settings command failed.\n");
		return -EIO;
	}

	return count;
}

static int tune_serdes_dbg_open_settings(struct inode *inode, struct file *file)
{
	return single_open(file, tune_serdes_dbg_settings_read_op,
			inode->i_private);
}

static const struct file_operations tune_serdes_dbg_settings_fops = {
	.owner		= THIS_MODULE,
	.open		= tune_serdes_dbg_open_settings,
	.read		= seq_read,
	.write		= tune_serdes_dbg_settings_write_op,
	.llseek		= seq_lseek,
	.release	= single_release,
};

static int loop_serdes_dbg_lane_parse(const char __user *buffer,
				 size_t count, int *qlm, int *lane,
				 int *type)
{
	char *cmd_buf, *cmd_buf_tmp, *subtoken;
	int ec;

	cmd_buf = memdup_user(buffer, count);
	if (IS_ERR(cmd_buf))
		return -ENOMEM;

	cmd_buf[count] = '\0';

	cmd_buf_tmp = strchr(cmd_buf, '\n');
	if (cmd_buf_tmp) {
		*cmd_buf_tmp = '\0';
		count = cmd_buf_tmp - cmd_buf + 1;
	}

	cmd_buf_tmp = cmd_buf;
	subtoken = strsep(&cmd_buf, " ");
	ec = subtoken ? kstrtoint(subtoken, 10, qlm) : -EINVAL;

	if (ec < 0) {
		kfree(cmd_buf_tmp);
		return ec;
	}

	subtoken = strsep(&cmd_buf, " ");
	ec = subtoken ? kstrtoint(subtoken, 10, lane) : -EINVAL;

	if (ec == -EINVAL) {
		kfree(cmd_buf_tmp);
		return ec;
	}

	subtoken = strsep(&cmd_buf, " ");
	ec = subtoken ? kstrtoint(subtoken, 10, type) : -EINVAL;

	kfree(cmd_buf_tmp);
	return ec;
}

static ssize_t loop_serdes_dbg_settings_write_op(struct file *filp,
					    const char __user *buffer,
					    size_t count, loff_t *ppos)
{
	struct arm_smccc_res res;
	int ec;

	ec = loop_serdes_dbg_lane_parse(buffer, count, &loop_serdes_cmd.qlm,
			&loop_serdes_cmd.lane, &loop_serdes_cmd.type);
	if (ec < 0) {
		pr_info("Usage: echo <qlm> <lane> <type> > loop\n");
		return ec;
	}

	arm_smccc_smc(OCTEONTX_SERDES_DBG_SET_LOOP, loop_serdes_cmd.qlm,
		loop_serdes_cmd.lane, loop_serdes_cmd.type,
		0, 0, 0, 0, &res);

	if (res.a0 != SMCCC_RET_SUCCESS) {
		pr_info("QLM serdes loop command failed.\n");
		return -EIO;
	}

	return count;
}

static int loop_serdes_dbg_settings_read_op(struct seq_file *s, void *unused)
{
	loop_serdes_cmd.res = '\0';

	seq_printf(s, "%s", loop_serdes_cmd.res);

	return 0;
}

static int loop_serdes_dbg_open_settings(struct inode *inode, struct file *file)
{
	return single_open(file, loop_serdes_dbg_settings_read_op,
			inode->i_private);
}

static const struct file_operations loop_serdes_dbg_settings_fops = {
	.owner		= THIS_MODULE,
	.open		= loop_serdes_dbg_open_settings,
	.read		= seq_read,
	.write		= loop_serdes_dbg_settings_write_op,
	.llseek		= seq_lseek,
	.release	= single_release,
};

static int serdes_dbg_prbs_lane_parse(const char __user *buffer,
				      size_t count, int *qlm,
				      enum cgx_prbs_cmd *cmd, int *mode,
				      int *qlm_lane, int *inject)
{
	char *cmd_buf, *cmd_buf_tmp, *subtoken;
	int ec;

	cmd_buf = memdup_user(buffer, count);
	if (IS_ERR(cmd_buf))
		return -ENOMEM;

	cmd_buf[count] = '\0';

	cmd_buf_tmp = strchr(cmd_buf, '\n');
	if (cmd_buf_tmp) {
		*cmd_buf_tmp = '\0';
		count = cmd_buf_tmp - cmd_buf + 1;
	}

	cmd_buf_tmp = cmd_buf;
	subtoken = strsep(&cmd_buf, " ");
	ec = subtoken ? kstrtoint(subtoken, 10, qlm) : -EINVAL;

	if (ec < 0) {
		kfree(cmd_buf_tmp);
		return ec;
	}

	subtoken = strsep(&cmd_buf, " ");
	ec = subtoken ? kstrtoint(subtoken, 10, qlm_lane) : -EINVAL;

	if (ec == -EINVAL || *qlm_lane < 0) {
		kfree(cmd_buf_tmp);
		return ec;
	}

	subtoken = strsep(&cmd_buf, " ");
	if (subtoken == NULL) {
		*cmd = CGX_PRBS_GET_DATA_CMD;
	} else {
		if (!strcmp(subtoken, "start")) {
			*cmd = CGX_PRBS_START_CMD;
			subtoken = strsep(&cmd_buf, " ");
			ec = subtoken ? kstrtoint(subtoken, 10, mode) :
					-EINVAL;
			if (ec == -EINVAL)
				goto out;
			subtoken = strsep(&cmd_buf, " ");
			if (subtoken) {
				ec = kstrtoint(subtoken, 10, inject);
				if (ec)
					goto out;
			} else {
				*inject = 0;
			}
		} else if (!strcmp(subtoken, "stop")) {
			*cmd = CGX_PRBS_STOP_CMD;
		} else if (!strcmp(subtoken, "clear")) {
			*cmd = CGX_PRBS_CLEAR_CMD;
		} else {
			ec = -EINVAL;
		}
	}

out:
	kfree(cmd_buf_tmp);
	return ec;
}

static ssize_t serdes_dbg_prbs_write_op(struct file *filp,
					const char __user *buffer,
					size_t count, loff_t *ppos)
{
	struct prbs_status *status = NULL;
	struct arm_smccc_res res;
	enum cgx_prbs_cmd cmd;
	int mode;
	int qlm;
	int ec;
	int qlm_lane;
	int inject;

	ec = serdes_dbg_prbs_lane_parse(buffer, count, &prbs_cmd_data.qlm,
					&cmd, &mode, &prbs_cmd_data.qlm_lane,
					&inject);
	if (ec < 0) {
		pr_info("Usage: echo <qlm> <lane> [{start <mode> [inject]|stop|clear}] > prbs\n");
		return ec;
	}

	qlm = prbs_cmd_data.qlm;
	qlm_lane = prbs_cmd_data.qlm_lane;

	switch (cmd) {
	case CGX_PRBS_START_CMD:
		arm_smccc_smc(OCTEONTX_SERDES_DBG_PRBS, cmd, qlm,
			      mode | (inject << 8),
			      qlm_lane, 0, 0, 0, &res);

		list_for_each_entry(status,
				    &prbs_cmd_data.status_list.list,
				    list) {
			if ((status->qlm == qlm) &&
					(status->qlm_lane == qlm_lane))
				break;
		}

		/*
		 * If status is head of the list, status for specific
		 * qlm doesn't exist
		 */
		if (&status->list == &prbs_cmd_data.status_list.list)
			status = NULL;

		if (res.a0 != SMCCC_RET_SUCCESS) {
			if (status != NULL) {
				list_del(&status->list);
				kfree(status);
			}
			pr_info("GSER prbs start command failed.\n");
			return -EIO;
		}

		if (status == NULL) {
			status = kmalloc(sizeof(struct prbs_status),
					 GFP_KERNEL);
			if (status == NULL)
				return -ENOMEM;
			status->qlm = qlm;
			status->qlm_lane = qlm_lane;
			list_add(&status->list,
				 &prbs_cmd_data.status_list.list);
		}
		status->start_time = ktime_get_seconds();
		pr_info("GSER PRBS-%d start on QLM %d on lane %d.\n", mode,
				qlm, qlm_lane);
		break;

	case CGX_PRBS_STOP_CMD:
		arm_smccc_smc(OCTEONTX_SERDES_DBG_PRBS, cmd,
			      qlm, 0, qlm_lane, 0, 0, 0, &res);
		if (res.a0 != SMCCC_RET_SUCCESS) {
			pr_info("GSER prbs stop command failed.\n");
			return -EIO;
		}
		list_for_each_entry(status,
				    &prbs_cmd_data.status_list.list,
				    list) {
			if ((status->qlm == qlm) &&
					(status->qlm_lane == qlm_lane)) {
				list_del(&status->list);
				kfree(status);
				break;
			}
		}
		pr_info("GSER PRBS stop on QLM %d on Lane %d.\n", qlm,
				qlm_lane);
		break;

	case CGX_PRBS_CLEAR_CMD:
		arm_smccc_smc(OCTEONTX_SERDES_DBG_PRBS, cmd,
			      qlm, 0, qlm_lane, 0, 0, 0, &res);
		if (res.a0 != SMCCC_RET_SUCCESS) {
			pr_info("GSER prbs clear command failed.\n");
			return -EIO;
		}
		pr_info("GSER PRBS errors cleared on QLM%d Lane%d\n", qlm,
				qlm_lane);
		break;

	default:
		pr_info("GSER PRBS set QLM %d Lane %d to read.\n", qlm,
				qlm_lane);
		break;
	}

	return count;
}

static int serdes_dbg_prbs_read_op(struct seq_file *s, void *unused)
{
	struct prbs_status *status = NULL;
	struct cgx_prbs_errors *errors;
	struct arm_smccc_res res;
	long time = -1;
	int lane;
	int qlm;

	qlm = prbs_cmd_data.qlm;
	lane = prbs_cmd_data.qlm_lane;

	list_for_each_entry(status,
			    &prbs_cmd_data.status_list.list,
			    list) {
		if (status->qlm == qlm) {
			time = status->start_time;
			break;
		}
	}

	if (time == -1) {
		seq_printf(s, "GSER PRBS not started for QLM%d.Lane%d.\n", qlm,
			lane);
		return 0;
	}

	time = ktime_get_seconds() - time;

	arm_smccc_smc(OCTEONTX_SERDES_DBG_PRBS, CGX_PRBS_GET_DATA_CMD,
		      qlm, 0, lane, 0, 0, 0, &res);

	if (res.a0 != SMCCC_RET_SUCCESS) {
		seq_printf(s, "GSER prbs get command failed for QLM%d.Lane%d.\n",
			qlm, lane);
		return 0;
	}

	errors = prbs_cmd_data.res->errors;

	seq_printf(s, "Time: %ld seconds QLM%d.Lane%d: errors: ", time, qlm,
			lane);
	if (errors[lane].err != -1)
		seq_printf(s, "%lld", errors[lane].err);
	else
		seq_puts(s, "No lock");

	if (errors[lane].phy_host != -2) {
		seq_puts(s, ", PHY Host errors: ");
		if (errors[lane].phy_host != -1)
			seq_printf(s, "%lld", errors[lane].phy_host);
		else
			seq_puts(s, "No lock");
	}

	if (errors[lane].phy_line != -2) {
		seq_puts(s, ", PHY Line errors: ");
		if (errors[lane].phy_line != -1)
			seq_printf(s, "%lld", errors[lane].phy_line);
		else
			seq_puts(s, "No lock");
	}
	seq_puts(s, "\n");

	return 0;
}

static int serdes_dbg_open_prbs(struct inode *inode, struct file *file)
{
	return single_open(file, serdes_dbg_prbs_read_op, inode->i_private);
}

static const struct file_operations serdes_dbg_prbs_fops = {
	.owner		= THIS_MODULE,
	.open		= serdes_dbg_open_prbs,
	.read		= seq_read,
	.write		= serdes_dbg_prbs_write_op,
	.llseek		= seq_lseek,
	.release	= single_release,
};

static int serdes_dbg_setup_debugfs(struct dentry *root)
{
	struct dentry *pfile;

	pfile = debugfs_create_file("eye", 0644, root, NULL,
				    &serdes_dbg_eye_fops);
	if (IS_ERR_OR_NULL(pfile))
		goto create_failed;

	pfile = debugfs_create_file("settings", 0644, root, NULL,
				    &serdes_dbg_settings_fops);
	if (IS_ERR_OR_NULL(pfile))
		goto create_failed;

	pfile = debugfs_create_file("prbs", 0644, root, NULL,
				    &serdes_dbg_prbs_fops);
	if (IS_ERR_OR_NULL(pfile))
		goto create_failed;

	pfile = debugfs_create_file("tunetx", 0644, root, NULL,
				    &tune_serdes_dbg_settings_fops);
	if (IS_ERR_OR_NULL(pfile))
		goto create_failed;

	pfile = debugfs_create_file("loop", 0644, root, NULL,
				    &loop_serdes_dbg_settings_fops);
	if (IS_ERR_OR_NULL(pfile))
		goto create_failed;

	return 0;

create_failed:
	pr_err("Failed to create debugfs dir/file for serdes\n");
	return IS_ERR(pfile) ? PTR_ERR(pfile) : -ENODEV;
}

static int __init serdes_dbg_init(void)
{
	struct arm_smccc_res res;
	int ret;

	/* Check the debugfs presence */
	pserdes_root = debugfs_create_dir("octeontx2_serdes", NULL);
	if (IS_ERR_OR_NULL(pserdes_root)) {
		if (IS_ERR(pserdes_root)) {
			int ret = PTR_ERR(pserdes_root);

			pr_err("Can't access debugfs, error (%d)\n", ret);
			return ret;
		}
		/* It should not happen that ERR != 0 && pserdes_root == NULL */
		pr_info("Can't create debugfs entry\n");
		return -ENODEV;
	}

	/*
	 * Compare response for standard SVC_UID commandi with OcteonTX UUID.
	 * Continue only if it is OcteonTX.
	 */
	if (octeontx_soc_check_smc() != 0) {
		pr_info("OcteonTX2 serdes diagnostics not support\n");
		ret = -EPERM;
		goto smc_access_failed;
	}

	arm_smccc_smc(OCTEONTX_SERDES_DBG_GET_MEM, 0, 0, 0, 0, 0, 0, 0, &res);
	if (res.a0 == SMCCC_RET_NOT_SUPPORTED) {
		pr_info("Firmware doesn't support serdes diagnostic cmds.\n");
		ret = -EPERM;
		goto smc_access_failed;
	}

	if (res.a0 != SMCCC_RET_SUCCESS)
		goto serdes_mem_init_failed;

	eye_cmd_data.res = ioremap_wc(res.a1, sizeof(struct eye_data));
	if (!eye_cmd_data.res)
		goto serdes_mem_init_failed;

	serdes_cmd_data.res = ioremap_wc(res.a2, SERDES_SETTINGS_SIZE);
	if (!serdes_cmd_data.res)
		goto serdes_mem_init_failed;

	prbs_cmd_data.res = ioremap_wc(res.a3, sizeof(struct cgx_prbs_data));
	if (!prbs_cmd_data.res)
		goto serdes_mem_init_failed;

	tune_serdes_cmd.res = ioremap_wc(res.a0, sizeof(tune_serdes_cmd));
	if (!tune_serdes_cmd.res)
		goto serdes_mem_init_failed;

	loop_serdes_cmd.res = ioremap_wc(res.a0, sizeof(loop_serdes_cmd));
	if (!loop_serdes_cmd.res)
		goto serdes_mem_init_failed;

	ret = serdes_dbg_setup_debugfs(pserdes_root);
	if (ret)
		goto serdes_debugfs_failed;

	INIT_LIST_HEAD(&prbs_cmd_data.status_list.list);

	return 0;

serdes_mem_init_failed:
	pr_err("Failed to obtain shared memory for serdes debug commands\n");
	ret = -EACCES;

serdes_debugfs_failed:
	if (eye_cmd_data.res)
		iounmap(eye_cmd_data.res);

	if (serdes_cmd_data.res)
		iounmap(serdes_cmd_data.res);

	if (prbs_cmd_data.res)
		iounmap(prbs_cmd_data.res);

	if (tune_serdes_cmd.res)
		iounmap(tune_serdes_cmd.res);

	if (loop_serdes_cmd.res)
		iounmap(loop_serdes_cmd.res);

smc_access_failed:
	debugfs_remove_recursive(pserdes_root);

	return ret;
}

static void __exit serdes_dbg_exit(void)
{
	struct prbs_status *status, *n;

	debugfs_remove_recursive(pserdes_root);

	if (eye_cmd_data.res)
		iounmap(eye_cmd_data.res);

	if (serdes_cmd_data.res)
		iounmap(serdes_cmd_data.res);

	if (prbs_cmd_data.res)
		iounmap(prbs_cmd_data.res);

	if (tune_serdes_cmd.res)
		iounmap(tune_serdes_cmd.res);

	list_for_each_entry_safe(status, n,
				 &prbs_cmd_data.status_list.list,
				 list) {
		kfree(status);
	}
}

module_init(serdes_dbg_init);
module_exit(serdes_dbg_exit);

MODULE_AUTHOR("Marvell International Ltd.");
MODULE_DESCRIPTION("Serdes diagnostic commands for OcteonTX2");
MODULE_LICENSE("GPL v2");

