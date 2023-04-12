/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2018-2019 Hisilicon Limited.
 */

#ifndef _HNS3_INTR_H_
#define _HNS3_INTR_H_

#define HNS3_PPP_MPF_ECC_ERR_INT0_EN		0xFFFFFFFF
#define HNS3_PPP_MPF_ECC_ERR_INT0_EN_MASK	0xFFFFFFFF
#define HNS3_PPP_MPF_ECC_ERR_INT1_EN		0xFFFFFFFF
#define HNS3_PPP_MPF_ECC_ERR_INT1_EN_MASK	0xFFFFFFFF
#define HNS3_PPP_PF_ERR_INT_EN			0x0003
#define HNS3_PPP_PF_ERR_INT_EN_MASK		0x0003
#define HNS3_PPP_MPF_ECC_ERR_INT2_EN		0x003F
#define HNS3_PPP_MPF_ECC_ERR_INT2_EN_MASK	0x003F
#define HNS3_PPP_MPF_ECC_ERR_INT3_EN		0x003F
#define HNS3_PPP_MPF_ECC_ERR_INT3_EN_MASK	0x003F

#define HNS3_MAC_COMMON_ERR_INT_EN		0x107FF
#define HNS3_MAC_COMMON_ERR_INT_EN_MASK		0x107FF

#define HNS3_PPU_MPF_ABNORMAL_INT0_EN		GENMASK(31, 0)
#define HNS3_PPU_MPF_ABNORMAL_INT0_EN_MASK	GENMASK(31, 0)
#define HNS3_PPU_MPF_ABNORMAL_INT1_EN		GENMASK(31, 0)
#define HNS3_PPU_MPF_ABNORMAL_INT1_EN_MASK	GENMASK(31, 0)
#define HNS3_PPU_MPF_ABNORMAL_INT2_EN		0x3FFF3FFF
#define HNS3_PPU_MPF_ABNORMAL_INT2_EN_MASK	0x3FFF3FFF
#define HNS3_PPU_MPF_ABNORMAL_INT2_EN2		0xB
#define HNS3_PPU_MPF_ABNORMAL_INT2_EN2_MASK	0xB
#define HNS3_PPU_MPF_ABNORMAL_INT3_EN		GENMASK(7, 0)
#define HNS3_PPU_MPF_ABNORMAL_INT3_EN_MASK	GENMASK(23, 16)
#define HNS3_PPU_PF_ABNORMAL_INT_EN		GENMASK(5, 0)
#define HNS3_PPU_PF_ABNORMAL_INT_EN_MASK	GENMASK(5, 0)
#define HNS3_PPU_PF_INT_MSIX_MASK		0x27
#define HNS3_PPU_MPF_INT_ST2_MSIX_MASK		GENMASK(29, 28)

#define HNS3_SSU_1BIT_ECC_ERR_INT_EN		GENMASK(31, 0)
#define HNS3_SSU_1BIT_ECC_ERR_INT_EN_MASK	GENMASK(31, 0)
#define HNS3_SSU_MULTI_BIT_ECC_ERR_INT_EN	GENMASK(31, 0)
#define HNS3_SSU_MULTI_BIT_ECC_ERR_INT_EN_MASK	GENMASK(31, 0)
#define HNS3_SSU_BIT32_ECC_ERR_INT_EN		0x0101
#define HNS3_SSU_BIT32_ECC_ERR_INT_EN_MASK	0x0101
#define HNS3_SSU_COMMON_INT_EN			GENMASK(9, 0)
#define HNS3_SSU_COMMON_INT_EN_MASK		GENMASK(9, 0)
#define HNS3_SSU_PORT_BASED_ERR_INT_EN		0x0BFF
#define HNS3_SSU_PORT_BASED_ERR_INT_EN_MASK	0x0BFF0000
#define HNS3_SSU_FIFO_OVERFLOW_ERR_INT_EN	GENMASK(23, 0)
#define HNS3_SSU_FIFO_OVERFLOW_ERR_INT_EN_MASK	GENMASK(23, 0)
#define HNS3_SSU_COMMON_ERR_INT_MASK		GENMASK(9, 0)
#define HNS3_SSU_PORT_INT_MSIX_MASK		0x7BFF

#define HNS3_RESET_PROCESS_MS			200

struct hns3_hw_blk {
	const char *name;
	int (*enable_err_intr)(struct hns3_adapter *hns, bool en);
};

struct hns3_hw_error {
	uint32_t int_msk;
	const char *msg;
	enum hns3_reset_level reset_level;
};

int hns3_enable_hw_error_intr(struct hns3_adapter *hns, bool state);
void hns3_handle_msix_error(struct hns3_adapter *hns, uint64_t *levels);
void hns3_intr_unregister(const struct rte_intr_handle *hdl,
			  rte_intr_callback_fn cb_fn, void *cb_arg);
void hns3_notify_reset_ready(struct hns3_hw *hw, bool enable);
int hns3_reset_init(struct hns3_hw *hw);
void hns3_wait_callback(void *param);
void hns3_schedule_reset(struct hns3_adapter *hns);
void hns3_schedule_delayed_reset(struct hns3_adapter *hns);
int hns3_reset_req_hw_reset(struct hns3_adapter *hns);
int hns3_reset_process(struct hns3_adapter *hns,
		       enum hns3_reset_level reset_level);
void hns3_reset_abort(struct hns3_adapter *hns);

#endif /* _HNS3_INTR_H_ */
