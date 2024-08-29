/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2022 Marvell.
 */

/**
 * @file rte_pmd_cnxk.h
 * CNXK PMD specific functions.
 *
 **/

#ifndef _PMD_CNXK_H_
#define _PMD_CNXK_H_

#include <rte_compat.h>
#include <rte_ethdev.h>
#include <rte_ether.h>
#include <rte_security.h>

/** Algorithm type to be used with security action to
 * calculate SA_index
 */
enum rte_pmd_cnxk_sec_action_alg {
	/** No swizzling of SPI bits into SA index.
	 * SA_index is from SA_XOR if enabled.
	 */
	RTE_PMD_CNXK_SEC_ACTION_ALG0,
	/** SPI<31:28> has 4 upper bits which segment the sequence number space.
	 * Initial SA_index is from SA_XOR if enabled.
	 * SA_alg = { 4'b0, SA_mcam[27:0] + SPI[31:28]}
	 */
	RTE_PMD_CNXK_SEC_ACTION_ALG1,
	/** SPI<27:25> segment the sequence number space.
	 *  Initial SA_index is from SA_XOR if enabled.
	 *  SA_alg = { 7'b0, SA_mcam[24:0] + SPI[27:25]}
	 */
	RTE_PMD_CNXK_SEC_ACTION_ALG2,
	/** SPI<28:25> segment the sequence number space.
	 * Initial SA_index is from SA_XOR if enabled.
	 * SA_alg = { 7'b0, SA_mcam[24:0] + SPI[28:25]}
	 */
	RTE_PMD_CNXK_SEC_ACTION_ALG3,
	/** The inbound SPI maybe "random", therefore we want the MCAM to be
	 * capable of remapping the SPI to an arbitrary SA_index.
	 * SPI to SA is done using a lookup in NIX/NPC cam entry with key as
	 * SPI, MATCH_ID, LFID.
	 */
	RTE_PMD_CNXK_SEC_ACTION_ALG4,
};

struct rte_pmd_cnxk_sec_action {
	/** Used as lookup result for ALG3 */
	uint32_t sa_index;
	/** When true XOR initial SA_INDEX with SA_HI/SA_LO to get SA_MCAM */
	bool sa_xor;
	/** SA_hi and SA_lo values for xor */
	uint16_t sa_hi, sa_lo;
	/** Determines alg to be applied post SA_MCAM computation with/without
	 * XOR.
	 */
	enum rte_pmd_cnxk_sec_action_alg alg;
};

#define RTE_PMD_CNXK_CTX_MAX_CKEY_LEN	   32
#define RTE_PMD_CNXK_CTX_MAX_OPAD_IPAD_LEN 128

/** Anti reply window size supported */
#define RTE_PMD_CNXK_AR_WIN_SIZE_MIN	    64
#define RTE_PMD_CNXK_AR_WIN_SIZE_MAX	    4096
#define RTE_PMD_CNXK_LOG_MIN_AR_WIN_SIZE_M1 5

/** u64 array size to fit anti replay window bits */
#define RTE_PMD_CNXK_AR_WINBITS_SZ (RTE_ALIGN_CEIL(RTE_PMD_CNXK_AR_WIN_SIZE_MAX, 64) / 64)

/** Outer header info for Inbound or Outbound */
union rte_pmd_cnxk_ipsec_outer_ip_hdr {
	struct {
		/** IPv4 destination */
		uint32_t dst_addr;
		/** IPv4 source */
		uint32_t src_addr;
	} ipv4;
	struct {
		/** IPv6 source */
		uint8_t src_addr[16];
		/** IPv6 destination */
		uint8_t dst_addr[16];
	} ipv6;
};

/** Inbound IPsec context update region */
struct rte_pmd_cnxk_ipsec_inb_ctx_update_reg {
	/** Highest sequence number received */
	uint64_t ar_base;
	/** Valid bit for 64-bit words of replay window */
	uint64_t ar_valid_mask;
	/** Hard life for SA */
	uint64_t hard_life;
	/** Soft life for SA */
	uint64_t soft_life;
	/** MIB octets */
	uint64_t mib_octs;
	/** MIB packets */
	uint64_t mib_pkts;
	/** AR window bits */
	uint64_t ar_winbits[RTE_PMD_CNXK_AR_WINBITS_SZ];
};

/** Outbound IPsec IV data */
union rte_pmd_cnxk_ipsec_outb_iv {
	uint64_t u64[2];
	/** IV debug - 16B*/
	uint8_t iv_dbg[16];
	struct {
		/** IV debug - 8B */
		uint8_t iv_dbg1[4];
		/** Salt */
		uint8_t salt[4];

		uint32_t rsvd;
		/** IV debug - 8B */
		uint8_t iv_dbg2[4];
	} s;
};

/** Outbound IPsec context update region */
struct rte_pmd_cnxk_ipsec_outb_ctx_update_reg {
	union {
		struct {
			uint64_t reserved_0_2 : 3;
			uint64_t address : 57;
			uint64_t mode : 4;
		} s;
		uint64_t u64;
	} err_ctl;

	uint64_t esn_val;
	uint64_t hard_life;
	uint64_t soft_life;
	uint64_t mib_octs;
	uint64_t mib_pkts;
};

/**
 * Inbound IPsec SA
 */
struct rte_pmd_cnxk_ipsec_inb_sa {
	/** Word0 */
	union {
		struct {
			/** AR window size */
			uint64_t ar_win : 3;
			/** Hard life enable */
			uint64_t hard_life_dec : 1;
			/** Soft life enable */
			uint64_t soft_life_dec : 1;

			/** Count global octets */
			uint64_t count_glb_octets : 1;
			/** Count global pkts */
			uint64_t count_glb_pkts : 1;
			/** Count bytes */
			uint64_t count_mib_bytes : 1;

			/** Count pkts */
			uint64_t count_mib_pkts : 1;
			/** HW context offset */
			uint64_t hw_ctx_off : 7;

			/** Context ID */
			uint64_t ctx_id : 16;

			/** Original packet free absolute */
			uint64_t orig_pkt_fabs : 1;
			/** Original packet free */
			uint64_t orig_pkt_free : 1;
			/** PKIND for second pass */
			uint64_t pkind : 6;

			uint64_t rsvd0 : 1;
			/** Ether type overwrite */
			uint64_t et_ovrwr : 1;
			/** Packet output type */
			uint64_t pkt_output : 2;
			/** Packet format type */
			uint64_t pkt_format : 1;
			/** Defrag option */
			uint64_t defrag_opt : 2;
			/** Reserved for X2P dest */
			uint64_t x2p_dst : 1;

			/** Context push size */
			uint64_t ctx_push_size : 7;
			uint64_t rsvd1 : 1;

			/** Context header size */
			uint64_t ctx_hdr_size : 2;
			/** AOP enable */
			uint64_t aop_valid : 1;
			uint64_t rsvd2 : 1;
			/** Context size */
			uint64_t ctx_size : 4;
		} s;
		uint64_t u64;
	} w0;

	/** Word1 */
	union {
		struct {
			/** Original packet aura */
			uint64_t orig_pkt_aura : 20;
			uint64_t rsvd3 : 4;
			/** Original packet free offset */
			uint64_t orig_pkt_foff : 8;
			/** SA cookie */
			uint64_t cookie : 32;
		} s;
		uint64_t u64;
	} w1;

	/** Word 2 */
	union {
		struct {
			/** SA valid */
			uint64_t valid : 1;
			/** SA direction */
			uint64_t dir : 1;
			uint64_t rsvd11 : 1;
			uint64_t rsvd4 : 1;
			/** IPsec mode */
			uint64_t ipsec_mode : 1;
			/** IPsec protocol */
			uint64_t ipsec_protocol : 1;
			/** AES key length */
			uint64_t aes_key_len : 2;

			/** Encryption algo */
			uint64_t enc_type : 3;
			/** Soft life and hard life unit */
			uint64_t life_unit : 1;
			/** Authentication algo */
			uint64_t auth_type : 4;

			/** Encapsulation type */
			uint64_t encap_type : 2;
			/** Ether type override enable */
			uint64_t et_ovrwr_ddr_en : 1;
			/** ESN enable */
			uint64_t esn_en : 1;
			/** Transport mode L4 checksum incrementally update */
			uint64_t tport_l4_incr_csum : 1;
			/** Outer IP header verification */
			uint64_t ip_hdr_verify : 2;
			/** UDP enacapsulation ports verification */
			uint64_t udp_ports_verify : 1;

			/** Return 64B of L2/L3 header on error */
			uint64_t l3hdr_on_err : 1;
			uint64_t rsvd6 : 6;
			uint64_t rsvd12 : 1;

			/** SPI */
			uint64_t spi : 32;
		} s;
		uint64_t u64;
	} w2;

	/** Word3 */
	uint64_t rsvd7;

	/** Word4 - Word7 */
	uint8_t cipher_key[RTE_PMD_CNXK_CTX_MAX_CKEY_LEN];

	/** Word8 - Word9 */
	union {
		struct {
			uint32_t rsvd8;
			/** IV salt */
			uint8_t salt[4];
		} s;
		uint64_t u64;
	} w8;
	uint64_t rsvd9;

	/** Word10 */
	union {
		struct {
			uint64_t rsvd10 : 32;
			/** UDP encapsulation source port */
			uint64_t udp_src_port : 16;
			/** UDP encapsulation destination port */
			uint64_t udp_dst_port : 16;
		} s;
		uint64_t u64;
	} w10;

	/** Word11 - Word14 */
	union rte_pmd_cnxk_ipsec_outer_ip_hdr outer_hdr;

	/** Word15 - Word30 */
	uint8_t hmac_opad_ipad[RTE_PMD_CNXK_CTX_MAX_OPAD_IPAD_LEN];

	/** Word31 - Word100 */
	struct rte_pmd_cnxk_ipsec_inb_ctx_update_reg ctx;
};

/**
 * Outbound IPsec SA
 */
struct rte_pmd_cnxk_ipsec_outb_sa {
	/** Word0 */
	union {
		struct {
			/** ESN enable */
			uint64_t esn_en : 1;
			/** IP ID generation type */
			uint64_t ip_id : 1;
			uint64_t rsvd0 : 1;
			/** Hard life enable */
			uint64_t hard_life_dec : 1;
			/** Soft life enable */
			uint64_t soft_life_dec : 1;

			/** Count global octets */
			uint64_t count_glb_octets : 1;
			/** Count global pkts */
			uint64_t count_glb_pkts : 1;
			/** Count bytes */
			uint64_t count_mib_bytes : 1;

			/** Count pkts */
			uint64_t count_mib_pkts : 1;
			/** HW context offset */
			uint64_t hw_ctx_off : 7;

			/** Context ID */
			uint64_t ctx_id : 16;
			uint64_t rsvd1 : 16;

			/** Context push size */
			uint64_t ctx_push_size : 7;
			uint64_t rsvd2 : 1;

			/** Context header size */
			uint64_t ctx_hdr_size : 2;
			/** AOP enable */
			uint64_t aop_valid : 1;
			uint64_t rsvd3 : 1;
			/** Context size */
			uint64_t ctx_size : 4;
		} s;
		uint64_t u64;
	} w0;

	/** Word1 */
	union {
		struct {
			uint64_t rsvd4 : 32;
			/** SA cookie */
			uint64_t cookie : 32;
		} s;
		uint64_t u64;
	} w1;

	/** Word 2 */
	union {
		struct {
			/** SA valid */
			uint64_t valid : 1;
			/** SA direction */
			uint64_t dir : 1;
			uint64_t rsvd11 : 1;
			uint64_t rsvd5 : 1;
			/** IPsec mode */
			uint64_t ipsec_mode : 1;
			/** IPsec protocol */
			uint64_t ipsec_protocol : 1;

			/** AES key length */
			uint64_t aes_key_len : 2;

			/** Encryption algo */
			uint64_t enc_type : 3;
			/** Soft life and hard life unit */
			uint64_t life_unit : 1;
			/** Authentication algo */
			uint64_t auth_type : 4;

			/** Encapsulation type */
			uint64_t encap_type : 2;
			/** DF source */
			uint64_t ipv4_df_src_or_ipv6_flw_lbl_src : 1;
			/** DSCP source */
			uint64_t dscp_src : 1;
			/** IV source */
			uint64_t iv_src : 2;
			/** IPID value in outer header */
			uint64_t ipid_gen : 1;
			uint64_t rsvd6 : 1;

			uint64_t rsvd7 : 7;
			uint64_t rsvd12 : 1;

			/** SPI */
			uint64_t spi : 32;
		} s;
		uint64_t u64;
	} w2;

	/** Word3 */
	uint64_t rsvd8;

	/** Word4 - Word7 */
	uint8_t cipher_key[RTE_PMD_CNXK_CTX_MAX_CKEY_LEN];

	/** Word8 - Word9 */
	union rte_pmd_cnxk_ipsec_outb_iv iv;

	/** Word10 */
	union {
		struct {
			uint64_t rsvd9 : 4;
			/** Outer header IPv4 DF or IPv6 flow label */
			uint64_t ipv4_df_or_ipv6_flw_lbl : 20;

			/** DSCP for outer header */
			uint64_t dscp : 6;
			uint64_t rsvd10 : 2;

			/** UDP encapsulation destination port */
			uint64_t udp_dst_port : 16;

			/** UDP encapsulation source port */
			uint64_t udp_src_port : 16;
		} s;
		uint64_t u64;
	} w10;

	/** Word11 - Word14 */
	union rte_pmd_cnxk_ipsec_outer_ip_hdr outer_hdr;

	/** Word15 - Word30 */
	uint8_t hmac_opad_ipad[RTE_PMD_CNXK_CTX_MAX_OPAD_IPAD_LEN];

	/** Word31 - Word36 */
	struct rte_pmd_cnxk_ipsec_outb_ctx_update_reg ctx;
};

/** Inbound/Outbound IPsec SA */
union rte_pmd_cnxk_ipsec_hw_sa {
	/** Inbound SA */
	struct rte_pmd_cnxk_ipsec_inb_sa inb;
	/** Outbound SA */
	struct rte_pmd_cnxk_ipsec_outb_sa outb;
};

/**
 * Read HW SA context from session.
 *
 * @param device
 *   Port identifier of Ethernet device.
 * @param sess
 *   Handle of the security session.
 * @param[out] data
 *   Destination pointer to copy SA context for application.
 * @param len
 *   Length of SA context to copy into data parameter.
 *
 * @return
 *   0 on success, a negative errno value otherwise.
 */
__rte_experimental
int rte_pmd_cnxk_hw_sa_read(void *device, struct rte_security_session *sess,
			    union rte_pmd_cnxk_ipsec_hw_sa *data, uint32_t len);
/**
 * Write HW SA context to session.
 *
 * @param device
 *   Port identifier of Ethernet device.
 * @param sess
 *   Handle of the security session.
 * @param[in] data
 *   Source data pointer from application to copy SA context into session.
 * @param len
 *   Length of SA context to copy from data parameter.
 *
 * @return
 *   0 on success, a negative errno value otherwise.
 */
__rte_experimental
int rte_pmd_cnxk_hw_sa_write(void *device, struct rte_security_session *sess,
			     union rte_pmd_cnxk_ipsec_hw_sa *data, uint32_t len);

/**
 * Get pointer to CPT result info for inline inbound processed pkt.
 *
 * It is recommended to use this API only when mbuf indicates packet
 * was processed with inline IPsec and there was a failure with the same i.e
 * mbuf->ol_flags indicates (RTE_MBUF_F_RX_SEC_OFFLOAD | RTE_MBUF_F_RX_SEC_OFFLOAD_FAILED).
 *
 * @param mbuf
 *   Pointer to packet that was just received and was processed with Inline IPsec.
 *
 * @return
 *   - Pointer to mbuf location where CPT result info is stored on success.
 *   - NULL on failure.
 */
__rte_experimental
void *rte_pmd_cnxk_inl_ipsec_res(struct rte_mbuf *mbuf);
#endif /* _PMD_CNXK_H_ */
