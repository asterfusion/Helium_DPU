/* SPDX-License-Identifier: Apache-2.0 */

#ifndef __LCP_POLICER_H__
#define __LCP_POLICER_H__

#include <vlib/vlib.h>

u8 lcp_policer_police (vlib_main_t *vm, vlib_buffer_t *b,
		       u32 policer_index);

#endif /* __LCP_POLICER_H__ */
