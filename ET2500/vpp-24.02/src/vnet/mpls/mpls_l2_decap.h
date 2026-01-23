#ifndef __MPLS_L2_DECAP_H__
#define __MPLS_L2_DECAP_H__

#include <vppinfra/bihash_8_8.h>


typedef struct mpls_l2_decap_main_t_
{
    clib_bihash_8_8_t table;
} mpls_l2_decap_main_t;


extern mpls_l2_decap_main_t mpls_l2_decap_main;

#endif /* __MPLS_L2_DECAP_H__ */
