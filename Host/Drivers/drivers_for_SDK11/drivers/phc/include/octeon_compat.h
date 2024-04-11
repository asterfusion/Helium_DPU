#include "linux/version.h"

#if defined(RHEL_RELEASE_CODE)
#if  (RHEL_RELEASE_CODE >= RHEL_RELEASE_VERSION(8,4))
#define HAS_2PARAM_ACCESS_OK
#define NO_HAS_MMIOWB
#define HAS_MULTI_TXQUEUE
#define HAS_SELECT_QUEUE_FALLBACK
#define NO_HAS_XMIT_MORE
#define HAS_SKB_FRAG_OFF
#endif
#endif
