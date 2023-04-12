/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2017 Marvell International Ltd.
 * Copyright(c) 2017 Semihalf.
 * All rights reserved.
 */

#ifndef __MV_ERRNO_H__
#define __MV_ERRNO_H__

#include <errno.h>

#ifndef ENOMEM
#define ENOMEM 12
#endif /* ENOMEM */

#ifndef EBUSY
#define	EBUSY 16	/* Device or resource busy */
#endif /* EBUSY */


#ifndef ENODEV
#define ENODEV 19
#endif /* ENODEV */

#ifndef EINVAL
#define EINVAL 22
#endif /* EINVAL */

#ifndef ENOMSG
#define ENOMSG 42
#endif /* ENOMSG */

#ifndef ENODATA
#define ENODATA 61
#endif /* ENODATA */

#ifndef EOVERFLOW
#define EOVERFLOW 75
#endif /* EOVERFLOW */

#ifndef EOPNOTSUPP
#define EOPNOTSUPP 95
#endif /* EOPNOTSUPP */

#ifndef ENOBUFS
#define ENOBUFS 105
#endif /* ENOBUFS */

#ifndef ETIMEDOUT
#define ETIMEDOUT 110
#endif /* ETIMEDOUT */

#endif /* __MV_ERRNO_H__ */
