/*
 * Copyright (c) 2021 Marvell.
 * SPDX-License-Identifier: Apache-2.0
 * https://spdx.org/licenses/Apache-2.0.html
 */

/**
 * @file
 * @brief ONP crypto interface.
 */

#ifndef included_onp_crypto_crypto_h
#define included_onp_crypto_crypto_h

#include <onp/drv/inc/crypto.h>
#include <vnet/crypto/crypto.h>

/* CRYPTO_ID, KEY_LENGTH_IN_BYTES, TAG_LEN, AAD_LEN */
#define foreach_onp_crypto_aead_async_alg                                     \
  _ (AES_128_GCM, 16, 16, 8)                                                  \
  _ (AES_128_GCM, 16, 16, 12)                                                 \
  _ (AES_192_GCM, 24, 16, 8)                                                  \
  _ (AES_192_GCM, 24, 16, 12)                                                 \
  _ (AES_256_GCM, 32, 16, 8)                                                  \
  _ (AES_256_GCM, 32, 16, 12)

/* CRYPTO_ID, INTEG_ID, KEY_LENGTH_IN_BYTES, DIGEST_LEN */
#define foreach_onp_crypto_link_async_alg                                     \
  _ (AES_128_CBC, SHA1, 16, 12)                                               \
  _ (AES_192_CBC, SHA1, 24, 12)                                               \
  _ (AES_256_CBC, SHA1, 32, 12)                                               \
  _ (AES_128_CBC, SHA256, 16, 16)                                             \
  _ (AES_192_CBC, SHA256, 24, 16)                                             \
  _ (AES_256_CBC, SHA256, 32, 16)                                             \
  _ (AES_128_CBC, SHA384, 16, 24)                                             \
  _ (AES_192_CBC, SHA384, 24, 24)                                             \
  _ (AES_256_CBC, SHA384, 32, 24)                                             \
  _ (AES_128_CBC, SHA512, 16, 32)                                             \
  _ (AES_192_CBC, SHA512, 24, 32)                                             \
  _ (AES_256_CBC, SHA512, 32, 32)

typedef struct
{
  vlib_pci_addr_t crypto_pci_addr;
  u32 n_crypto_hw_queues;
} onp_crypto_config_t;

typedef struct
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);
  i32 crypto_dev_id;
  i32 crypto_queues;
  vlib_pci_addr_t crypto_pci_addr;
} onp_crypto_t;

typedef struct
{
  onp_crypto_t *onp_cryptodevs;
} onp_crypto_main_t;

extern onp_crypto_main_t onp_crypto_main;

clib_error_t *onp_crypto_setup (vlib_main_t *vm);

#endif /* included_onp_crypto_crypto_h */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
