/*
---------------------------------------------------------------------------
Copyright (c) 1998-2013, Brian Gladman, Worcester, UK. All rights reserved.

The redistribution and use of this software (with or without changes)
is allowed without the payment of fees or royalties provided that:

  source code distributions include the above copyright notice, this
  list of conditions and the following disclaimer;

  binary distributions include the above copyright notice, this list
  of conditions and the following disclaimer in their documentation.

This software is provided 'as is' with no explicit or implied warranties
in respect of its operation, including, but not limited to, correctness
and fitness for purpose.
---------------------------------------------------------------------------
Issue Date: 1/7/2020
*/

#ifndef AES_ARM64_H
#define AES_ARM64_H

#define USE_AES_CONTEXT

#include "aesopt.h"

#if defined( USE_ARM64_CRYPTO_IF_PRESENT )

/* map names in C code to make them internal ('name' -> 'aes_name_i') */
#define aes_xi(x) aes_ ## x ## _i

/* map names here to provide the external API ('name' -> 'aes_name') */
#define aes_arm64(x) aes_ ## x

AES_RETURN aes_arm64(encrypt_key128)(const unsigned char *key, aes_encrypt_ctx cx[1]);
AES_RETURN aes_arm64(encrypt_key192)(const unsigned char *key, aes_encrypt_ctx cx[1]);
AES_RETURN aes_arm64(encrypt_key256)(const unsigned char *key, aes_encrypt_ctx cx[1]);

AES_RETURN aes_arm64(decrypt_key128)(const unsigned char *key, aes_decrypt_ctx cx[1]);
AES_RETURN aes_arm64(decrypt_key192)(const unsigned char *key, aes_decrypt_ctx cx[1]);
AES_RETURN aes_arm64(decrypt_key256)(const unsigned char *key, aes_decrypt_ctx cx[1]);

AES_RETURN aes_arm64(encrypt)(const unsigned char *in, unsigned char *out, const aes_encrypt_ctx cx[1]);
AES_RETURN aes_arm64(decrypt)(const unsigned char *in, unsigned char *out, const aes_decrypt_ctx cx[1]);

AES_RETURN aes_xi(encrypt_key128)(const unsigned char *key, aes_encrypt_ctx cx[1]);
AES_RETURN aes_xi(encrypt_key192)(const unsigned char *key, aes_encrypt_ctx cx[1]);
AES_RETURN aes_xi(encrypt_key256)(const unsigned char *key, aes_encrypt_ctx cx[1]);

AES_RETURN aes_xi(decrypt_key128)(const unsigned char *key, aes_decrypt_ctx cx[1]);
AES_RETURN aes_xi(decrypt_key192)(const unsigned char *key, aes_decrypt_ctx cx[1]);
AES_RETURN aes_xi(decrypt_key256)(const unsigned char *key, aes_decrypt_ctx cx[1]);

AES_RETURN aes_xi(encrypt)(const unsigned char *in, unsigned char *out, const aes_encrypt_ctx cx[1]);
AES_RETURN aes_xi(decrypt)(const unsigned char *in, unsigned char *out, const aes_decrypt_ctx cx[1]);

#endif

#endif
