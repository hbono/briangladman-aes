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
*/

#include "aes_arm64.h"

#if defined( USE_ARM64_CRYPTO_IF_PRESENT )

#include <assert.h>

#if defined( _MSC_VER )

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <intrin.h>
#define INLINE __inline

#elif defined( __ANDROID__ )

#include <arm_neon.h>
#include <cpu-features.h>
#define INLINE static __inline

#elif defined( __linux__ )

#include <arm_neon.h>
#include <sys/auxv.h>
#define INLINE static __inline

#endif

INLINE int has_feature_aes()
{
#if defined( _MSC_VER )
    static int feature_aes = -1;
    if(feature_aes < 0)
    {
        feature_aes = IsProcessorFeaturePresent(PF_ARM_V8_CRYPTO_INSTRUCTIONS_AVAILABLE);
    }
    return feature_aes;
#elif defined( __ANDROID__ )
    static int feature_aes = -1;
    if(feature_aes < 0)
    {
        int cpu_features = (int)android_getCpuFeatures();
#if __aarch64__
        feature_aes = cpu_features & ANDROID_CPU_ARM64_FEATURE_AES;
#elif __arm__
        feature_aes = cpu_features & ANDROID_CPU_ARM_FEATURE_AES;
#endif
    }
    return feature_aes;
#elif defined( __IPHONE_OS_VERSION_MIN_REQUIRED )
    // All 64-bit Apple CPUs support the ARMv8 cryptography extension.
    return 1;
#elif defined( __linux__ )
    static int feature_aes = -1;
    if(feature_aes < 0)
    {
        // See <uapi/asm/hwcap.h>.
        enum {
            HWCAP_FP    = (1 << 0),
            HWCAP_ASIMD = (1 << 1),
            HWCAP_AES   = (1 << 3),
            HWCAP_PMULL = (1 << 4),
            HWCAP_SHA1  = (1 << 5),
            HWCAP_SHA2  = (1 << 6),
            HWCAP_CRC32 = (1 << 7),
        };
        int hwcaps = (int)getauxval(AT_HWCAP);
        feature_aes = hwcaps & HWCAP_AES;
    }
    return feature_aes;
#else
    return 0;
#endif
}

INLINE uint8x16_t aes_keygenassist(uint8x16_t t1, const uint32x4_t round_constant)
{
    // This function emulates the `AESKEYGENASSIST` instruction of AESNI.
    // (See https://blog.michaelbrase.com/2018/05/08/emulating-x86-aes-intrinsics-on-armv8-a/)
    ALIGNED_(16) static const uint8_t kUndoShiftRows[16] = {
        0x04, 0x01, 0x0E, 0x0B,  // SubBytes(T1)
        0x01, 0x0E, 0x0B, 0x04,  // ROT(SubBytes(T1))
        0x0C, 0x09, 0x06, 0x03,  // SubBytes(T3)
        0x09, 0x06, 0x03, 0x0C,  // ROT(SubBytes(T3))
    };
    t1 = vaeseq_u8(t1, vdupq_n_u8(0));
    t1 = vqtbl1q_u8(t1, vld1q_u8(kUndoShiftRows));
    return veorq_u8(t1, vreinterpretq_u8_u32(round_constant));
}

INLINE uint8x16_t aes_128_assist(uint8x16_t t1, const uint32x4_t round_constant)
{
    uint8x16_t t2;
    uint8x16_t t3;
    t2 = aes_keygenassist(t1, round_constant);
    t2 = vreinterpretq_u8_u32(vdupq_n_u32(vgetq_lane_u32(vreinterpretq_u32_u8(t2), 3)));
    t3 = vextq_u8(vdupq_n_u8(0), t1, 16 - 4);
    t1 = veorq_u8(t1, t3);
    t3 = vextq_u8(vdupq_n_u8(0), t3, 16 - 4);
    t1 = veorq_u8(t1, t3);
    t3 = vextq_u8(vdupq_n_u8(0), t3, 16 - 4);
    t1 = veorq_u8(t1, t3);
    t1 = veorq_u8(t1, t2);
    return t1;
}

AES_RETURN aes_arm64(encrypt_key128)(const unsigned char *key, aes_encrypt_ctx cx[1])
{
    uint8x16_t t1;
    uint32x4_t round_constant;
    uint8_t* ks = (uint8_t*)&cx->ks[0];
    ALIGNED_(16) static const uint32_t kRoundConstant1[4] = { 0, 0x01, 0, 0x01 };
    ALIGNED_(16) static const uint32_t kRoundConstant2[4] = { 0, 0x1B, 0, 0x1B };

    if(!has_feature_aes())
    {
        return aes_xi(encrypt_key128)(key, cx);
    }
    assert(ALIGN_OFFSET(cx, 16) == 0);

    t1 = vld1q_u8(key);
    vst1q_u8(&ks[0 * 16], t1);

    round_constant = vld1q_u32(kRoundConstant1);      // { 0, 0x01, 0, 0x01 }
    t1 = aes_128_assist(t1, round_constant);
    vst1q_u8(&ks[1 * 16], t1);

    round_constant = vshlq_n_u32(round_constant, 1);  // { 0, 0x02, 0, 0x02 }
    t1 = aes_128_assist(t1, round_constant);
    vst1q_u8(&ks[2 * 16], t1);

    round_constant = vshlq_n_u32(round_constant, 1);  // { 0, 0x04, 0, 0x04 }
    t1 = aes_128_assist(t1, round_constant);
    vst1q_u8(&ks[3 * 16], t1);

    round_constant = vshlq_n_u32(round_constant, 1);  // { 0, 0x08, 0, 0x08 }
    t1 = aes_128_assist(t1, round_constant);
    vst1q_u8(&ks[4 * 16], t1);

    round_constant = vshlq_n_u32(round_constant, 1);  // { 0, 0x10, 0, 0x10 }
    t1 = aes_128_assist(t1, round_constant);
    vst1q_u8(&ks[5 * 16], t1);

    round_constant = vshlq_n_u32(round_constant, 1);  // { 0, 0x20, 0, 0x20 }
    t1 = aes_128_assist(t1, round_constant);
    vst1q_u8(&ks[6 * 16], t1);

    round_constant = vshlq_n_u32(round_constant, 1);  // { 0, 0x40, 0, 0x40 }
    t1 = aes_128_assist(t1, round_constant);
    vst1q_u8(&ks[7 * 16], t1);

    round_constant = vshlq_n_u32(round_constant, 1);  // { 0, 0x80, 0, 0x80 }
    t1 = aes_128_assist(t1, round_constant);
    vst1q_u8(&ks[8 * 16], t1);

    round_constant = vld1q_u32(kRoundConstant2);      // { 0, 0x1B, 0, 0x1B }
    t1 = aes_128_assist(t1, round_constant);
    vst1q_u8(&ks[9 * 16], t1);

    round_constant = vshlq_n_u32(round_constant, 1);  // { 0, 0x36, 0, 0x36 }
    t1 = aes_128_assist(t1, round_constant);
    vst1q_u8(&ks[10 * 16], t1);

    cx->inf.l = 0;
    cx->inf.b[0] = 10 * AES_BLOCK_SIZE;
    return EXIT_SUCCESS;
}

INLINE void aes_192_assist(uint8x16_t t1, uint8x16_t t3, const uint32x4_t round_constant, uint8x16_t *t5, uint8x16_t *t7)
{
    uint8x16_t t2, t4;
    t2 = aes_keygenassist(t3, round_constant);
    t2 = vreinterpretq_u8_u32(vdupq_n_u32(vgetq_lane_u32(vreinterpretq_u32_u8(t2), 1)));
    t4 = vextq_u8(vdupq_n_u8(0), t1, 16 - 4);
    t1 = veorq_u8(t1, t4);
    t4 = vextq_u8(vdupq_n_u8(0), t4, 16 - 4);
    t1 = veorq_u8(t1, t4);
    t4 = vextq_u8(vdupq_n_u8(0), t4, 16 - 4);
    t1 = veorq_u8(t1, t4);
    t1 = veorq_u8(t1, t2);
    t2 = vreinterpretq_u8_u32(vdupq_n_u32(vgetq_lane_u32(vreinterpretq_u32_u8(t1), 3)));
    t4 = vextq_u8(vdupq_n_u8(0), t3, 16 - 4);
    t3 = veorq_u8(t3, t4);
    t3 = veorq_u8(t3, t2);
    *t5 = t1;
    *t7 = t3;
}

AES_RETURN aes_arm64(encrypt_key192)(const unsigned char *key, aes_encrypt_ctx cx[1])
{
    uint8x16_t t1, t3, t5, t7;
    uint32x4_t round_constant;
    uint8_t *ks = (uint8_t*)&cx->ks[0];
    ALIGNED_(16) static const uint32_t kRoundConstant1[4] = { 0, 0x01, 0, 0x01 };

    if(!has_feature_aes())
    {
        return aes_xi(encrypt_key192)(key, cx);
    }
    assert(ALIGN_OFFSET(cx, 16) == 0);

    t1 = vld1q_u8(key);
    t3 = vld1q_u8(key + 16);
    round_constant = vld1q_u32(kRoundConstant1);      // { 0, 0x01, 0, 0x01 }
    aes_192_assist(t1, t3, round_constant, &t5, &t7);
    vst1q_u8(&ks[0 * 16], t1);
    vst1q_u8(&ks[1 * 16], vcombine_u8(vget_low_u8(t3), vget_low_u8(t5)));
    vst1q_u8(&ks[2 * 16], vcombine_u8(vget_high_u8(t5), vget_low_u8(t7)));

    round_constant = vshlq_n_u32(round_constant, 1);  // { 0, 0x02, 0, 0x02 }
    aes_192_assist(t5, t7, round_constant, &t1, &t3);
    round_constant = vshlq_n_u32(round_constant, 1);  // { 0, 0x04, 0, 0x04 }
    aes_192_assist(t1, t3, round_constant, &t5, &t7);
    vst1q_u8(&ks[3 * 16], t1);
    vst1q_u8(&ks[4 * 16], vcombine_u8(vget_low_u8(t3), vget_low_u8(t5)));
    vst1q_u8(&ks[5 * 16], vcombine_u8(vget_high_u8(t5), vget_low_u8(t7)));

    round_constant = vshlq_n_u32(round_constant, 1);  // { 0, 0x08, 0, 0x08 }
    aes_192_assist(t5, t7, round_constant, &t1, &t3);
    round_constant = vshlq_n_u32(round_constant, 1);  // { 0, 0x10, 0, 0x10 }
    aes_192_assist(t1, t3, round_constant, &t5, &t7);
    vst1q_u8(&ks[6 * 16], t1);
    vst1q_u8(&ks[7 * 16], vcombine_u8(vget_low_u8(t3), vget_low_u8(t5)));
    vst1q_u8(&ks[8 * 16], vcombine_u8(vget_high_u8(t5), vget_low_u8(t7)));

    round_constant = vshlq_n_u32(round_constant, 1);  // { 0, 0x20, 0, 0x20 }
    aes_192_assist(t5, t7, round_constant, &t1, &t3);
    round_constant = vshlq_n_u32(round_constant, 1);  // { 0, 0x40, 0, 0x40 }
    aes_192_assist(t1, t3, round_constant, &t5, &t7);
    vst1q_u8(&ks[9 * 16], t1);
    vst1q_u8(&ks[10 * 16], vcombine_u8(vget_low_u8(t3), vget_low_u8(t5)));
    vst1q_u8(&ks[11 * 16], vcombine_u8(vget_high_u8(t5), vget_low_u8(t7)));

    round_constant = vshlq_n_u32(round_constant, 1);  // { 0, 0x80, 0, 0x80 }
    aes_192_assist(t5, t7, round_constant, &t1, &t3);
    vst1q_u8(&ks[12 * 16], t1);

    cx->inf.l = 0;
    cx->inf.b[0] = 12 * AES_BLOCK_SIZE;
    return EXIT_SUCCESS;
}

INLINE uint8x16_t aes_256_assist1(uint8x16_t t1, uint8x16_t t3, uint32x4_t round_constant)
{
    uint8x16_t t2, t4;
    t2 = aes_keygenassist(t3, round_constant);
    t2 = vreinterpretq_u8_u32(vdupq_n_u32(vgetq_lane_u32(vreinterpretq_u32_u8(t2), 3)));
    t4 = vextq_u8(vdupq_n_u8(0), t1, 16 - 4);
    t1 = veorq_u8(t1, t4);
    t4 = vextq_u8(vdupq_n_u8(0), t4, 16 - 4);
    t1 = veorq_u8(t1, t4);
    t4 = vextq_u8(vdupq_n_u8(0), t4, 16 - 4);
    t1 = veorq_u8(t1, t4);
    t1 = veorq_u8(t1, t2);
    return t1;
}

INLINE uint8x16_t aes_256_assist2(uint8x16_t t1, uint8x16_t t3)
{
    uint8x16_t t2, t4;
    t2 = aes_keygenassist(t1, vdupq_n_u32(0));
    t2 = vreinterpretq_u8_u32(vdupq_n_u32(vgetq_lane_u32(vreinterpretq_u32_u8(t2), 2)));
    t4 = vextq_u8(vdupq_n_u8(0), t3, 16 - 4);
    t3 = veorq_u8(t3, t4);
    t4 = vextq_u8(vdupq_n_u8(0), t4, 16 - 4);
    t3 = veorq_u8(t3, t4);
    t4 = vextq_u8(vdupq_n_u8(0), t4, 16 - 4);
    t3 = veorq_u8(t3, t4);
    t3 = veorq_u8(t3, t2);
    return t3;
}

AES_RETURN aes_arm64(encrypt_key256)(const unsigned char *key, aes_encrypt_ctx cx[1])
{
    uint8x16_t t1, t3;
    uint32x4_t round_constant;
    uint8_t *ks = (uint8_t*)&cx->ks[0];
    ALIGNED_(16) static const uint32_t kRoundConstant1[4] = { 0, 0x01, 0, 0x01 };

    if(!has_feature_aes())
    {
        return aes_xi(encrypt_key256)(key, cx);
    }
    assert(ALIGN_OFFSET(cx, 16) == 0);

    t1 = vld1q_u8(key);
    t3 = vld1q_u8(key + 16);
    vst1q_u8(&ks[0 * 16], t1);
    vst1q_u8(&ks[1 * 16], t3);

    round_constant = vld1q_u32(kRoundConstant1);      // { 0, 0x01, 0, 0x01 }
    t1 = aes_256_assist1(t1, t3, round_constant);
    t3 = aes_256_assist2(t1, t3);
    vst1q_u8(&ks[2 * 16], t1);
    vst1q_u8(&ks[3 * 16], t3);

    round_constant = vshlq_n_u32(round_constant, 1);  // { 0, 0x02, 0, 0x02 }
    t1 = aes_256_assist1(t1, t3, round_constant);
    t3 = aes_256_assist2(t1, t3);
    vst1q_u8(&ks[4 * 16], t1);
    vst1q_u8(&ks[5 * 16], t3);

    round_constant = vshlq_n_u32(round_constant, 1);  // { 0, 0x04, 0, 0x04 }
    t1 = aes_256_assist1(t1, t3, round_constant);
    t3 = aes_256_assist2(t1, t3);
    vst1q_u8(&ks[6 * 16], t1);
    vst1q_u8(&ks[7 * 16], t3);

    round_constant = vshlq_n_u32(round_constant, 1);  // { 0, 0x08, 0, 0x08 }
    t1 = aes_256_assist1(t1, t3, round_constant);
    t3 = aes_256_assist2(t1, t3);
    vst1q_u8(&ks[8 * 16], t1);
    vst1q_u8(&ks[9 * 16], t3);

    round_constant = vshlq_n_u32(round_constant, 1);  // { 0, 0x10, 0, 0x10 }
    t1 = aes_256_assist1(t1, t3, round_constant);
    t3 = aes_256_assist2(t1, t3);
    vst1q_u8(&ks[10 * 16], t1);
    vst1q_u8(&ks[11 * 16], t3);

    round_constant = vshlq_n_u32(round_constant, 1);  // { 0, 0x20, 0, 0x20 }
    t1 = aes_256_assist1(t1, t3, round_constant);
    t3 = aes_256_assist2(t1, t3);
    vst1q_u8(&ks[12 * 16], t1);
    vst1q_u8(&ks[13 * 16], t3);

    round_constant = vshlq_n_u32(round_constant, 1);  // { 0, 0x40, 0, 0x40 }
    t1 = aes_256_assist1(t1, t3, round_constant);
    vst1q_u8(&ks[14 * 16], t1);

    cx->inf.l = 0;
    cx->inf.b[0] = 14 * AES_BLOCK_SIZE;
    return EXIT_SUCCESS;
}

AES_RETURN aes_arm64(decrypt_key128)(const unsigned char *key, aes_decrypt_ctx cx[1])
{
    uint8x16_t t1;
    uint32x4_t round_constant;
    uint8_t *ks = (uint8_t*)&cx->ks[0];
    ALIGNED_(16) static const uint32_t kRoundConstant1[4] = { 0, 0x01, 0, 0x01 };
    ALIGNED_(16) static const uint32_t kRoundConstant2[4] = { 0, 0x1B, 0, 0x1B };

    if(!has_feature_aes())
    {
        return aes_xi(decrypt_key128)(key, cx);
    }
    assert(ALIGN_OFFSET(cx, 16) == 0);

    t1 = vld1q_u8(key);
    vst1q_u8(&ks[10 * 16], t1);

    round_constant = vld1q_u32(kRoundConstant1);      // { 0, 0x01, 0, 0x01 }
    t1 = aes_128_assist(t1, round_constant);
    vst1q_u8(&ks[9 * 16], vaesimcq_u8(t1));

    round_constant = vshlq_n_u32(round_constant, 1);  // { 0, 0x02, 0, 0x02 }
    t1 = aes_128_assist(t1, round_constant);
    vst1q_u8(&ks[8 * 16], vaesimcq_u8(t1));

    round_constant = vshlq_n_u32(round_constant, 1);  // { 0, 0x04, 0, 0x04 }
    t1 = aes_128_assist(t1, round_constant);
    vst1q_u8(&ks[7 * 16], vaesimcq_u8(t1));

    round_constant = vshlq_n_u32(round_constant, 1);  // { 0, 0x08, 0, 0x08 }
    t1 = aes_128_assist(t1, round_constant);
    vst1q_u8(&ks[6 * 16], vaesimcq_u8(t1));

    round_constant = vshlq_n_u32(round_constant, 1);  // { 0, 0x10, 0, 0x10 }
    t1 = aes_128_assist(t1, round_constant);
    vst1q_u8(&ks[5 * 16], vaesimcq_u8(t1));

    round_constant = vshlq_n_u32(round_constant, 1);  // { 0, 0x20, 0, 0x20 }
    t1 = aes_128_assist(t1, round_constant);
    vst1q_u8(&ks[4 * 16], vaesimcq_u8(t1));

    round_constant = vshlq_n_u32(round_constant, 1);  // { 0, 0x40, 0, 0x40 }
    t1 = aes_128_assist(t1, round_constant);
    vst1q_u8(&ks[3 * 16], vaesimcq_u8(t1));

    round_constant = vshlq_n_u32(round_constant, 1);  // { 0, 0x80, 0, 0x80 }
    t1 = aes_128_assist(t1, round_constant);
    vst1q_u8(&ks[2 * 16], vaesimcq_u8(t1));

    round_constant = vld1q_u32(kRoundConstant2);      // { 0, 0x1B, 0, 0x1B }
    t1 = aes_128_assist(t1, round_constant);
    vst1q_u8(&ks[1 * 16], vaesimcq_u8(t1));

    round_constant = vshlq_n_u32(round_constant, 1);  // { 0, 0x36, 0, 0x36 }
    t1 = aes_128_assist(t1, round_constant);
    vst1q_u8(&ks[0 * 16], t1);

    cx->inf.l = 0;
    cx->inf.b[0] = 10 * 16;
    return EXIT_SUCCESS;
}

AES_RETURN aes_arm64(decrypt_key192)(const unsigned char *key, aes_decrypt_ctx cx[1])
{
    uint8x16_t t1, t3, t5, t7;
    uint32x4_t round_constant;
    uint8_t *ks = (uint8_t*)&cx->ks[0];
    ALIGNED_(16) static const uint32_t kRoundConstant1[4] = { 0, 0x01, 0, 0x01 };

    if(!has_feature_aes())
    {
        return aes_xi(decrypt_key192)(key, cx);
    }
    assert(ALIGN_OFFSET(cx, 16) == 0);

    t1 = vld1q_u8(key);
    t3 = vld1q_u8(key + 16);
    round_constant = vld1q_u32(kRoundConstant1);      // { 0, 0x01, 0, 0x01 }
    aes_192_assist(t1, t3, round_constant, &t5, &t7);
    vst1q_u8(&ks[12 * 16], t1);
    vst1q_u8(&ks[11 * 16], vaesimcq_u8(vcombine_u8(vget_low_u8(t3), vget_low_u8(t5))));
    vst1q_u8(&ks[10 * 16], vaesimcq_u8(vcombine_u8(vget_high_u8(t5), vget_low_u8(t7))));

    round_constant = vshlq_n_u32(round_constant, 1);  // { 0, 0x02, 0, 0x02 }
    aes_192_assist(t5, t7, round_constant, &t1, &t3);
    round_constant = vshlq_n_u32(round_constant, 1);  // { 0, 0x04, 0, 0x04 }
    aes_192_assist(t1, t3, round_constant, &t5, &t7);
    vst1q_u8(&ks[9 * 16], vaesimcq_u8(t1));
    vst1q_u8(&ks[8 * 16], vaesimcq_u8(vcombine_u8(vget_low_u8(t3), vget_low_u8(t5))));
    vst1q_u8(&ks[7 * 16], vaesimcq_u8(vcombine_u8(vget_high_u8(t5), vget_low_u8(t7))));

    round_constant = vshlq_n_u32(round_constant, 1);  // { 0, 0x08, 0, 0x08 }
    aes_192_assist(t5, t7, round_constant, &t1, &t3);
    round_constant = vshlq_n_u32(round_constant, 1);  // { 0, 0x10, 0, 0x10 }
    aes_192_assist(t1, t3, round_constant, &t5, &t7);
    vst1q_u8(&ks[6 * 16], vaesimcq_u8(t1));
    vst1q_u8(&ks[5 * 16], vaesimcq_u8(vcombine_u8(vget_low_u8(t3), vget_low_u8(t5))));
    vst1q_u8(&ks[4 * 16], vaesimcq_u8(vcombine_u8(vget_high_u8(t5), vget_low_u8(t7))));

    round_constant = vshlq_n_u32(round_constant, 1);  // { 0, 0x20, 0, 0x20 }
    aes_192_assist(t5, t7, round_constant, &t1, &t3);
    round_constant = vshlq_n_u32(round_constant, 1);  // { 0, 0x40, 0, 0x40 }
    aes_192_assist(t1, t3, round_constant, &t5, &t7);
    vst1q_u8(&ks[3 * 16], vaesimcq_u8(t1));
    vst1q_u8(&ks[2 * 16], vaesimcq_u8(vcombine_u8(vget_low_u8(t3), vget_low_u8(t5))));
    vst1q_u8(&ks[1 * 16], vaesimcq_u8(vcombine_u8(vget_high_u8(t5), vget_low_u8(t7))));

    round_constant = vshlq_n_u32(round_constant, 1);  // { 0, 0x80, 0, 0x80 }
    aes_192_assist(t5, t7, round_constant, &t1, &t3);
    vst1q_u8(&ks[0 * 16], t1);

    cx->inf.l = 0;
    cx->inf.b[0] = 12 * AES_BLOCK_SIZE;
    return EXIT_SUCCESS;
}

AES_RETURN aes_arm64(decrypt_key256)(const unsigned char *key, aes_decrypt_ctx cx[1])
{
    uint8x16_t t1, t3;
    uint32x4_t round_constant;
    uint8_t *ks = (uint8_t*)&cx->ks[0];
    ALIGNED_(16) static const uint32_t kRoundConstant1[4] = { 0, 0x01, 0, 0x01 };

    if(!has_feature_aes())
    {
        return aes_xi(decrypt_key256)(key, cx);
    }
    assert(ALIGN_OFFSET(cx, 16) == 0);

    t1 = vld1q_u8(key);
    t3 = vld1q_u8(key + 16);
    vst1q_u8(&ks[14 * 16], t1);
    vst1q_u8(&ks[13 * 16], vaesimcq_u8(t3));

    round_constant = vld1q_u32(kRoundConstant1);      // { 0, 0x01, 0, 0x01 }
    t1 = aes_256_assist1(t1, t3, round_constant);
    t3 = aes_256_assist2(t1, t3);
    vst1q_u8(&ks[12 * 16], vaesimcq_u8(t1));
    vst1q_u8(&ks[11 * 16], vaesimcq_u8(t3));

    round_constant = vshlq_n_u32(round_constant, 1);  // { 0, 0x02, 0, 0x02 }
    t1 = aes_256_assist1(t1, t3, round_constant);
    t3 = aes_256_assist2(t1, t3);
    vst1q_u8(&ks[10 * 16], vaesimcq_u8(t1));
    vst1q_u8(&ks[9 * 16], vaesimcq_u8(t3));

    round_constant = vshlq_n_u32(round_constant, 1);  // { 0, 0x04, 0, 0x04 }
    t1 = aes_256_assist1(t1, t3, round_constant);
    t3 = aes_256_assist2(t1, t3);
    vst1q_u8(&ks[8 * 16], vaesimcq_u8(t1));
    vst1q_u8(&ks[7 * 16], vaesimcq_u8(t3));

    round_constant = vshlq_n_u32(round_constant, 1);  // { 0, 0x08, 0, 0x08 }
    t1 = aes_256_assist1(t1, t3, round_constant);
    t3 = aes_256_assist2(t1, t3);
    vst1q_u8(&ks[6 * 16], vaesimcq_u8(t1));
    vst1q_u8(&ks[5 * 16], vaesimcq_u8(t3));

    round_constant = vshlq_n_u32(round_constant, 1);  // { 0, 0x10, 0, 0x10 }
    t1 = aes_256_assist1(t1, t3, round_constant);
    t3 = aes_256_assist2(t1, t3);
    vst1q_u8(&ks[4 * 16], vaesimcq_u8(t1));
    vst1q_u8(&ks[3 * 16], vaesimcq_u8(t3));

    round_constant = vshlq_n_u32(round_constant, 1);  // { 0, 0x20, 0, 0x20 }
    t1 = aes_256_assist1(t1, t3, round_constant);
    t3 = aes_256_assist2(t1, t3);
    vst1q_u8(&ks[2 * 16], vaesimcq_u8(t1));
    vst1q_u8(&ks[1 * 16], vaesimcq_u8(t3));

    round_constant = vshlq_n_u32(round_constant, 1);  // { 0, 0x40, 0, 0x40 }
    t1 = aes_256_assist1(t1, t3, round_constant);
    vst1q_u8(&ks[0 * 16], t1);

    cx->inf.l = 0;
    cx->inf.b[0] = 14 * AES_BLOCK_SIZE;
    return EXIT_SUCCESS;
}

AES_RETURN aes_arm64(encrypt)(const unsigned char *in, unsigned char *out, const aes_encrypt_ctx cx[1])
{
    uint8x16_t t;
    const uint8_t *key = (const uint8_t*)cx->ks;

    if(cx->inf.b[0] != 10 * AES_BLOCK_SIZE && cx->inf.b[0] != 12 * AES_BLOCK_SIZE && cx->inf.b[0] != 14 * AES_BLOCK_SIZE)
        return EXIT_FAILURE;

    if(!has_feature_aes())
    {
        return aes_xi(encrypt)(in, out, cx);
    }
    assert(ALIGN_OFFSET(cx, 16) == 0);

    t = vaesmcq_u8(vaeseq_u8(vld1q_u8(in), vld1q_u8(key)));
    switch(cx->inf.b[0])
    {
    case 14 * AES_BLOCK_SIZE:
        t = vaesmcq_u8(vaeseq_u8(t, vld1q_u8(key + 1 * 16)));
        t = vaesmcq_u8(vaeseq_u8(t, vld1q_u8(key + 2 * 16)));
        key += 2 * 16;
    case 12 * AES_BLOCK_SIZE:
        t = vaesmcq_u8(vaeseq_u8(t, vld1q_u8(key + 1 * 16)));
        t = vaesmcq_u8(vaeseq_u8(t, vld1q_u8(key + 2 * 16)));
        key += 2 * 16;
    case 10 * AES_BLOCK_SIZE:
        t = vaesmcq_u8(vaeseq_u8(t, vld1q_u8(key + 1 * 16)));
        t = vaesmcq_u8(vaeseq_u8(t, vld1q_u8(key + 2 * 16)));
        t = vaesmcq_u8(vaeseq_u8(t, vld1q_u8(key + 3 * 16)));
        t = vaesmcq_u8(vaeseq_u8(t, vld1q_u8(key + 4 * 16)));
        t = vaesmcq_u8(vaeseq_u8(t, vld1q_u8(key + 5 * 16)));
        t = vaesmcq_u8(vaeseq_u8(t, vld1q_u8(key + 6 * 16)));
        t = vaesmcq_u8(vaeseq_u8(t, vld1q_u8(key + 7 * 16)));
        t = vaesmcq_u8(vaeseq_u8(t, vld1q_u8(key + 8 * 16)));
        t = vaeseq_u8(t, vld1q_u8(key + 9 * 16));
        t = veorq_u8(t, vld1q_u8(key + 10 * 16));
    }
    vst1q_u8(out, t);
    return EXIT_SUCCESS;
}

AES_RETURN aes_arm64(decrypt)(const unsigned char *in, unsigned char *out, const aes_decrypt_ctx cx[1])
{
    uint8x16_t t;
    const uint8_t *key = (const uint8_t*)cx->ks;

    if(cx->inf.b[0] != 10 * AES_BLOCK_SIZE && cx->inf.b[0] != 12 * AES_BLOCK_SIZE && cx->inf.b[0] != 14 * AES_BLOCK_SIZE)
        return EXIT_FAILURE;

    if(!has_feature_aes())
    {
        return aes_xi(decrypt)(in, out, cx);
    }
    assert(ALIGN_OFFSET(cx, 16) == 0);

    t = vaesimcq_u8(vaesdq_u8(vld1q_u8(in), vld1q_u8(key)));
    switch(cx->inf.b[0])
    {
    case 14 * AES_BLOCK_SIZE:
        t = vaesimcq_u8(vaesdq_u8(t, vld1q_u8(key + 1 * 16)));
        t = vaesimcq_u8(vaesdq_u8(t, vld1q_u8(key + 2 * 16)));
        key += 2 * 16;
    case 12 * AES_BLOCK_SIZE:
        t = vaesimcq_u8(vaesdq_u8(t, vld1q_u8(key + 1 * 16)));
        t = vaesimcq_u8(vaesdq_u8(t, vld1q_u8(key + 2 * 16)));
        key += 2 * 16;
    case 10 * AES_BLOCK_SIZE:
        t = vaesimcq_u8(vaesdq_u8(t, vld1q_u8(key + 1 * 16)));
        t = vaesimcq_u8(vaesdq_u8(t, vld1q_u8(key + 2 * 16)));
        t = vaesimcq_u8(vaesdq_u8(t, vld1q_u8(key + 3 * 16)));
        t = vaesimcq_u8(vaesdq_u8(t, vld1q_u8(key + 4 * 16)));
        t = vaesimcq_u8(vaesdq_u8(t, vld1q_u8(key + 5 * 16)));
        t = vaesimcq_u8(vaesdq_u8(t, vld1q_u8(key + 6 * 16)));
        t = vaesimcq_u8(vaesdq_u8(t, vld1q_u8(key + 7 * 16)));
        t = vaesimcq_u8(vaesdq_u8(t, vld1q_u8(key + 8 * 16)));
        t = vaesdq_u8(t, vld1q_u8(key + 9 * 16));
        t = veorq_u8(t, vld1q_u8(key + 10 * 16));
    }
    vst1q_u8(out, t);
    return EXIT_SUCCESS;
}

#endif
