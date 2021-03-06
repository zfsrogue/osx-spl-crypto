/*-
 * Copyright 2013 Jorgen Lundman <lundman@lundman.net>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * $FreeBSD$
 *
 */

/*
 *
 * Implement CTR-AES, 4byte nonce, 8byte iv, 4byte counter
 *
 * Implement GCM authtag, which uses magic somehow
 *
 * authtag is computed and put at the end of the output "cipher" buffer.
 *
 *
 */

//#define ZFS_CRYPTO_VERBOSE

#include <sys/cdefs.h>
#include <sys/types.h>
#include <sys/conf.h>
#include <sys/cpuvar.h>
#include <sys/errno.h>

#include <sys/param.h>
#include <sys/systm.h>

#include <sys/crypto/api.h>
#include <sys/crypto/rijndael.h>
#include <sys/crypto/sun_gcm.h>
#include <sys/byteorder.h>

int crypto_get_buffer(crypto_data_t *solaris_buffer, unsigned int *index,
                      uint8_t **addr, uint64_t *size);


/*
 * Are we guaranteed that all xor operations are on 4 byte boundaries?
 */
static __inline void xor_block(uint8_t *dst,
                               uint8_t *src,
                               size_t size)
{
#if 1
    uint32_t *a = (uint32_t *)dst;
    uint32_t *b = (uint32_t *)src;

    for (; size >= 4; size -= 4)
        *a++ ^= *b++;
    dst = (uint8_t *)a;
    src = (uint8_t *)b;
#endif
    for (; size; size--)
        *dst++ ^= *src++;
}

static __inline void xor_block2(uint8_t *dst,
                                uint8_t *src,
                                uint8_t *xor,
                                size_t size)
{
#if 1
    uint32_t *a = (uint32_t *)dst;
    uint32_t *b = (uint32_t *)src;
    uint32_t *x = (uint32_t *)xor;

    for (; size >= 4; size -= 4)
        *a++ = *b++ ^ *x++;
    dst = (uint8_t *)a;
    src = (uint8_t *)b;
    xor = (uint8_t *)x;
#endif
    for (; size; size--)
        *dst++ = *src++ ^ *xor++;
}


#define CCMP_ENCRYPT(_i, _S, _b0, _pos, _out, _e, _len, _H) do {   \
        /* Encryption, with counter */                             \
        _b0[12] = (_i >> 24)& 0xff;                                \
        _b0[13] = (_i >> 16)& 0xff;                                \
        _b0[14] = (_i >> 8) & 0xff;                                \
        _b0[15] = _i & 0xff;                                       \
        rijndael_encrypt(cc_aes, _b0, _e);                         \
        xor_block2(_out, _pos, _e, _len);                          \
        /* Authentication */                                       \
        ghash(H, _out, _len, S);                                   \
} while (0)

#define CCMP_DECRYPT(_i, _b, _b0, _pos, _out, _H, _len, _S) do {      \
        /* Authentication */                                          \
        ghash(_H, _pos, _len, _S);                                    \
        /* Decrypt, with counter */                                   \
        _b0[12] = (_i >> 24)& 0xff;                                   \
        _b0[13] = (_i >> 16)& 0xff;                                   \
        _b0[14] = (_i >> 8) & 0xff;                                   \
        _b0[15] = _i & 0xff;                                          \
        rijndael_encrypt(cc_aes, _b0, _b);                            \
        xor_block2(_out, _pos, _b, _len);                             \
} while (0)





void sun_gcm_setkey(rijndael_ctx *cc_aes,
                    uint8_t *key, uint32_t keylen)
{
    rijndael_set_key(cc_aes, key, keylen*NBBY);
}


/*
 * For authtag;
 * B0 is computed with M and L in flags (first byte), then nonce is copied in
 * followed by the cryptlen at the end, with most significant byte first.
 */
static void ccm_init_b0(uint8_t *b0,
                        uint8_t *nonce,
                        uint32_t noncelen)
{

    if (nonce && noncelen)
        memcpy(&b0[0], nonce, noncelen);
    else
        memset(&b0[0], 0, 12);

    b0[12] = 0x00;
    b0[13] = 0x00;
    b0[14] = 0x00;
    b0[15] = 0x01;

}




static void shift_right_block(uint8_t *v)
{
    uint32_t val;
    uint32_t *r;

    //val = WPA_GET_BE32(v + 12);
    r = (uint32_t *)&v[12];
    val = BE_32(*r);
    val >>= 1;
    if (v[11] & 0x01)
        val |= 0x80000000;
    *r = BE_32(val);
    //    WPA_PUT_BE32(v + 12, val);

    //val = WPA_GET_BE32(v + 8);
    r = (uint32_t *)&v[8];
    val = BE_32(*r);
    val >>= 1;
    if (v[7] & 0x01)
        val |= 0x80000000;
    *r = BE_32(val);
    //WPA_PUT_BE32(v + 8, val);

    //val = WPA_GET_BE32(v + 4);
    r = (uint32_t *)&v[4];
    val = BE_32(*r);
    val >>= 1;
    if (v[3] & 0x01)
        val |= 0x80000000;
    *r = BE_32(val);
    //WPA_PUT_BE32(v + 4, val);

    //val = WPA_GET_BE32(v);
    r = (uint32_t *)&v[0];
    val = BE_32(*r);
    val >>= 1;
    *r = BE_32(val);
    //    WPA_PUT_BE32(v, val);
}

#define BIT(n) (1 << (n))

/* Multiplication in GF(2^128) */
static void gf_mult(uint8_t *x, uint8_t *y, uint8_t *z)
{
    uint8_t v[16];
    int i, j;

    memset(z, 0, 16); /* Z_0 = 0^128 */
    memcpy(v, y, 16); /* V_0 = Y */

    for (i = 0; i < 16; i++) {
        for (j = 0; j < 8; j++) {
            if (x[i] & BIT(7 - j)) {
                /* Z_(i + 1) = Z_i XOR V_i */
                xor_block(z, v, 16);
            } else {
                /* Z_(i + 1) = Z_i */
            }

            if (v[15] & 0x01) {
                /* V_(i + 1) = (V_i >> 1) XOR R */
                shift_right_block(v);
                /* R = 11100001 || 0^120 */
                v[0] ^= 0xe1;
            } else {
                /* V_(i + 1) = V_i >> 1 */
                shift_right_block(v);
            }
        }
    }
}


static void ghash_start(uint8_t *y)
{
    /* Y_0 = 0^128 */
    memset(y, 0, 16);
}


static void ghash(uint8_t *h, uint8_t *x, size_t xlen, uint8_t *y)
{
    size_t m, i;
    uint8_t *xpos = x;
    uint8_t tmp[16];

    m = xlen / 16;

    for (i = 0; i < m; i++) {
        /* Y_i = (Y^(i-1) XOR X_i) dot H */
        xor_block(y, xpos, 16);
        xpos += 16;

        /* dot operation:
         * multiplication operation for binary Galois (finite) field of
         * 2^128 elements */
        gf_mult(y, h, tmp);
        memcpy(y, tmp, 16);
    }

    if (x + xlen > xpos) {
        /* Add zero padded last block */
        size_t last = x + xlen - xpos;
        memcpy(tmp, xpos, last);
        memset(tmp + last, 0, sizeof(tmp) - last);

        /* Y_i = (Y^(i-1) XOR X_i) dot H */
        xor_block(y, tmp, 16);

        /* dot operation:
         * multiplication operation for binary Galois (finite) field of
         * 2^128 elements */
        gf_mult(y, h, tmp);
        memcpy(y, tmp, 16);
    }

    /* Return Y_m */
}


static void aes_gcm_init_hash_subkey(rijndael_ctx *aes,
                                     uint8_t *H)
{

    /* Generate hash subkey H = AES_K(0^128) */
    memset(H, 0, AES_BLOCK_LEN);
    rijndael_encrypt(aes, H, H);

}


static void aes_gcm_prepare_j0(uint8_t *iv, size_t iv_len,
                               uint8_t *H, uint8_t *J0)
{
    uint8_t len_buf[16];
    uint64_t s;

    if (iv_len == 12) {
        /* Prepare block J_0 = IV || 0^31 || 1 [len(IV) = 96] */
        memcpy(J0, iv, iv_len);
        memset(J0 + iv_len, 0, AES_BLOCK_LEN - iv_len);
        J0[AES_BLOCK_LEN - 1] = 0x01;
    } else {
        /*
         * s = 128 * ceil(len(IV)/128) - len(IV)
         * J_0 = GHASH_H(IV || 0^(s+64) || [len(IV)]_64)
         */
        ghash_start(J0);
        ghash(H, iv, iv_len, J0);
        s = 0;
        memcpy(&len_buf[0], &s, sizeof(s));
        s = BE_64(iv_len*8);
        memcpy(&len_buf[8], &s, sizeof(s));
        //WPA_PUT_BE64(len_buf, 0);
        //WPA_PUT_BE64(len_buf + 8, iv_len * 8);
        ghash(H, len_buf, sizeof(len_buf), J0);
    }
}





static void aes_gcm_final(rijndael_ctx *aes, uint32_t aad_len,
                          uint32_t crypt_len, uint8_t *H, uint8_t *S,
                          uint8_t *J0, uint8_t *tag)
{
    uint64_t s;
    uint8_t len_buf[16];

    s = BE_64(aad_len * 8);
    memcpy(&len_buf[0], &s, sizeof(s));
    //WPA_PUT_BE64(len_buf, aad_len * 8);
    s = BE_64(crypt_len * 8);
    memcpy(&len_buf[8], &s, sizeof(s));
    //WPA_PUT_BE64(len_buf + 8, crypt_len * 8);
    ghash(H, len_buf, sizeof(len_buf), S);

    /* T = MSB_t(GCTR_K(J_0, S)) */
    //aes_gctr(aes, J0, S, sizeof(S), tag);
    rijndael_encrypt(aes, J0, tag);
    xor_block(tag, S, 16);
}








/*
 * Encrypt "plain" struct mbuf(s) into "cipher" struct mbuf(s).
 * If there is room, tack the auth at the end of "cipher".
 */
int sun_gcm_encrypt_and_auth(rijndael_ctx *cc_aes,
                             crypto_data_t *plaintext,
                             crypto_data_t *crypttext,
                             uint8_t *nonce, uint32_t noncelen,
                             uint32_t authlen)
{
    uint64_t len;
    uint8_t *src;
    uint8_t *dst;
    uint64_t srclen;
    uint64_t dstlen;
    uint32_t i;
    uint64_t space;
    uint8_t b0[AES_BLOCK_LEN], tag[AES_BLOCK_LEN], e[AES_BLOCK_LEN];
    uint8_t tmp[AES_BLOCK_LEN];
    unsigned int plain_index, crypt_index;
    uint64_t remainder;
    uint64_t avail;
    uint8_t  H[AES_BLOCK_LEN];
    uint8_t  J0[AES_BLOCK_LEN];
    uint8_t  S[AES_BLOCK_LEN];

#ifdef ZFS_CRYPTO_VERBOSE
    printf("gcm_encrypt enter: len %04lx maclen %d, authlen %d\n",
           plaintext->cd_length,
           noncelen, authlen);
#endif

    memset(tag, 0, sizeof(tag));
    memset(e, 0, sizeof(e));

    /*
     * ***********************************************************
     * For encryption, copy iv over to B0
     */

    ccm_init_b0(b0, nonce, noncelen);


    /*
     * ***********************************************************
     * GHASH needs key setup
     */

    aes_gcm_init_hash_subkey(cc_aes, H);


    /*
     * ***********************************************************
     * For AUTH, setup J0 correctly.
     */

    aes_gcm_prepare_j0(nonce, noncelen, H, J0);

    ghash_start(S);
    //ghash(H, aad, aad_len, S);
    ghash(H, NULL, 0, S);


    /*
     * ***********************************************************
     */

    // Encrypt
    len = plaintext->cd_length;

    // Setup first buffers.
    plain_index = 0;
    crypt_index = 0;
    if (!crypto_get_buffer(plaintext,
                           &plain_index, &src, &srclen)) return -1;
    if (!crypto_get_buffer(crypttext,
                           &crypt_index, &dst, &dstlen)) return -1;

#ifdef ZFS_CRYPTO_VERBOSE
    printf("Before:\n");
    for (i = 0; i < 16; i++)
        printf("0x%02x ", src[i]);
    printf("\n");
#endif

    // Process all 16 blocks in the smallest of the two buffers
    while(len) {

#ifdef ZFS_CRYPTO_VERBOSE
        printf("gcmp_encrypt: %p:0x%x -> %p:0x%x\n",
               src, (unsigned int)srclen, dst, (unsigned int)dstlen);
#endif

        space = MIN(srclen, dstlen);

#ifdef ZFS_CRYPTO_VERBOSE
        printf("encrypt: opting to process buffer size 0x%04x\n",
               (uint32_t)space);
#endif
        i = 1;
        while (space >= AES_BLOCK_LEN) {
            i++; // Linux has counter=2 for first encrypted block
            CCMP_ENCRYPT(i, S, b0, src, dst, e, AES_BLOCK_LEN, H);
            src += AES_BLOCK_LEN;
            dst += AES_BLOCK_LEN;
            space -= AES_BLOCK_LEN;
            srclen-= AES_BLOCK_LEN;
            dstlen-= AES_BLOCK_LEN;
            len -= AES_BLOCK_LEN;
        }

        if (!len) break; // all finished.

        // One, or both, of src or dst may not be 16 byte aligned, so we need
        // to handle this special case.
        if (((srclen > 0) && (srclen < AES_BLOCK_LEN)) ||
            ((dstlen > 0) && (dstlen < AES_BLOCK_LEN))) {

#ifdef ZFS_CRYPTO_VERBOSE
            printf("src 0x%04x dst 0x%04x total 0x%04x\n",
                   (uint32_t)srclen, (uint32_t)dstlen, (uint32_t)len);
#endif

            remainder = srclen;
            // If src actually have more than 16, we only want 16.
            if (remainder > AES_BLOCK_LEN) remainder=AES_BLOCK_LEN;

            // Copy what we have to temp
            memcpy(tmp, src, remainder);
            // Clear the rest, in case we don't have more
            memset(&tmp[remainder], 0, AES_BLOCK_LEN - remainder);

            src+=remainder;
            srclen-=remainder;
            len -= remainder;

            // Advance to next buffer, but only if srclen was smaller than 16
            while(remainder < AES_BLOCK_LEN) {

                // Advance input to next buffer
                if (!crypto_get_buffer(plaintext,
                                       &plain_index, &src, &srclen)) break;
                // Copy over new bytes, you'd think there be 16 bytes there
                // but just in case there isn't ...
                avail = MIN(srclen, AES_BLOCK_LEN-remainder);
                memcpy(&tmp[remainder], src, avail);
                src += avail;
                srclen-=avail;
                remainder += avail;
                len -= avail;
            }

            // We have successfully loaded "tmp" with another block.
            // Process it:
            i++;
            CCMP_ENCRYPT(i, S, b0, tmp, tmp, e, AES_BLOCK_LEN, H);

            // Now it is time to write it out, and make sure there is space.
            remainder = dstlen;
            if (remainder > AES_BLOCK_LEN) remainder=AES_BLOCK_LEN;

            memcpy(dst, tmp, remainder);
            dst+=remainder;
            dstlen-=remainder;

            while(remainder < AES_BLOCK_LEN) {

                // Advance output to next buffer
                if (!crypto_get_buffer(crypttext,
                                       &crypt_index, &dst, &dstlen)) break;

                avail = MIN(dstlen, AES_BLOCK_LEN-remainder);
                memcpy(dst, &tmp[remainder], avail);
                dst += avail;
                dstlen -= avail;
                remainder += avail;
            }

#ifdef ZFS_CRYPTO_VERBOSE
            printf("Half block finished\n");
            printf("src 0x%04x dst 0x%04x total 0x%04x\n",
                   (uint32_t)srclen, (uint32_t)dstlen, (uint32_t)len);
#endif
        }

        if (srclen == 0) {
#ifdef ZFS_CRYPTO_VERBOSE
            printf("Advancing src\n");
#endif
            if (!crypto_get_buffer(plaintext,
                                   &plain_index, &src, &srclen)) break;
        }
        if (dstlen == 0) {
#ifdef ZFS_CRYPTO_VERBOSE
            printf("Advancing dst\n");
#endif
            if (!crypto_get_buffer(crypttext,
                                   &crypt_index, &dst, &dstlen)) break;
        }
    } // while total length processing


    // No authtag? just leave
    if (!authlen) return 0;

    /*
     * ***********************************************************
     * Compute final GCM authtag
     */

    aes_gcm_final(cc_aes, 0, plaintext->cd_length, H, S, J0, tag);


#ifdef ZFS_CRYPTO_VERBOSE
    printf("gcmp_auth output:\n");
    for (i = 0; i < GCM_AUTH_LEN; i++)
        printf("0x%02x ", tag[i]);
    printf("\n");
#endif

    // Do we need to advance buffer?
    if (!dstlen) {
        crypto_get_buffer(crypttext,
                          &crypt_index, &dst, &dstlen);
    }

#ifdef ZFS_CRYPTO_VERBOSE
    printf("Copying over auth: 0x%04x\n", (uint32_t) dstlen);
#endif

    // We need to try to find space in output to write auth
    remainder = dstlen;
    if (remainder > GCM_AUTH_LEN) remainder=GCM_AUTH_LEN;

    memcpy(dst, tag, remainder);
    dst+=remainder;
    dstlen-=remainder;

    while((remainder < AES_BLOCK_LEN)) {

        // Advance input to next buffer
        if (!crypto_get_buffer(crypttext,
                               &crypt_index, &dst, &dstlen)) break;
        avail = MIN(dstlen, AES_BLOCK_LEN-remainder);
        memcpy(dst, &tag[remainder], avail);
        dst += avail;
        remainder += avail;
    }
#ifdef ZFS_CRYPTO_VERBOSE
    printf("encryption completed.\n");
#endif

    return 0;
}

/*
 * Decrypt "cipher" struct mbuf(s) into "plain" struct mbuf(s).
 * authtag should follow after "cipher", is verified against computed auth.
 */
int sun_gcm_decrypt_and_auth(rijndael_ctx *cc_aes,
                             crypto_data_t *crypttext,
                             crypto_data_t *plaintext,
                             uint8_t *nonce, uint32_t noncelen,
                             uint32_t authlen)
{
    uint64_t len;
    uint8_t *src;
    uint8_t *dst;
    uint64_t srclen;
    uint64_t dstlen;
    unsigned int plain_index, crypt_index;
    uint32_t i;
    uint64_t space;
    uint8_t b0[AES_BLOCK_LEN], b[AES_BLOCK_LEN], tag[AES_BLOCK_LEN];
    uint8_t tmp[AES_BLOCK_LEN];
    uint64_t remainder;
    uint64_t avail;
    uint8_t  H[AES_BLOCK_LEN];
    uint8_t  J0[AES_BLOCK_LEN];
    uint8_t  S[AES_BLOCK_LEN];

#ifdef ZFS_CRYPTO_VERBOSE
    printf("gcm_decrypt enter: len %04lx maclen %d, authlen %d\n",
           plaintext->cd_length,
           noncelen, authlen);
#endif

    memset(b, 0, sizeof(b));
    memset(tag, 0, sizeof(tag));

    /*
     * ***********************************************************
     * For encryption, copy iv over to B0
     */

    ccm_init_b0(b0, nonce, noncelen);


    /*
     * ***********************************************************
     * GHASH needs key setup
     */

    aes_gcm_init_hash_subkey(cc_aes, H);

    /*
     * ***********************************************************
     * For AUTH, setup J0 correctly.
     */

    aes_gcm_prepare_j0(nonce, noncelen, H, J0);

    ghash_start(S);
    //ghash(H, aad, aad_len, S);
    ghash(H, NULL, 0, S);


    /*
     * ***********************************************************
     * Decrypt
     */
    len = plaintext->cd_length;

    // Setup first buffers.
    plain_index = 0;
    crypt_index = 0;

    if (!crypto_get_buffer(crypttext,
                           &crypt_index, &src, &srclen)) return -1;

    if (!crypto_get_buffer(plaintext,
                           &plain_index, &dst, &dstlen)) return -2;

    while(len) {

#ifdef ZFS_CRYPTO_VERBOSE
        printf("gcmp_decrypt: %p:0x%x -> %p:0x%x\n",
               src, (unsigned int)srclen, dst, (unsigned int)dstlen);
#endif

        space = MIN(srclen, dstlen);

        i = 1;
        while (space >= AES_BLOCK_LEN) {
            i++;
            CCMP_DECRYPT(i, b, b0, src, dst, H, AES_BLOCK_LEN, S);
            src += AES_BLOCK_LEN;
            dst += AES_BLOCK_LEN;
            space -= AES_BLOCK_LEN;
            srclen-= AES_BLOCK_LEN;
            dstlen-= AES_BLOCK_LEN;
            len -= AES_BLOCK_LEN;
        }

        if (!len) break; // All finished

        // One, or both, of src or dst may not be 16 byte aligned, so we need
        // to handle this special case.
        if (((srclen > 0) && (srclen < AES_BLOCK_LEN)) ||
            ((dstlen > 0) && (dstlen < AES_BLOCK_LEN))) {

#ifdef ZFS_CRYPTO_VERBOSE
            printf("src buffer has %d remaining bytes\n", (uint32_t)srclen);
            printf("dst buffer has %d remaining bytes\n", (uint32_t)dstlen);
#endif

            remainder = srclen;
            // If src actually have more than 16, we only want 16.
            if (remainder > AES_BLOCK_LEN) remainder=AES_BLOCK_LEN;

            // Copy what we have to temp
            memcpy(tmp, src, remainder);
            // Clear the rest, incase we have no more input
            memset(&tmp[remainder], 0, AES_BLOCK_LEN-remainder);
            src+=remainder;
            srclen-=remainder;
            len -= remainder;

            // Advance to next buffer, but only if srclen was smaller than 16
            while(remainder < AES_BLOCK_LEN) {

                // Advance input to next buffer
                if (!crypto_get_buffer(crypttext,
                                       &crypt_index, &src, &srclen)) break;
                // Copy over new bytes, you'd think there be 16 bytes there
                // but just in case there isn't ...
                avail = MIN(srclen, AES_BLOCK_LEN-remainder);
                memcpy(&tmp[remainder], src, avail);
                src += avail;
                srclen-=avail;
                remainder += avail;
                len -= avail;
            }

            // We have successfully loaded "tmp" with another block.
            // Process it:
            i++;
            CCMP_DECRYPT(i, b, b0, tmp, tmp, H, AES_BLOCK_LEN, S);

            // Now it is time to write it out, and make sure there is space.
            remainder = dstlen;
            if (remainder > AES_BLOCK_LEN) remainder=AES_BLOCK_LEN;

            memcpy(dst, tmp, remainder);
            dst+=remainder;
            dstlen-=remainder;

            while(remainder < AES_BLOCK_LEN) {

                // Advance output to next buffer
                if (!crypto_get_buffer(plaintext,
                                       &plain_index, &dst, &dstlen)) break;
                avail = MIN(dstlen, AES_BLOCK_LEN-remainder);
                memcpy(dst, &tmp[remainder], avail);
                dst += avail;
                dstlen-=avail;
                remainder += avail;
            }

#ifdef ZFS_CRYPTO_VERBOSE
            printf("Half block finished\n");
#endif
        }

        if (srclen == 0) {
#ifdef ZFS_CRYPTO_VERBOSE
            printf("Advancing src\n");
#endif
            if (!crypto_get_buffer(crypttext,
                                   &crypt_index, &src, &srclen)) break;
        }
        if (dstlen == 0) {
#ifdef ZFS_CRYPTO_VERBOSE
            printf("Advancing dst\n");
#endif
            if (!crypto_get_buffer(plaintext,
                                   &plain_index, &dst, &dstlen)) break;
        }
    } // while total length processing


    // No authtag? just leave
    if (!authlen) return 0;


    /*
     * ***********************************************************
     * Compute final GCM authtag
     */

    aes_gcm_final(cc_aes, 0, plaintext->cd_length, H, S, J0, tag);


#ifdef ZFS_CRYPTO_VERBOSE
    printf("computed_auth output:\n");
    for (i = 0; i < GCM_AUTH_LEN; i++)
        printf("0x%02x ", tag[i]);
    printf("\n");

#endif

    // Do we need to advance buffer?
    if (!srclen) {
        crypto_get_buffer(crypttext,
                          &crypt_index, &src, &srclen);
    }

    // We need to try to find the auth at end of input
    remainder = srclen;

#ifdef ZFS_CRYPTO_VERBOSE
    printf("decryption completed, remaining in src 0x%04x\n",
           (uint32_t) remainder);
#endif

    if (remainder > GCM_AUTH_LEN) remainder=GCM_AUTH_LEN;

    memcpy(tmp, src, remainder);
    src+=remainder;
    srclen-=remainder;

    while((remainder < AES_BLOCK_LEN)) {

        // Advance input to next buffer
        if (!crypto_get_buffer(crypttext,
                               &crypt_index, &src, &srclen)) break;

        avail = MIN(srclen, AES_BLOCK_LEN-remainder);
        memcpy(&tmp[remainder], src, avail);
        src += avail;
        remainder += avail;
    }

#ifdef ZFS_CRYPTO_VERBOSE
    printf("end of src: remainder 0x%04x\n", (uint32_t)remainder);
    for (i = 0; i < remainder; i++)
        printf("0x%02x ", tmp[i]);
    printf("\n");
#endif

    if (memcmp(tmp, tag, remainder)) {
#ifdef ZFS_CRYPTO_VERBOSE
        printf("decrypt authtag mismatch\n");
#endif
        return EBADMSG;
    }
#ifdef ZFS_CRYPTO_VERBOSE
    printf("decrypt authtag is ggoooooddd\n");
#endif
    return 0;
}






#define SPL_CRYPTO_CIPHER_TEST
#ifdef SPL_CRYPTO_CIPHER_TEST
/*
 * Cipher test
 */


static unsigned char key[16] = {
    0x5c, 0x95, 0x64, 0x42, 0x00, 0x82, 0x1c, 0x9e,
    0xd4, 0xac, 0x01, 0x83, 0xc4, 0x9c, 0x14, 0x97
};

/*
 * Input data will be set to 00, 01, 02, ....., fe, ff, 00, 01, ...
 * First iv is set to a8, a9, ...
 * Using key 'This.Is.A.Key' with len 13
 * The salt picked was:
 * 0xf2 0x61 0x01 0x50 0x73 0x54 0x9a 0xd1
 *
 * Output produced is: iv=12, iv=a8
 *
 * 0x01 0x95 0x6c 0x01 0x63 0x96 0xfd 0x13
 * 0xba 0x59 0x99 0x36 0x9f 0xd8 0x96 0x09
 * 0xe5 0xed 0xc1 0x3b 0x2f 0x57 0x0f 0x23 ...
 * [snip]
 *
 * solaris MAC output:
 *
 * OSX authtag
 * 0x18 0x76 0xc0 0xd2 0x22 0x91 0x7b 0x75
 * 0x3e 0x17 0xe9 0x33 0x74 0xa7 0x10 0x0f
 */

int cipher_test_gcm()
{
    crypto_data_t plaintext, ciphertext;
    crypto_mechanism_t *mech;
    crypto_mechanism_t mech_holder;
    iovec_t *dstiov = NULL;
    struct uio *dstuio = NULL;
    unsigned char d = 0;
    uint64_t size;
    int i;
    int maclen;
    int err;
    crypto_key_t ckey;
    unsigned char *plaindata  = NULL;
    unsigned char *cipherdata = NULL;
    unsigned char *mac = NULL;
    unsigned char *iv  = NULL;
    CK_AES_GCM_PARAMS *ccmp = NULL;
    unsigned char out[180];
    int ivsize = 12;

    printf("cipher tester loading\n");

    plaindata  = kmem_alloc(512, KM_SLEEP);
    if (!plaindata) goto out;
    cipherdata = kmem_alloc(512, KM_SLEEP);
    if (!cipherdata) goto out;
    mac = kmem_alloc(16, KM_SLEEP);
    if (!mac) goto out;
    iv = kmem_alloc(ivsize, KM_SLEEP);
    if (!iv) goto out;

    for (i = 0, d = 0; i < sizeof(plaindata); i++, d++)
        plaindata[i] = d;

    ckey.ck_format = CRYPTO_KEY_RAW;
    ckey.cku_data.cku_key_value.cku_v_length = sizeof(key) * 8;
    ckey.cku_data.cku_key_value.cku_v_data   = (void *)&key;

    // Clear all outputs
    memset(cipherdata, 0, 512);
    memset(iv, 0, ivsize);
    memset(mac, 0, 16);
    memset(&mech_holder, 0, sizeof(mech_holder));
    mech = &mech_holder;

    size = 512;

    printf("init complete\n");

    // Call cipher
    plaintext.cd_format = CRYPTO_DATA_RAW;
    plaintext.cd_offset = 0;
    plaintext.cd_length = size;
    plaintext.cd_miscdata = NULL;
    plaintext.cd_raw.iov_base = (void *)plaindata;
    plaintext.cd_raw.iov_len = size;

    maclen = 16;

    dstiov = kmem_alloc(sizeof (iovec_t) * 2, KM_SLEEP);
    if (!dstiov) goto out;

    dstiov[0].iov_base = (void *)cipherdata;
    dstiov[0].iov_len = size;
    dstiov[1].iov_base = (void *)mac;
    dstiov[1].iov_len = maclen;

    dstuio = uio_create( 2,       /* max number of iovecs */
                         0,            /* current offset */
                         UIO_SYSSPACE,     /* type of address space */
                         UIO_WRITE);    /* read or write flag */
    for (i = 0; i < 2; i++)
        uio_addiov(dstuio, (user_addr_t)dstiov[i].iov_base, dstiov[i].iov_len);

    //dstuio.uio_iov = dstiov;
    //dstuio.uio_iovcnt = 2;
    ciphertext.cd_length = size + maclen;

    //srcuio.uio_segflg = dstuio.uio_segflg = UIO_SYSSPACE;

    ciphertext.cd_format = CRYPTO_DATA_UIO;
    ciphertext.cd_offset = 0;
    ciphertext.cd_uio = dstuio;
    ciphertext.cd_miscdata = NULL;

    printf("loaded CD structs\n");

    //mech = zio_crypt_setup_mech_gen_iv(crypt, type, dedup, key, txg,
    //                                   bookmark, src, plaintext.cd_length, iv);

    //mech = zio_crypt_setup_mech_common(crypt, type, datalen);
    mech->cm_type = crypto_mech2id(SUN_CKM_AES_GCM);

    ccmp = kmem_alloc(sizeof (CK_AES_GCM_PARAMS), KM_SLEEP);
    // ccmp = calloc(sizeof (CK_AES_CCM_PARAMS), 1);
    ccmp->ulAADLen = 0;
    ccmp->pAAD = NULL;

    ccmp->ulIvLen = ivsize;
    ccmp->pIv = (uchar_t *)iv;
    ccmp->ulTagBits = maclen * 8;

    mech->cm_param = (char *)ccmp;
    mech->cm_param_len = sizeof (CK_AES_GCM_PARAMS);


    //zio_crypt_gen_data_iv(crypt, type, dedup, data, datalen,
    //                     key, txg, bookmark, iv);
    printf("Setting iv to: \n");
    for (i = 0, d=0xa8; i < ivsize; i++,d++) {
        iv[i] = d;
        printf("0x%02x ", iv[i]);
    }
    printf("\n");


    err = crypto_encrypt(mech, &plaintext, &ckey, NULL,
                         &ciphertext, NULL);

    printf("crypt_encrypt returns 0x%02X\n", err);
    *out = 0;

    for (i = 0; i < size; i++) {

        snprintf((char*)out, sizeof(out), "%s 0x%02x", out, cipherdata[i]);
        if ((i % 8)==7) {
            printf("%s\n", out);
            *out = 0;
        }
    }
    printf("%s\nMAC output:", out);
    *out = 0;
    for (i = 0; i < 16; i++) {
        snprintf((char *)out, sizeof(out), "%s 0x%02x", out, mac[i]);
    }
    printf("%s\n", out);

    printf("%s\nIV output:", out);
    *out = 0;
    for (i = 0; i < ivsize; i++) {
        snprintf((char *)out, sizeof(out), "%s 0x%02x", out, iv[i]);
    }
    printf("%s\n", out);


    if (dstuio)     uio_free(dstuio);

    IODelay(500);
    printf("*** Decrypt test\n");




    // Clear all outputs (cipherdata is input)
    memset(plaindata, 0, 512);
    memset(iv, 0, ivsize);
    memset(&mech_holder, 0, sizeof(mech_holder));
    mech = &mech_holder;

    size = 512;

    printf("init complete\n");

    // Call cipher
    plaintext.cd_format = CRYPTO_DATA_RAW;
    plaintext.cd_offset = 0;
    plaintext.cd_length = size;
    plaintext.cd_miscdata = NULL;
    plaintext.cd_raw.iov_base = (void *)plaindata;
    plaintext.cd_raw.iov_len = size;

    maclen = 16;

    dstiov[0].iov_base = (void *)cipherdata;
    dstiov[0].iov_len = size;
    dstiov[1].iov_base = (void *)mac;
    dstiov[1].iov_len = maclen;

    dstuio = uio_create( 2,       /* max number of iovecs */
                         0,            /* current offset */
                         UIO_SYSSPACE,     /* type of address space */
                         UIO_READ);    /* read or write flag */
    for (i = 0; i < 2; i++)
        uio_addiov(dstuio, (user_addr_t)dstiov[i].iov_base, dstiov[i].iov_len);

    //dstuio.uio_iov = dstiov;
    //dstuio.uio_iovcnt = 2;
    ciphertext.cd_length = size + maclen;

    //srcuio.uio_segflg = dstuio.uio_segflg = UIO_SYSSPACE;

    ciphertext.cd_format = CRYPTO_DATA_UIO;
    ciphertext.cd_offset = 0;
    ciphertext.cd_uio = dstuio;
    ciphertext.cd_miscdata = NULL;

    printf("loaded CD structs\n");

    //mech = zio_crypt_setup_mech_gen_iv(crypt, type, dedup, key, txg,
    //                                   bookmark, src, plaintext.cd_length, iv);

    //mech = zio_crypt_setup_mech_common(crypt, type, datalen);
    mech->cm_type = crypto_mech2id(SUN_CKM_AES_GCM);

    //ccmp = kmem_alloc(sizeof (CK_AES_CCM_PARAMS), KM_SLEEP);
    // ccmp = calloc(sizeof (CK_AES_CCM_PARAMS), 1);
    ccmp->ulAADLen = 0;
    ccmp->pAAD = NULL;

    ccmp->ulIvLen = ivsize;
    ccmp->pIv = (uchar_t *)iv;
    ccmp->ulTagBits = maclen * 8;

    mech->cm_param = (char *)ccmp;
    mech->cm_param_len = sizeof (CK_AES_GCM_PARAMS);


    //zio_crypt_gen_data_iv(crypt, type, dedup, data, datalen,
    //                     key, txg, bookmark, iv);
    printf("Setting iv to: \n");
    for (i = 0, d=0xa8; i < ivsize; i++,d++) {
        iv[i] = d;
        printf("0x%02x ", iv[i]);
    }
    printf("\n");


    err = crypto_decrypt(mech, &ciphertext, &ckey, NULL,
                         &plaintext, NULL);

    printf("crypt_decrypt returns 0x%02X\n", err);
    *out = 0;

    for (i = 0; i < size; i++) {

        snprintf((char*)out, sizeof(out), "%s 0x%02x", out, plaindata[i]);
        if ((i % 8)==7) {
            printf("%s\n", out);
            *out = 0;
        }
    }
    printf("%s\nMAC output:", out);
    *out = 0;
    for (i = 0; i < 16; i++) {
        snprintf((char *)out, sizeof(out), "%s 0x%02x", out, mac[i]);
    }
    printf("%s\n", out);



 out:
    if (dstuio)     uio_free(dstuio);
    if (ccmp)       kmem_free(ccmp, sizeof (CK_AES_GCM_PARAMS));
    if (plaindata)  kmem_free(plaindata, 512);
    if (cipherdata) kmem_free(cipherdata, 512);
    if (mac)        kmem_free(mac, 16);
    if (iv)         kmem_free(iv, ivsize);
    if (dstiov)     kmem_free(dstiov, sizeof (iovec_t) * 2);
    return 0;
}
#endif


