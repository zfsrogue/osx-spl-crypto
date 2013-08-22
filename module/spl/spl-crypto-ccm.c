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
 * This source file was based on ieee80211_crypto_ccmp.c, which was not
 * generic enough to be of use.
 *
 * This implementation does not handle "Associated authentication data", and
 * assumes it is of length 0.
 *
 * authtag is computed and put at the end of the output "cipher" buffer.
 *
 * ZFS uses variable sized nonce, usually size 12.
 * ZFS uses variable sized authtag, usually size 16.
 *
 */

//#define ZFS_CRYPTO_VERBOSE

#include <sys/cdefs.h>
#include <sys/types.h>
#include <sys/conf.h>
#include <sys/cpuvar.h>
#include <sys/errno.h>
#include <sys/kernel.h>

#include <sys/socket.h>

#include <sys/crypto/api.h>
#include <sys/crypto/rijndael.h>
#include <sys/crypto/sun_ccm.h>

//#define ZFS_CRYPTO_VERBOSE

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


#define CCMP_ENCRYPT(_i, _b, _b0, _pos, _out, _e, _len) do { \
        /* Authentication */                            \
        xor_block(_b, _pos, _len);                      \
        rijndael_encrypt(cc_aes, _b, _b);               \
        /* Encryption, with counter */                  \
        _b0[14] = (_i >> 8) & 0xff;                     \
        _b0[15] = _i & 0xff;                            \
        rijndael_encrypt(cc_aes, _b0, _e);              \
        xor_block2(_out, _pos, _e, _len);               \
} while (0)

#define CCMP_DECRYPT(_i, _b, _b0, _pos, _out, _a, _len) do { \
        /* Decrypt, with counter */                     \
        _b0[14] = (_i >> 8) & 0xff;                     \
        _b0[15] = _i & 0xff;                            \
        rijndael_encrypt(cc_aes, _b0, _b);              \
        xor_block2(_out, _pos, _b, _len);               \
        /* Authentication */                            \
        xor_block(_a, _out, _len);                      \
        rijndael_encrypt(cc_aes, _a, _a);               \
} while (0)




void sun_ccm_setkey(rijndael_ctx *cc_aes,
                    uint8_t *key, uint32_t keylen)
{
    rijndael_set_key(cc_aes, key, keylen*NBBY);
}


/*
 * For authtag;
 * B0 is computed with M and L in flags (first byte), then nonce is copied in
 * followed by the cryptlen at the end, with most significant byte first.
 */
static void ccm_init_b0(rijndael_ctx *cc_aes,
                        uint8_t *b0,
                        uint64_t len,
                        uint8_t *nonce,
                        uint32_t noncelen,
                        uint32_t authlen,
                        uint8_t *a)
{
    uint32_t be32;
    uint8_t flags;
    int i;

    // Compute M' from M
    flags = (authlen-2)/2;  // M' = ((M-2)/2)
    flags &= 7;  // 3 bits only
    flags <<= 3; // Bits 5.4.3

    // Compute L' is number of bytes in the length field, minus one.
    // So, 3 bytes, makes L' be 2.
    flags |= (( 15-noncelen-1 )&7);

    b0[0] = flags;

    memcpy(&b0[1], nonce, noncelen);
    // Put the srclen into the sizelen number of bytes, if nonce is 12
    // 0    1 .... noncelen   length ... 15
    // 0    1 .... 12             13 ... 15
    for (i = CCM_AUTH_LEN-1, be32 = (uint32_t)len;
         i >= noncelen+1;
         i--) {
        b0[i] = (uint8_t) (be32 & 0xff);
        be32 = be32 >> 8;
    }

#ifdef ZFS_CRYPTO_VERBOSE
    printf("B0 set to: len 0x%04x\n", (uint32_t)len);
    for (i = 0; i < CCM_AUTH_LEN; i++)
        printf("0x%02x ", b0[i]);
    printf("\n");
#endif

    // Let's start, setup round 0
    rijndael_encrypt(cc_aes, b0, a);

}

/*
 * For encryption/decryption;
 * B0 flags (first byte) is cleared to only contain L
 * The cryptlen field is cleared (in preparation to be used as counter)
 */

static void ccm_clear_b0(uint8_t *b0, uint32_t noncelen)
{
    int i;
    b0[0] &= 0x07;
    for (i = noncelen+1;
         i < CCM_AUTH_LEN;
         i++) {
        b0[i] = 0;
    }
}

/*
 * authtag is computed at the end by encrypting B0 to S_0, then XOR
 * with computed auth "T" to produce final "U".
 */
static void ccm_final_b0(rijndael_ctx *cc_aes,
                         uint8_t *b0,
                         uint8_t *a)
{
    rijndael_encrypt(cc_aes, b0, b0);  // Get S_0
    xor_block(a, b0, AES_BLOCK_LEN);   // S_0 XOR T -> U
}


/*
 * Encrypt "plain" struct mbuf(s) into "cipher" struct mbuf(s).
 * If there is room, tack the auth at the end of "cipher".
 */
int sun_ccm_encrypt_and_auth(rijndael_ctx *cc_aes,
                             crypto_data_t *plaintext,
                             crypto_data_t *crypttext,
                             uint8_t *nonce, uint32_t noncelen,
                             uint32_t authlen)
{
    uint8_t *src;
    uint8_t *dst;
    uint64_t srclen;
    uint64_t dstlen;
    uint32_t i;
    uint64_t space;
    uint64_t len;
    uint8_t b0[AES_BLOCK_LEN], t[AES_BLOCK_LEN], e[AES_BLOCK_LEN];
    uint8_t tmp[AES_BLOCK_LEN];
    unsigned int plain_index, crypt_index;
    uint64_t remainder;
    uint64_t avail;

    memset(t, 0, sizeof(t));
    memset(e, 0, sizeof(e));

    /*
     * ***********************************************************
     * For AUTH, setup b0 correctly.
     */
    len = plaintext->cd_length;

    ccm_init_b0(cc_aes, b0, len, nonce, noncelen, authlen, t);


    /*
     * ***********************************************************
     * Clear "crypt len" field for encryption
     */

    ccm_clear_b0(b0, noncelen);


    /*
     * ***********************************************************
     */

    // Encrypt

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
        printf("ccmp_encrypt: %p:0x%x -> %p:0x%x\n",
               src, (unsigned int)srclen, dst, (unsigned int)dstlen);
#endif

        space = MIN(srclen, dstlen);

#ifdef ZFS_CRYPTO_VERBOSE
        printf("encrypt: opting to process buffer size 0x%04x\n",
               (uint32_t)space);
#endif
        i = 1;
        while (space >= AES_BLOCK_LEN) {
            CCMP_ENCRYPT(i, t, b0, src, dst, e, AES_BLOCK_LEN);
            src += AES_BLOCK_LEN;
            dst += AES_BLOCK_LEN;
            space -= AES_BLOCK_LEN;
            srclen-= AES_BLOCK_LEN;
            dstlen-= AES_BLOCK_LEN;
            len -= AES_BLOCK_LEN;
            i++;
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
            CCMP_ENCRYPT(i, t, b0, tmp, tmp, e, AES_BLOCK_LEN);
            i++;

            // Now it is time to write it out, and make sure there is space.
            remainder = dstlen;
            if (remainder > AES_BLOCK_LEN) remainder=AES_BLOCK_LEN;

            memcpy(dst, tmp, remainder);
            dst+=remainder;
            dstlen-=remainder;

            while(remainder < AES_BLOCK_LEN) {

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


    /*
     * ***********************************************************
     */

    /*
     * Note: rfc 3610 and NIST 800-38C require counter of
	 * zero to encrypt auth tag.
	 */

    ccm_clear_b0(b0, noncelen);

    // To compute authentication value U, we use
    //  S_0 := E( K, A_0 ), where A_0 has flags&7, and counter = 0;
    //    U := T XOR first-M-bytes( S_0 )
    ccm_final_b0(cc_aes, b0, t);

#ifdef ZFS_CRYPTO_VERBOSE
    printf("ccmp_auth output:\n");
    for (i = 0; i < CCM_AUTH_LEN; i++)
        printf("0x%02x ", t[i]);
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
    if (remainder > CCM_AUTH_LEN) remainder=CCM_AUTH_LEN;

    memcpy(dst, t, remainder);
    dst+=remainder;
    dstlen-=remainder;

    while((remainder < AES_BLOCK_LEN)) {

        // Advance input to next buffer
        if (!crypto_get_buffer(crypttext,
                               &crypt_index, &dst, &dstlen)) break;
        avail = MIN(dstlen, AES_BLOCK_LEN-remainder);
        memcpy(dst, &t[remainder], avail);
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

int sun_ccm_decrypt_and_auth(rijndael_ctx *cc_aes,
                             crypto_data_t *crypttext,
                             crypto_data_t *plaintext,
                             uint8_t *nonce, uint32_t noncelen,
                             uint32_t authlen)
{
    uint8_t *src;
    uint8_t *dst;
    uint64_t srclen;
    uint64_t dstlen;
    unsigned int plain_index, crypt_index;
    uint32_t i;
    uint64_t space;
    uint64_t len;
    uint8_t b0[AES_BLOCK_LEN], b[AES_BLOCK_LEN], a[AES_BLOCK_LEN];
    uint8_t tmp[AES_BLOCK_LEN];
    uint64_t remainder;
    uint64_t avail;

    memset(b, 0, sizeof(b));
    memset(a, 0, sizeof(a));

    /*
     * ***********************************************************
     * For AUTH, setup b0 correctly -> "a"
     */
    len = crypttext->cd_length;

    ccm_init_b0(cc_aes, b0, len, nonce, noncelen, authlen, a);



    /*
     * ***********************************************************
     * Clear b0 flags and counter for decrypt
     */

    ccm_clear_b0(b0, noncelen);


    /*
     * ***********************************************************
     * Decrypt
     */



    // Setup first buffers.
    plain_index = 0;
    crypt_index = 0;

    if (!crypto_get_buffer(crypttext,
                           &crypt_index, &src, &srclen)) return -1;

    if (!crypto_get_buffer(plaintext,
                           &plain_index, &dst, &dstlen)) return -2;


    while(len) {

#ifdef ZFS_CRYPTO_VERBOSE
        printf("ccmp_decrypt: %p:0x%x -> %p:0x%x\n",
               src, (unsigned int)srclen, dst, (unsigned int)dstlen);
#endif

        space = MIN(srclen, dstlen);

        i = 1;
        while (space >= AES_BLOCK_LEN) {
            CCMP_DECRYPT(i, b, b0, src, dst, a, AES_BLOCK_LEN);
            src += AES_BLOCK_LEN;
            dst += AES_BLOCK_LEN;
            space -= AES_BLOCK_LEN;
            srclen-= AES_BLOCK_LEN;
            dstlen-= AES_BLOCK_LEN;
            len -= AES_BLOCK_LEN;
            i++;
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
            CCMP_DECRYPT(i, b, b0, tmp, tmp, a, AES_BLOCK_LEN);
            i++;

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


    /*
     * ***********************************************************
     * Compute a->t->T->U and compare auth.
     */

    /*
     * Note: rfc 3610 and NIST 800-38C require counter of
	 * zero to encrypt auth tag.
	 */
    ccm_clear_b0(b0, noncelen);

    // To compute authentication value U, we use
    //  S_0 := E( K, A_0 ), where A_0 has flags&7, and counter = 0;
    //    U := T XOR first-M-bytes( S_0 )
    ccm_final_b0(cc_aes, b0, a);


#ifdef ZFS_CRYPTO_VERBOSE
    printf("computed_auth output:\n");
    for (i = 0; i < CCM_AUTH_LEN; i++)
        printf("0x%02x ", a[i]);
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

    if (remainder > CCM_AUTH_LEN) remainder=CCM_AUTH_LEN;

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

    if (memcmp(tmp, a, remainder)) {
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




#ifdef SPL_CRYPTO_CIPHER_TEST
/*
 * Cipher test
 */


unsigned char key[16] = {
    0x5c, 0x95, 0x64, 0x42, 0x00, 0x82, 0x1c, 0x9e,
    0xd4, 0xac, 0x01, 0x83, 0xc4, 0x9c, 0x14, 0x97
};

// Input data will be set to 00, 01, 02, ....., fe, ff, 00, 01, ...
// First iv is set to a8, a9, ...

int cipher_test()
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
    CK_AES_CCM_PARAMS *ccmp;
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
    mech->cm_type = crypto_mech2id(SUN_CKM_AES_CCM);

    ccmp = kmem_alloc(sizeof (CK_AES_CCM_PARAMS), KM_SLEEP);
    // ccmp = calloc(sizeof (CK_AES_CCM_PARAMS), 1);
    ccmp->ulNonceSize = ivsize;
    ccmp->ulAuthDataSize = 0;
    ccmp->authData = NULL;
    ccmp->ulDataSize = size;
    ccmp->ulMACSize = 16;
    mech->cm_param = (char *)ccmp;
    mech->cm_param_len = sizeof (CK_AES_CCM_PARAMS);


    //zio_crypt_gen_data_iv(crypt, type, dedup, data, datalen,
    //                     key, txg, bookmark, iv);
    printf("Setting iv to: \n");
    for (i = 0, d=0xa8; i < ivsize; i++,d++) {
        iv[i] = d;
        printf("0x%02x ", iv[i]);
    }
    printf("\n");

    ccmp->nonce = (uchar_t *)iv;


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


 out:
    if (dstuio)     uio_free(dstuio);
    if (ccmp)       kmem_free(ccmp, sizeof (CK_AES_CCM_PARAMS));
    if (plaindata)  kmem_free(plaindata, 512);
    if (cipherdata) kmem_free(cipherdata, 512);
    if (mac)        kmem_free(mac, 16);
    if (iv)         kmem_free(iv, ivsize);
    if (dstiov)     kmem_free(dstiov, sizeof (iovec_t) * 2);
    return 0;
}
#endif


